/*
 * capture.c
 * (C) 2010, all rights reserved,
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Filtering, packet capture, and re-injection for Linux.
 *
 * FILTERING:
 *      Filtering is achieved by issuing iptables commands.  This is a bit
 *      ugly however it has the advantage of transparency (for Linux users
 *      that understand iptables).  The issued commands are cleaned up when
 *      this program exits.
 *
 * CAPTURING:
 *      Capturing filtered packets is achieved via netlink sockets.
 *      Originally libnfnetlink+libnetfilter_queue libraries were used,
 *      however:
 *          - this introduced a dependency, and these libraries are not always
 *            installed by default
 *          - the existing API is terrible -- the callback model does not fit
 *            the capture.h API without lots of hacky-ness.
 *      In the end we cut out the middle man and used netlink sockets
 *      directly.
 *
 * RE-INJECTION:
 *      This is handled by a RAW socket.  We could also use netlink to
 *      re-inject the packets, however this is less flexible because (AFAIK)
 *      you cannot replace one packet with multiple packets.  Re-injected
 *      packets are marked so that they are not re-captured.
 */

#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>

// Use full path to avoid ambiguity:
#include "/usr/include/linux/socket.h"

#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>

#include "capture.h"
#include "log.h"
#include "options.h"
#include "socket.h"

/*
 * NFQ configuration.
 */
#define QUEUE_NUMBER    40403
#define QUEUE_MAX_LEN   512

/*
 * Packet marking for re-injected packets.
 */
#define MARK_NUMBER     40402

/*
 * IP tables commands.
 */
#define IPTABLES_BUFFSIZE   256
#define IPTABLES_ARGS_MAX   32
static const char *ip_tables_enable_tcp_queue =
    "/sbin/iptables -I OUTPUT -p tcp -m tcp -m owner --uid-owner %d "
    "-m mark ! --mark %d -j NFQUEUE --dport 80 --queue-num %d";
static const char *ip_tables_enable_udp_queue =
    "/sbin/iptables -I OUTPUT -p udp -m udp -m owner --uid-owner %d "
    "-m mark ! --mark %d -j NFQUEUE --dport 53 --queue-num %d";
static const char *ip_tables_enable_filter_icmp =
    "/sbin/iptables -I INPUT -p icmp --icmp-type ttl-zero-during-transit "
    "-j DROP";
static const char *ip_tables_disable_tcp_queue =
    "/sbin/iptables -D OUTPUT -p tcp -m tcp -m owner --uid-owner %d "
    "-m mark ! --mark %d -j NFQUEUE --dport 80 --queue-num %d";
static const char *ip_tables_disable_udp_queue =
    "/sbin/iptables -D OUTPUT -p udp -m udp -m owner --uid-owner %d "
    "-m mark ! --mark %d -j NFQUEUE --dport 53 --queue-num %d";
static const char *ip_tables_disable_filter_icmp =
    "/sbin/iptables -D INPUT -p icmp --icmp-type ttl-zero-during-transit "
    "-j DROP";

/*
 * Prototypes.
 */
static bool netfilter_set_config(uint8_t cmd, uint16_t qnum, uint16_t pf);
static bool netfilter_set_params(uint8_t mode, uint32_t range);
static bool netfilter_set_queue_length(uint32_t qlen);
static bool netfilter_send_message(uint16_t nl_type, int nfa_type,
    uint16_t res_id, bool ack, void *msg, size_t size);
static int netfilter_get_packet(uint8_t *buff, size_t size);
static void iptables(const char *command);
static void iptables_undo_insert(const char *command);
static void iptables_undo_on_signal(int sig);
static void iptables_undo_flush(void);

/*
 * Global packet raw socket for packet re-injection.
 */
static int socket_inject;

/*
 * Global netlink socket for packet capture.
 */
static int socket_netfilter;

/*
 * Queued iptables commands that are to be run when this program exits.
 */
#define MAX_IPTABLES_COMMANDS   8
static const char *iptables_undo[MAX_IPTABLES_COMMANDS+1] = {NULL};

/*
 * Clean up iptables state?
 */
static bool iptables_clean = true;

/*
 * Initialise packet capturing.
 */
void init_capture(void)
{
    // Set-up netfilterqueue.
    trace("[" PLATFORM "] setting up netfilter queue %d", QUEUE_NUMBER);
    
    socket_netfilter = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    if (socket_netfilter < 0)
    {
        error("unable to create a netfilter socket");
    }
    
    struct sockaddr_nl nl_addr;
    memset(&nl_addr, 0x0, sizeof(nl_addr));
    nl_addr.nl_family = AF_NETLINK;
    nl_addr.nl_pid    = getpid();

    if (bind(socket_netfilter, (struct sockaddr *)&nl_addr, sizeof(nl_addr))
            != 0)
    {
        error("unable to bind netfilter socket to current process");
    }

    if (!netfilter_set_config(NFQNL_CFG_CMD_PF_UNBIND, 0, PF_INET))
    {
        error("unable to unbind netfilter from PF_INET");
    }
    if (!netfilter_set_config(NFQNL_CFG_CMD_PF_BIND, 0, PF_INET))
    {
        error("unable to bind netfilter to PF_INET");
    }
    if (!netfilter_set_config(NFQNL_CFG_CMD_BIND, QUEUE_NUMBER, 0))
    {
        error("unable to bind netfilter to queue number %u", QUEUE_NUMBER);
    }
    uint32_t range = ETH_DATA_LEN + sizeof(struct ethhdr) +
        sizeof(struct nfqnl_msg_packet_hdr);
    if (!netfilter_set_params(NFQNL_COPY_PACKET, range))
    {
        error("unable to set netfilter into copy packet mode with maximum "
            "buffer size %u", range);
    }
    if (!netfilter_set_queue_length(QUEUE_MAX_LEN))
    {
        error("unable to set netfilter queue maximum length to %u",
            QUEUE_MAX_LEN);
    }

    // Initialise packet redirection with iptables.
#ifndef DEBUG
    signal(SIGINT, iptables_undo_on_signal);
    signal(SIGQUIT, iptables_undo_on_signal);
    signal(SIGHUP, iptables_undo_on_signal);
    signal(SIGILL, iptables_undo_on_signal);
    signal(SIGFPE, iptables_undo_on_signal);
    signal(SIGABRT, iptables_undo_on_signal);
    signal(SIGSEGV, iptables_undo_on_signal);
    signal(SIGTERM, iptables_undo_on_signal);
    signal(SIGPIPE, iptables_undo_on_signal);
    signal(SIGALRM, iptables_undo_on_signal);
#endif      /* DEBUG */
    iptables_undo_insert(ip_tables_disable_tcp_queue);
    iptables_undo_insert(ip_tables_disable_udp_queue);
    iptables_undo_insert(ip_tables_disable_filter_icmp);
    iptables(ip_tables_enable_tcp_queue);
    iptables(ip_tables_enable_udp_queue);
    iptables(ip_tables_enable_filter_icmp);
    iptables_clean = false;
    atexit(iptables_undo_flush);

    // Create a RAW socket for packet re-injection.
    trace("[" PLATFORM "] setting up raw socket for re-injection");
    socket_inject = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    if (socket_inject < 0)
    {
        error("unable to open a raw socket for packet re-injection");
    }

    // Mark re-injected packets so that they don't get captured again!
    uint32_t mark = MARK_NUMBER;
    if (setsockopt(socket_inject, SOL_SOCKET, SO_MARK, &mark, sizeof(mark))
        != 0)
    {
        error("unable to set raw socket for packet re-injection mark to %u",
            MARK_NUMBER);
    }
}

/*
 * Set a netfilter configuration option.
 */
static bool netfilter_set_config(uint8_t cmd, uint16_t qnum, uint16_t pf)
{
    struct nfqnl_msg_config_cmd nl_cmd;
    nl_cmd.command = cmd;
    nl_cmd.pf = htons(pf);
    return netfilter_send_message(NFQNL_MSG_CONFIG, NFQA_CFG_CMD, qnum, true,
        &nl_cmd, sizeof(nl_cmd));
}

/*
 * Set the netfilter parameters.
 */
static bool netfilter_set_params(uint8_t mode, uint32_t range)
{
    struct nfqnl_msg_config_params nl_params;
    nl_params.copy_mode = mode;
    nl_params.copy_range = htonl(range);
    return netfilter_send_message(NFQNL_MSG_CONFIG, NFQA_CFG_PARAMS, 
        QUEUE_NUMBER, true, &nl_params, sizeof(nl_params));
}

/*
 * Set the netfilter queue length.
 */
static bool netfilter_set_queue_length(uint32_t qlen)
{
    return netfilter_send_message(NFQNL_MSG_CONFIG, NFQA_CFG_QUEUE_MAXLEN,
        QUEUE_NUMBER, true, &qlen, sizeof(qlen));
}

/*
 * Send a message to the netfilter system and wait for an acknowledgement.
 */
static bool netfilter_send_message(uint16_t nl_type, int nfa_type,
    uint16_t res_id, bool ack, void *msg, size_t size)
{
    size_t nl_size = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct nfgenmsg))) +
        NFA_ALIGN(NFA_LENGTH(size));
    uint8_t buff[nl_size];
    struct nlmsghdr *nl_hdr = (struct nlmsghdr *)buff;

    nl_hdr->nlmsg_len   = NLMSG_LENGTH(sizeof(struct nfgenmsg));
    nl_hdr->nlmsg_flags = NLM_F_REQUEST | (ack? NLM_F_ACK: 0);
    nl_hdr->nlmsg_type  = (NFNL_SUBSYS_QUEUE << 8) | nl_type;
    nl_hdr->nlmsg_pid   = 0;
    nl_hdr->nlmsg_seq   = 0;

    struct nfgenmsg *nl_gen_msg = (struct nfgenmsg *)(nl_hdr + 1);
    nl_gen_msg->version      = NFNETLINK_V0;
    nl_gen_msg->nfgen_family = AF_UNSPEC;
    nl_gen_msg->res_id       = htons(res_id);

    struct nfattr *nl_attr =
        (struct nfattr *)(buff + NLMSG_ALIGN(nl_hdr->nlmsg_len));
    size_t nl_attr_len = NFA_LENGTH(size);
    nl_hdr->nlmsg_len = NLMSG_ALIGN(nl_hdr->nlmsg_len) +
        NFA_ALIGN(nl_attr_len);
    nl_attr->nfa_type = nfa_type;
    nl_attr->nfa_len  = NFA_LENGTH(size);

    memcpy(NFA_DATA(nl_attr), msg, size);

    struct sockaddr_nl nl_addr;
    memset(&nl_addr, 0x0, sizeof(nl_addr));
    nl_addr.nl_family = AF_NETLINK;

    if (sendto(socket_netfilter, buff, sizeof(buff), 0,
            (struct sockaddr *)&nl_addr, sizeof(nl_addr)) != sizeof(buff))
    {
        return false;
    }

    if (!ack)
    {
        return true;
    }

    uint8_t ack_buff[64];
    socklen_t nl_addr_len = sizeof(nl_addr);
    int result = recvfrom(socket_netfilter, ack_buff, sizeof(ack_buff), 0,
        (struct sockaddr *)&nl_addr, &nl_addr_len);
    nl_hdr = (struct nlmsghdr *)ack_buff;

    if (result < 0)
    {
        return false;
    }

    if (nl_addr_len != sizeof(nl_addr) || nl_addr.nl_pid != 0)
    {
        errno = EINVAL;
        return false;
    }

    if (NLMSG_OK(nl_hdr, result) && nl_hdr->nlmsg_type == NLMSG_ERROR)
    {
        errno = -(*(int *)NLMSG_DATA(nl_hdr));
        return (errno == 0);
    }
    else
    {
        errno = EBADMSG;
        return false;
    }
}

/*
 * Get a packet from netfilter.
 */
static int netfilter_get_packet(uint8_t *buff, size_t size)
{
    // Read a message from netlink
    char nl_buff[ETH_DATA_LEN + sizeof(struct ethhdr) +
        sizeof(struct nfqnl_msg_packet_hdr)];
    struct sockaddr_nl nl_addr;
    socklen_t nl_addr_len = sizeof(nl_addr);
    int result = recvfrom(socket_netfilter, nl_buff, sizeof(nl_buff), 0,
        (struct sockaddr *)&nl_addr, &nl_addr_len);
    if (result <= sizeof(struct nlmsghdr))
    {
        errno = EINVAL;
        return -1;
    }
    if (nl_addr_len != sizeof(nl_addr) || nl_addr.nl_pid != 0)
    {
        errno = EINVAL;
        return false;
    }

    struct nlmsghdr *nl_hdr = (struct nlmsghdr *)nl_buff;
    if (NFNL_SUBSYS_ID(nl_hdr->nlmsg_type) != NFNL_SUBSYS_QUEUE)
    {
        errno = EINVAL;
        return -1;
    }
    if (NFNL_MSG_TYPE(nl_hdr->nlmsg_type) != NFQNL_MSG_PACKET)
    {
        errno = EINVAL;
        return -1;
    }
    if (nl_hdr->nlmsg_len < sizeof(struct nfgenmsg))
    {
        errno = EINVAL;
        return -1;
    }

    // Get the packet data
    int nl_size0 = NLMSG_SPACE(sizeof(struct nfgenmsg));
    if (nl_hdr->nlmsg_len < nl_size0)
    {
        errno = EINVAL;
        return -1;
    }
    struct nfattr *nl_attr = NFM_NFA(NLMSG_DATA(nl_hdr));
    int nl_attr_size = nl_hdr->nlmsg_len - NLMSG_ALIGN(nl_size0);
    bool found_data = false, found_pkt_hdr = false;
    uint8_t *nl_data = NULL;
    size_t nl_data_size = 0;
    struct nfqnl_msg_packet_hdr *nl_pkt_hdr = NULL;
    while (NFA_OK(nl_attr, nl_attr_size))
    {
        int nl_attr_type = NFA_TYPE(nl_attr);
        switch (nl_attr_type)
        {
            case NFQA_PAYLOAD:
                if (found_data)
                {
                    errno = EINVAL;
                    return -1;
                }
                found_data = true;
                nl_data = (uint8_t *)NFA_DATA(nl_attr);
                nl_data_size = (size_t)NFA_PAYLOAD(nl_attr);
                break;
            case NFQA_PACKET_HDR:
                if (found_pkt_hdr)
                {
                    errno = EINVAL;
                    return -1;
                }
                found_pkt_hdr = true;
                nl_pkt_hdr = (struct nfqnl_msg_packet_hdr *)NFA_DATA(nl_attr);
                break;
        }
        nl_attr = NFA_NEXT(nl_attr, nl_attr_size);
    }
    if (!found_data || !found_pkt_hdr)
    {
        errno = EINVAL;
        return -1;
    }

    // Tell netlink to drop the packet
    struct nfqnl_msg_verdict_hdr nl_verdict;
    nl_verdict.verdict = htonl(NF_DROP);
    nl_verdict.id = nl_pkt_hdr->packet_id;
    if (!netfilter_send_message(NFQNL_MSG_VERDICT, NFQA_VERDICT_HDR,
            QUEUE_NUMBER, false, &nl_verdict, sizeof(nl_verdict)))
    {
        return -1;
    }

    // Copy the packet's contents to the output buffer.
    // Also add a phoney ethernet header.
    struct ethhdr *eth_header = (struct ethhdr *)buff;
    memset(&eth_header->h_dest, 0x0, ETH_ALEN);
    memset(&eth_header->h_source, 0x0, ETH_ALEN);
    eth_header->h_proto = htons(ETH_P_IP);

    struct iphdr *ip_header = (struct iphdr *)(eth_header + 1);
    memcpy(ip_header, nl_data, nl_data_size);

    return (int)(nl_data_size + sizeof(struct ethhdr));
}

/*
 * Get a captured packet.
 */
size_t get_packet(uint8_t *buff, size_t size)
{
    int result;
    do
    {
        result = netfilter_get_packet(buff, size);
        if (result < 0)
        {
            warning("failed to read packet from netfilter socket");
            continue;
        }
    }
    while (false);

    return (size_t)result;
}

/*
 * Re-inject a packet.
 */
void inject_packet(uint8_t *buff, size_t size)
{
    struct ethhdr *eth_header = (struct ethhdr *)buff;
    struct iphdr *ip_header = (struct iphdr *)(eth_header + 1);
    size -= sizeof(struct ethhdr);

    struct sockaddr_in to_addr;
    memset(&to_addr, 0x0, sizeof(to_addr));
    to_addr.sin_family      = AF_INET;
    to_addr.sin_addr.s_addr = ip_header->daddr;
    
    int n = sendto(socket_inject, ip_header, size, 0,
        (struct sockaddr *)(&to_addr), sizeof(to_addr));
    if (n < 0)
    {
        warning("unable to re-inject packet of size %zu", size);
    }
}

/*
 * Execute an iptables command.
 */
static void iptables(const char *command)
{
    if (options_get()->seen_no_iptables)
    {
        return;
    }

    char buff[IPTABLES_BUFFSIZE];
    if (snprintf(buff, sizeof(buff), command, getuid(), MARK_NUMBER,
        QUEUE_NUMBER) >= sizeof(buff))
    {
        panic("iptables buffer is too small");
    }
    log("[" PLATFORM "] executing iptables command \"%s\"", buff);

    // Note: never use system() because we have setuid as root.
    char *args[IPTABLES_ARGS_MAX];
    args[0] = buff;
    int i, j;
    for (i = 0, j = 1; buff[i] && j < IPTABLES_ARGS_MAX-1; i++)
    {
        if(buff[i] == ' ')
        {
            buff[i] = '\0';
            if (buff[i+1] != '\0')
            {
                args[j++] = buff+i+1;
            }
        }
    }
    args[j] = NULL;

    pid_t pid = fork();
    if (pid == -1)
    {
        error("unable to execute iptables command; failed to fork current "
            "process");
    }
    else if (pid == 0)
    {
        if (setgid(0) != 0)
        {
            error("unable to set the group ID to 0 (root) for iptables "
                "command");
        }
        if (setuid(0) != 0)
        {
            error("unable to set the user ID to 0 (root) for iptables "
                "command");
        }
        execv("/sbin/iptables", args);
        error("unable to execute iptables command");
    }

    int exit_status;
    while (waitpid(pid, &exit_status, 0) < 0)
    {
        if (errno != EINTR)
        {
            error("unable to execute iptables command; failed to wait for "
                "iptables to complete");
        }
    }
    if(exit_status != 0)
    {
        error("iptables command returned non-zero exit status %d",
            exit_status);
    }
}

/*
 * Insert a command into the iptables_undo queue.
 */
static void iptables_undo_insert(const char *command)
{
    int i;
    for (i = 0; i < MAX_IPTABLES_COMMANDS && iptables_undo[i] != NULL; i++)
        ;
    if (i >= MAX_IPTABLES_COMMANDS)
    {
        panic("iptables undo queue is full");
    }
    iptables_undo[i] = command;
}

/*
 * Execute all queued iptables undo commands on signal then exit.
 */
static void iptables_undo_on_signal(int sig)
{
    log("[" PLATFORM "] caught deadly signal %d; cleaning up iptables state",
        sig);
    iptables_undo_flush();
    error("caught deadly signal %d; exitting", sig);
}

/*
 * Execute all queued iptables undo commands.
 */
static void iptables_undo_flush(void)
{
    if (!iptables_clean)
    {
        for (int i = 0; i < MAX_IPTABLES_COMMANDS && iptables_undo[i] != NULL;
            i++)
        {
            iptables(iptables_undo[i]);
            iptables_undo[i] = NULL;
        }
        iptables_clean = true;
    }
}

