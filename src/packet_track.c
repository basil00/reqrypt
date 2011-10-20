/*
 * packet_track.c
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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "packet.h"
#include "packet_track.h"
#include "socket.h"

#define PACKET_TABLE_NUM_BUCKETS    512
#define PACKET_TABLE_BUCKET_SIZE    4
#define MAX_SEQ                     0x00FFFFFF

struct packet_node_s
{
    uint32_t hash;
    uint32_t seq:24;
    uint8_t  rep;
};

/*
 * Prototypes.
 */
static uint64_t packet_hash(uint8_t *packet);
static uint64_t data_hash(void *data0, size_t data_size, uint64_t hash);

/*
 * Track a packet.  Determine its hash value and how many times it has been
 * repeated.
 */
void packet_track(uint8_t *packet, uint64_t *hash, unsigned *repeat)
{
    static struct packet_node_s 
        packet_table[PACKET_TABLE_NUM_BUCKETS][PACKET_TABLE_BUCKET_SIZE];
    static uint32_t seq = 0;
    seq = (seq == MAX_SEQ? 0: seq + 1);

    uint64_t hash64 = packet_hash(packet);
    uint32_t hash32 = (uint32_t)hash64 ^
        (uint32_t)(hash64 >> sizeof(uint32_t));
    uint16_t hash16 = (uint16_t)hash32 ^
        (uint16_t)(hash32 >> sizeof(uint16_t));
    *hash = hash64;

    struct packet_node_s *bucket =
        packet_table[hash16 % PACKET_TABLE_NUM_BUCKETS];

    unsigned j = 0;
    unsigned max_diff = 0;
    for (unsigned i = 0; i < PACKET_TABLE_BUCKET_SIZE; i++)
    {
        if (bucket[i].hash == hash32)
        {
            bucket[i].seq = seq;
            bucket[i].rep++;
            *repeat = bucket[i].rep;
            return;          
        }
        unsigned diff = seq - bucket[i].seq;
        if (diff > max_diff)
        {
            j = i;
        }
    }

    bucket[j].hash = hash32;
    bucket[j].seq  = seq;
    bucket[j].rep  = 0;
    *repeat = 0;
}

/*
 * Calculate the given packet's hash value.
 */
uint64_t packet_hash(uint8_t *packet)
{
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    uint8_t *data;
    size_t data_size;
    packet_init(packet, true, NULL, &ip_header, NULL, &tcp_header,
        &udp_header, &data, NULL, &data_size);

    uint64_t hash = 0x7126076C08D72A48ULL;
    uint16_t data_size16 = (uint16_t)data_size;
    hash = data_hash(&data_size16, sizeof(data_size16), hash);
    hash = data_hash(&ip_header->protocol, sizeof(ip_header->protocol), hash);
    hash = data_hash(&ip_header->saddr, sizeof(ip_header->saddr), hash);
    hash = data_hash(&ip_header->daddr, sizeof(ip_header->daddr), hash);
    if (tcp_header != NULL)
    {
        hash = data_hash(&tcp_header->source, sizeof(tcp_header->source),
            hash);
        hash = data_hash(&tcp_header->dest, sizeof(tcp_header->dest), hash);
        hash = data_hash(&tcp_header->seq, sizeof(tcp_header->seq), hash);
        hash = data_hash(&tcp_header->ack_seq, sizeof(tcp_header->ack_seq),
            hash);
        uint8_t tcp_flags = *(((uint8_t *)&tcp_header->window)-1);
        hash = data_hash(&tcp_flags, sizeof(tcp_flags), hash);
    }
    else
    {
        hash = data_hash(&udp_header->source, sizeof(udp_header->source),
            hash);
        hash = data_hash(&udp_header->dest, sizeof(udp_header->dest), hash);
    }
    hash = data_hash(data, data_size, hash);
    return hash;
}

/*
 * Generic hash function.
 */
#define FNV_64_PRIME    0x100000001b3ULL
uint64_t data_hash(void *data0, size_t data_size, uint64_t hash)
{
    uint8_t *data = (uint8_t *)data0;
    for (size_t i = 0; i < data_size; i++)
    {
        hash ^= (uint64_t)data[i];
        hash *= FNV_64_PRIME;
    }
    return hash;
}

