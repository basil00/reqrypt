# Makefile
# (C) 2010, all rights reserved,
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

include ../cfg.mk

CLIENT_OBJS = \
    base64.o \
    client.o \
    checksum.o \
    cktp_client.o \
    cktp_common.o \
    cktp_encoding.o \
    cktp_url.o \
    config.o \
    encodings/aes.o \
    encodings/crypt.o \
    encodings/pad.o \
    encodings/natural.o \
    http_server.o \
    install.o \
    log.o \
    options.o \
    packet.o \
    packet_dispatch.o \
    packet_filter.o \
    packet_protocol.o \
    packet_track.o \
    random.o \
    tunnel.o \
    $(PLATFORM)/capture.o \
    $(PLATFORM)/misc.o

SERVER_OBJS = \
    base64.o \
    checksum.o \
    cktp_common.o \
    cktp_encoding.o \
    cktp_server.o \
    cktp_url.o \
    encodings/aes.o \
    encodings/crypt.o \
    encodings/pad.o \
    linux/misc.o \
    quota.o \
    random.o \
    server.o \
    server_table.o

CTOOL_OBJS = \
    base64.o \
    encodings/aes.o \
    encodings/crypt.o

client: CFLAGS = $(CLIENT_CFLAGS)
client: CLIBS = $(CLIENT_CLIBS)
client: $(CLIENT_OBJS) http_data.c install_data.c
	$(CC) -o $(CLIENT_PROG) $(CLIENT_OBJS) $(CLIBS)
	strip $(CLIENT_PROG)

client32: CC := $(CC) -m32
client32: client

encodings/natural.o: CFLAGS = $(CLIENT_CFLAGS) -O3

client_cap: client
	sudo setcap cap_net_raw,cap_net_admin,cap_setgid,cap_setuid=ep \
        $(CLIENT_PROG)

client_suid: client
	sudo chmod +s $(CLIENT_PROG)
	sudo chown 0:0 $(CLIENT_PROG)

client_debug: CFLAGS = $(CLIENT_DEBUG_CFLAGS)
client_debug: CLIBS = $(CLIENT_CLIBS)
client_debug: $(CLIENT_OBJS) http_data.c
	$(CC) -o $(CLIENT_PROG) $(CLIENT_OBJS) $(CLIBS)
	(cd tools; ./build_selfextr.sh header_debug.sh $(CLIENT_PROG))
	mv tools/$(CLIENT_PROG).sh $(CLIENT_PROG).debug

$(CLIENT_PROG): client

http_data.c: ui/* tools/file2c
	(cd ui/; ../tools/file2c * > ../http_data.c)
install_data.c: install/* tools/file2c
	(cd install/; ../tools/file2c * > ../install_data.c)

http_server.o: http_data.c
install.o: install_data.c

server: CFLAGS = $(SERVER_CFLAGS)
server: CLIBS = $(SERVER_CLIBS)
server: $(SERVER_OBJS)
	$(CC) -o $(SERVER_PROG) $(SERVER_OBJS) $(CLIBS)
	strip $(SERVER_PROG)

server_debug: CFLAGS = $(SERVER_DEBUG_CFLAGS)
server_debug: CLIBS = $(SERVER_CLIBS)
server_debug: $(SERVER_OBJS)
	$(CC) -o $(SERVER_PROG) $(SERVER_OBJS) $(CLIBS)

$(SERVER_PROG): server

ctool: CFLAGS = $(CTOOL_CFLAGS) -Wno-unused-function
ctool: CLIBS = $(CTOOL_CLIBS)
ctool: $(CTOOL_OBJS)
	$(CC) -o $(CTOOL_PROG) $(CTOOL_OBJS) $(CLIBS)
	strip $(CTOOL_PROG)

ctool_debug: CFLAGS = $(CTOOL_DEBUG_CFLAGS)
ctool_debug: CLIBS = $(CTOOL_CLIBS)
ctool_debug: $(CTOOL_OBJS)
	$(CC) -o $(CTOOL_PROG) $(CTOOL_OBJS) $(CLIBS)

clean:
	rm -f $(CLIENT_OBJS) $(SERVER_OBJS) http_data.c install_data.c tools/file2c

