# Makefile
# (C) 2017, all rights reserved,
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

include cfg.mk

client:
	(cd src; \
	 make clean; \
	 make -j 4 client)

client32:
	(cd src; \
	 make clean; \
	 make -j 4 client32)

client_windows:
	(cd src; \
	 make -f Makefile.windows clean; \
	 make -f Makefile.windows -j 4 install)

server:
	(cd src; \
	 make clean; \
	 make -j 4 server)

ctool:
	(cd src; \
	 make clean; \
	 make -j 4 ctool)

client_install: client
	(cd src; \
	 cp reqrypt ../$(CLIENT_PROG)-$(PACKAGE_VERSION_SHORT)-linux64)

client_install32: client32
	(cd src; \
	 cp reqrypt ../$(CLIENT_PROG)-$(PACKAGE_VERSION_SHORT)-linux32)

client_install_freebsd: client
	(cd src; \
	 cp reqrypt ../$(CLIENT_PROG)-$(PACKAGE_VERSION_SHORT)-freebsd)

client_install_macosx: client
	(cd src; \
	 cp reqrypt ../$(CLIENT_PROG)-$(PACKAGE_VERSION_SHORT)-macosx)

client_install_windows: client_windows
	(cd src; \
	 mv $(PACKAGE_NAME)-install.exe \
		../$(CLIENT_PROG)-$(PACKAGE_VERSION_SHORT)-win$(BITS)-install.exe; \
     mv $(PACKAGE_NAME)-files.zip \
        ../$(CLIENT_PROG)-$(PACKAGE_VERSION_SHORT)-win$(BITS)-files.zip)

server_install: server ctool
	(cd src/tools; \
	 ./build_serverdeb.sh $(PACKAGE_NAME) $(PACKAGE_VERSION_SHORT); \
	 mv $(PACKAGE_NAME)d_*.deb ../../)

clean:
	(cd src; make clean; make -f Makefile.windows clean)
	rm -rf autom4te.cache cfg.mk config.log config.status configure

