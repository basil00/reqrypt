#!/bin/sh
# build.sh
# (C) 2011, all rights reserved,
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

if [ "`uname -s`" != "Linux" ]
then
    echo "$0: error: this build script is only for Linux" >&2
    exit 1
fi

set -e
set -x

# Build Linux 64/32-bit
rm -rf autom4te.cache cfg.mk config.log config.status configure
autoconf
./configure
make client_install
make client_install32
make server_install

# Build Windows 64/32-bit
rm -rf autom4te.cache cfg.mk config.log config.status configure
autoconf -o configure configure-windows2-cross.ac
./configure --host=i586-mingw32msvc
make client_install_windows
./configure --host=amd64-mingw32msvc
make client_install_windows

