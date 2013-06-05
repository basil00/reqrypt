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

DIVERT=
while getopts "hd:" OPTION
do
    case $OPTION in
        d) DIVERT=$OPTARG;;
        ?) echo "usage: $0 [-h] [-d <divert-install-path>]" >&2
           exit 1;;
    esac
done

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
DIVERT_VERSION=WinDivert-1.0.4-MINGW
set +x
if [ "$DIVERT" = "" ]
then
    if [ ! -d "$DIVERT_VERSION/" ]
    then
        wget http://reqrypt.org/download/$DIVERT_VERSION.zip
        unzip $DIVERT_VERSION.zip
        set -x
        if [ ! -d "$DIVERT_VERSION/" ]
        then
            echo "$0: unable to download divert package; cannot build \
                windows client" 1>&2
            exit 1
        fi
    fi
    DIVERT=$DIVERT_VERSION/
fi
set -x

rm -rf autom4te.cache cfg.mk config.log config.status configure
autoconf -o configure configure-windows.ac
./configure --host=i686-w64-mingw32 "DIVERT=$DIVERT"
make client_install_windows
./configure --host=x86_64-w64-mingw32 "DIVERT=$DIVERT"
make client_install_windows

