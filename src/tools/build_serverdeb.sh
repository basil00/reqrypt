#!/bin/sh
# build_serverdeb.sh
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

# Simple script that generates a .deb file for server installation.
# This is to avoid all the complexity of doing it the "correct way"
# (although eventually this will be unavoidable).

if [ $# != 1 ]
then
    echo "usage: $0 package-name" 1>&2
    exit 1
fi

if [ ! -x `which fakeroot` ]
then
    echo "$0: error: fakeroot is not installed" 1>&2
    exit 1
fi

PACKAGE_NAME=$1

set -e

mkdir -p root
cd root
mkdir -p "./etc/${PACKAGE_NAME}d/"
mkdir -p "./etc/init.d/"
mkdir -p "./usr/sbin/"
cp "../../${PACKAGE_NAME}d" "./usr/sbin/"
cp "../../${PACKAGE_NAME}d_tool" "./usr/sbin/"
cp "../init.d.sh" "./etc/init.d/${PACKAGE_NAME}d"
chmod a+x "./etc/init.d/${PACKAGE_NAME}d"
touch "./etc/${PACKAGE_NAME}d/${PACKAGE_NAME}.tab"
touch "./etc/${PACKAGE_NAME}d/${PACKAGE_NAME}.crypt.keys"
tar cz --owner root --group root -f ../data.tar.gz .
md5sum `find ../root/ -type f -printf "%P "` > md5sums
mv md5sums ../server.deb/
cd ..
rm -rf root/
cd server.deb
for INFILE in *.in
do
    OUTFILE=`basename "$INFILE" .in`
    sed "s/@PACKAGE_NAME@/${PACKAGE_NAME}/g" < "$INFILE" > "$OUTFILE"
    chmod a+x "$OUTFILE"
done
tar cz --owner root --group root -f ../control.tar.gz control postinst \
    prerm postrm md5sums
rm -f postinst prerm postrm md5sums
cd ..
echo "2.0" > debian-binary
fakeroot ar cr "${PACKAGE_NAME}d_0.2_amd64.deb" debian-binary control.tar.gz \
    data.tar.gz
rm -f debian-binary control.tar.gz data.tar.gz

