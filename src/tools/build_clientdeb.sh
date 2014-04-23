#!/bin/sh
# build_clientdeb.sh
# (C) 2014, all rights reserved,
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

# Simple script that generates a .deb file for client installation.
# This is to avoid all the complexity of doing it the "correct way"
# (although eventually this will be unavoidable).

if [ $# != 2 ]
then
    echo "usage: $0 package-name package-version" 1>&2
    exit 1
fi

if [ ! -x `which fakeroot` ]
then
    echo "$0: error: fakeroot is not installed" 1>&2
    exit 1
fi

PACKAGE_NAME=$1
PACKAGE_VERSION=$2

set -e

mkdir -p root
cd root
mkdir -p "./usr/sbin/"
cp "../../${PACKAGE_NAME}" "./usr/sbin/"
tar cz --owner root --group root -f ../data.tar.gz .
md5sum `find ../root/ -type f -printf "%P "` > md5sums
mv md5sums ../client.deb/
cd ..
rm -rf root/
cd client.deb
for INFILE in *.in
do
    OUTFILE=`basename "$INFILE" .in`
    sed "s/@PACKAGE_NAME@/${PACKAGE_NAME}/g" < "$INFILE" > "$OUTFILE"
    chmod a+x "$OUTFILE"
done
tar cz --owner root --group root -f ../control.tar.gz control postinst \
    md5sums
rm -f postinst md5sums
cd ..
echo "2.0" > debian-binary
fakeroot ar cr "${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64.deb" debian-binary \
    control.tar.gz data.tar.gz
rm -f debian-binary control.tar.gz data.tar.gz

