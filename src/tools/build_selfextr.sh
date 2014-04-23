#!/bin/sh
# mkselfextract.sh
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

if [ $# != 2 ]
then
    echo "usage: $0 header executable" 1>&2
    exit 1
fi

HDR=$1
EXE=$2
cp "../$EXE" .
bzip2 -9f "$EXE"
HDR_LINES=`wc -l < $HDR`
HDR_LINES=`expr $HDR_LINES + 1`
sed -e "s/LINES/$HDR_LINES/" "$HDR" > "$EXE.sh"
cat "$EXE.bz2" >> "$EXE.sh"
rm "$EXE.bz2"
chmod a+x "$EXE.sh"

