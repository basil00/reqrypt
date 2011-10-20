#!/bin/sh
EXEC=~/`basename $0`.XXXXXX
EXEC=`mktemp $EXEC`
tail -n+LINES $0 | bunzip2 > $EXEC
if [ "$(id -u)" -ne 0 ]
then
	CHMOD="chmod +xs $EXEC"
	CHOWN="chown 0:0 $EXEC"
	if [ -x `which sudo` ]
	then
		sudo $CHOWN
		sudo $CHMOD
	else
		echo "error: 'sudo' command is not installed; aborting" >&2
		rm -f $EXEC
		exit 1
	fi
fi
(sleep 5; rm -f $EXEC) &
exec $EXEC $@
