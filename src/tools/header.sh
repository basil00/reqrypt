#!/bin/sh
EXEC=~/`basename $0`.XXXXXX
EXEC=`mktemp $EXEC`
tail -n+LINES $0 | bunzip2 > $EXEC
chmod u+x $EXEC
if [ "$(id -u)" -ne 0 ]
then
	if [ ! -x `which sudo` ]
	then
		echo "error: 'sudo' command is not installed; aborting" >&2
		exit 1
	fi
	if [ -x `which setcap` ]
	then
		sudo setcap cap_net_raw,cap_net_admin,cap_setgid,cap_setuid=ep $EXEC
	else
		echo "warning: 'setcap' is not installed; using setuid root instead" >&2
		sudo chown 0:0 $EXEC
		sudo chmod +xs $EXEC
	fi
fi
(sleep 5; rm -f $EXEC) &
exec $EXEC $@
