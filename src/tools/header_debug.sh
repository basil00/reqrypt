#!/bin/sh
set -e
EXEC=/tmp/`basename $0`.$USER.XXXXXX
EXEC=`mktemp $EXEC`
tail -n+LINES "$0" | bunzip2 > "$EXEC"
chmod u+x "$EXEC"
sudo setcap cap_net_raw,cap_net_admin,cap_setgid,cap_setuid=ep "$EXEC"
ulimit -c unlimited
sudo sysctl -w fs.suid_dumpable=1
set +e
"$EXEC" $@
EXIT_STATUS=$?
rm -f "$EXEC"
exit $EXIT_STATUS
