# Uncomment to override default browser:

# BROWSER=firefox
# BROWSER=google-chrome
# BROWSER=opera
# BROWSER=open		# (for MacOSX only)

if [ "$#" != 1 ]
then
	echo "usage: $0 URL" >&2
	exit 1
fi

if [ -z "$BROWSER" ]
then
	BROWSER=firefox
fi

if [ -x "`which $BROWSER`" ]
then
	exec $BROWSER "$1"
fi

if [ "$BROWSER" = "firefox" -a -x "`which firefox3`" ]
then
	exec firefox3 "$1"
fi

echo "$0: error: browser '$BROWSER' not found" >&2
exit 1

