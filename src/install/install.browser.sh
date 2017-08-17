# Uncomment to override default browser:

# BROWSER=firefox
# BROWSER=google-chrome
# BROWSER=chromium
# BROWSER=opera
# BROWSER=open		# (for MacOSX only)

if [ "$#" != 1 ]
then
	echo "usage: $0 URL" >&2
	exit 1
fi

if [ -z "$BROWSER" ]
then
	BROWSER=xdg-open
fi

if [ -x "`which $BROWSER`" ]
then
	exec $BROWSER "$1"
fi

echo "$0: error: browser '$BROWSER' not found" >&2
exit 1

