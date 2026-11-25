# The recovery console on the first screen; a plain shell elsewhere.
if [ "$(tty)" = /dev/tty1 ]; then
  exec /usr/local/sbin/fenrir-console
fi
