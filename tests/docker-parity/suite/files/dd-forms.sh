# files/dd-forms: dd bs/count/skip/seek/conv without transfer stats
export LC_ALL=C TZ=UTC0
umask 022
t() { printf '$ %s\n' "$*"; "$@"; printf 'rc=%s\n' "$?"; }
printf '0123456789abcdef' > f
dd if=f bs=4 count=2 status=none; echo; dd if=f bs=1 skip=10 status=none; echo; dd if=f of=g bs=4 seek=1 status=none; od -An -c g
printf 'hello' | dd conv=ucase status=none; echo; printf 'HeLLo' | dd conv=lcase status=none; echo; printf 'abcd' | dd conv=swab status=none; echo
printf 'XY' | dd of=f conv=notrunc bs=1 seek=2 status=none; cat f; echo
dd if=f bs=5 count=1 status=noxfer of=/dev/null
dd if=f iflag=skip_bytes,count_bytes skip=3 count=4 status=none; echo
