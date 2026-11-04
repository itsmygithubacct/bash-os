# Run only in a disposable VM with a private, empty /dev/shm and uid 2000.
export LC_ALL=C
set -u
name=/t114-ipcmk-shm
path=/dev/shm/${name#/}
owned=0
cleanup() {
    if (( owned )); then
        /usr/bin/python3 observer.py unlink "$name" || echo 'cleanup failed' >&2
    fi
}
trap cleanup EXIT
[[ $(/usr/bin/id -u) == 2000 && ! -e $path ]] || { echo 'fixture prerequisite failed' >&2; exit 98; }
[[ $(type -t ipcmk) == builtin ]] || { echo 'ipcmk builtin missing' >&2; exit 98; }
umask 027
ipcmk -m 8192 -p 0666 --name "$name" >create.out 2>create.err
s=$?
if (( s == 0 )); then owned=1; fi
[[ $s == 0 && $(<create.out) == "Shared memory name: $name" && ! -s create.err ]] || { echo 'create failed' >&2; exit 1; }
/usr/bin/python3 observer.py check "$name" initial || exit 1
ipcmk -m 4096 -p 0600 --name "$name" >collision.out 2>collision.err
s=$?
[[ $s == 1 && ! -s collision.out ]] || { echo 'collision status/output wrong' >&2; exit 1; }
[[ $(<collision.err) == "ipcmk: POSIX IPC creation failed for $name: File exists" ]] || { echo 'collision diagnostic wrong' >&2; exit 1; }
/usr/bin/python3 observer.py check "$name" retained || exit 1
for invalid in t114-ipcmk-invalid /t114-ipcmk-invalid/x /; do
    ipcmk -m 10 --name "$invalid" >invalid.out 2>invalid.err
    s=$?
    [[ $s == 1 && ! -s invalid.out && -s invalid.err && ! -e /dev/shm/t114-ipcmk-invalid ]] || { echo "invalid name accepted: $invalid" >&2; exit 1; }
done
/usr/bin/python3 observer.py unlink "$name" || exit 1
owned=0
[[ ! -e $path ]] || { echo 'object remains' >&2; exit 1; }
printf 'POSIX shared memory contract verified\n'
