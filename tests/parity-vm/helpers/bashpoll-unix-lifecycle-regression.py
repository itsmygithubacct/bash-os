#!/usr/bin/python3
"""Additional listener-ownership checks; run only inside the parity VM."""
import importlib.util
import sys

spec = importlib.util.spec_from_file_location('base', '/opt/bashos-parity/harness/helpers/terra-local-io-bashpoll.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


def main():
    base.guard()
    if sys.argv[1] == 'setup':
        base.setup('unix')
        return
    base.init()
    script = r'''mkdir sub || exit 1
builtin bashpoll listen-unix sub/relative.sock l || exit 2
cd sub || exit 3
builtin bashpoll close "$l" || exit 4
[[ ! -e relative.sock ]] || exit 5
cd .. || exit 6
builtin bashpoll listen-unix replace.sock l || exit 7
rm replace.sock || exit 8
printf 'preserve\n' > replace.sock || exit 9
builtin bashpoll close "$l" || exit 10
[[ $(<replace.sock) == preserve ]] || exit 11
builtin bashpoll listen-unix reused.sock l || exit 12
eval "exec ${l}>&-" || exit 13
eval "exec ${l}>reused-file" || exit 14
builtin bashpoll close "$l" || exit 15
[[ -S reused.sock ]] || exit 16
readonly bad=x
builtin bashpoll listen-unix invalid.sock bad 2>/dev/null && exit 17
[[ ! -e invalid.sock ]] || exit 18
printf 'ownership=ok\n'
'''
    status, out, err = base.done(base.spawn(sys.argv[1], script), 'unix-ownership')
    base.record('unix-ownership', status=status, stdout_base64=base.raw(out), stderr_base64=base.raw(err))
    if status != 0 or out != b'ownership=ok\n' or err:
        raise RuntimeError('listener ownership check failed')
    print('ownership=ok')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        try:
            base.record('exception', error=repr(exc))
        except Exception:
            pass
        print('scenario-error=%s' % type(exc).__name__)
        sys.exit(1)
    finally:
        for child in base.CHILDREN:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=3)
