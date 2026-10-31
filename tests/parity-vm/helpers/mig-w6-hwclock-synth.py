#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only synthetic RTC and clock for hwclock fixtures.

Usage: mig-w6-hwclock-synth.py PROGRAM [ARG...]  (reads /tmp/parity-case/synth.json)
  {"rtc": [sec,min,hour,mday,mon,year,wday,yday,isdst]}
RTC_RD_TIME on /tmp/parity-case/rtc is answered with that calendar, RTC_SET_TIME
is recorded and answered with success, clock_settime is recorded and answered
with success (the real clock and RTC are never touched). After PROGRAM exits the
ordered events are printed, one line each:
  rd | set sec,min,hour,mday,mon,year | clock_settime clk=C sec=S nsec=N
"""
import ctypes, errno, fcntl, importlib.util, os, select, signal, struct, sys, json
from pathlib import Path
CASE = Path('/tmp/parity-case'); SEQ = Path('/opt/bashos-parity/harness/helpers/system-sequence.py')
RTC = str(CASE / 'rtc'); RD = 0x80247009; SET = 0x4024700a


def main():
    cfg = json.loads((CASE / 'synth.json').read_text())
    date = cfg.get('rtc', [0] * 9)
    spec = importlib.util.spec_from_file_location('seq', SEQ)
    seq = importlib.util.module_from_spec(spec); spec.loader.exec_module(seq)
    events = []

    def supervise(lib, listener, child, replies, sequences, logargs, logstr, logmem, log):
        status = None
        try:
            while status is None:
                done, wstatus = os.waitpid(child, os.WNOHANG)
                if done:
                    status = wstatus; break
                if not select.select([listener], [], [], .05)[0]:
                    continue
                req = bytearray(80)
                try:
                    fcntl.ioctl(listener, seq.NOTIF_RECV, req, True)
                except OSError as e:
                    if e.errno in (errno.ENOENT, errno.EINTR):
                        continue
                    raise
                ident, pid, _, nr, _, _ = struct.unpack_from('<QIIiIQ', req)
                args = struct.unpack_from('<6Q', req, 32)
                raw = lib.seccomp_syscall_resolve_num_arch(0, nr)
                name = ctypes.cast(raw, ctypes.c_char_p).value.decode() if raw else str(nr)
                if name == 'ioctl':
                    fd = int(args[0])
                    if os.readlink('/proc/%d/fd/%d' % (pid, fd)) != RTC:
                        raise RuntimeError('ioctl on unexpected descriptor')
                    if (args[1] & 0xffffffff) == RD:
                        payload = struct.pack('<9i', *date)
                        with open('/proc/%d/mem' % pid, 'r+b', buffering=0) as mem:
                            if os.pwrite(mem.fileno(), payload, args[2]) != len(payload):
                                raise RuntimeError('short RTC writeback')
                        events.append('rd')
                    else:
                        data = seq.read_memory(pid, args[2], 36)
                        v = struct.unpack('<9i', bytes.fromhex(data['hex']))
                        events.append('set ' + ','.join(str(x) for x in v[:6]))
                elif name == 'clock_settime':
                    data = seq.read_memory(pid, args[1], 16)
                    sec, nsec = struct.unpack('<qq', bytes.fromhex(data['hex']))
                    events.append('clock_settime clk=%d sec=%d nsec=%d' % (args[0] & 0xffffffff, sec, nsec))
                else:
                    raise RuntimeError('unexpected notified call ' + name)
                try:
                    fcntl.ioctl(listener, seq.NOTIF_SEND, struct.pack('<QqiI', ident, 0, 0, 0))
                except OSError as e:
                    if e.errno != errno.ENOENT:
                        raise
        finally:
            if status is None:
                os.kill(child, signal.SIGKILL); os.waitpid(child, 0)
        return status
    seq.supervise = supervise
    sys.argv = [str(SEQ), '--notify', 'ioctl:1=%d' % RD, '--notify', 'ioctl:1=%d' % SET,
                '--notify', 'clock_settime', '--'] + sys.argv[1:]
    rc = 0
    try:
        seq.main()
    except SystemExit as exc:
        rc = exc.code or 0
    for line in events or ['(no events)']:
        print(line)
    sys.exit(rc)


if __name__ == '__main__':
    main()
