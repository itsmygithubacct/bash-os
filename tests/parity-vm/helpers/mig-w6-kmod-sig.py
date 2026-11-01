#!/usr/bin/python3 -I
"""Oracle for kernel module signature handling (finit_module via ctypes).

  prep DIR            write DIR/signed.ko (decompressed nbd as shipped),
                      DIR/unsigned.ko (signature trailer removed) and
                      DIR/tampered.ko (signed, one payload byte flipped);
                      print whether the shipped module carries a signature
  try FILE            finit_module(FILE) directly; print "OK" or
                      "<ERRNO-NAME>|<strerror>"; a successful load is undone
                      with delete_module so the module set is unchanged
  enforce             write Y to /sys/module/module/parameters/sig_enforce
                      (one-way) and print the value read back
"""
import ctypes
import errno
import glob
import lzma
import os
import sys

MARKER = b"~Module signature appended~\n"
libc = ctypes.CDLL(None, use_errno=True)


def prep(d):
    src = glob.glob("/lib/modules/*/kernel/drivers/block/nbd.ko.xz")[0]
    data = lzma.open(src).read()
    signed = data.endswith(MARKER)
    if signed:
        body = data[:-len(MARKER)]
        siglen = int.from_bytes(body[-4:], "big")
        unsigned = body[:-(siglen + 12)]
    else:
        unsigned = data
    mid = len(data) // 2
    tampered = data[:mid] + bytes([data[mid] ^ 0xFF]) + data[mid + 1:]
    for name, blob in (("signed.ko", data), ("unsigned.ko", unsigned), ("tampered.ko", tampered)):
        with open(os.path.join(d, name), "wb") as f:
            f.write(blob)
    print("shipped-module-signed=%d unsigned-differs=%d" % (signed, unsigned != data))


def try_load(path):
    fd = os.open(path, os.O_RDONLY)
    r = libc.syscall(313, fd, b"", 0)
    e = ctypes.get_errno()
    os.close(fd)
    if r == 0:
        libc.syscall(176, b"nbd", 0x800)
        print("OK")
    else:
        print("%s|%s" % (errno.errorcode[e], os.strerror(e)))


def main(argv):
    if argv[1] == "prep":
        prep(argv[2])
    elif argv[1] == "try":
        try_load(argv[2])
    elif argv[1] == "enforce":
        with open("/sys/module/module/parameters/sig_enforce", "w") as f:
            f.write("Y")
        print(open("/sys/module/module/parameters/sig_enforce").read().strip())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
