/* Guest-only x86_64 syscall fixture, compiled without libc. */
static long call4(long n, long a, long b, long c, long d)
{
    register long r10 __asm__("r10") = d;
    long r;
    __asm__ volatile ("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx", "r11", "memory");
    return r;
}
static void number(char **p, long n)
{
    char b[24]; int i = 0;
    if (n < 0) { *(*p)++ = '-'; n = -n; }
    do { b[i++] = '0' + n % 10; n /= 10; } while (n);
    while (i) *(*p)++ = b[--i];
}
static void emit(char type, long a, long b, long c, long d, long e)
{
    char buf[120], *p = buf;
    *p++ = type; *p++ = ' '; number(&p, a); *p++ = ' '; number(&p, b);
    *p++ = ' '; number(&p, c); *p++ = ' '; number(&p, d);
    *p++ = ' '; number(&p, e); *p++ = '\n';
    if (call4(1, 1, (long)buf, p - buf, 0) != p - buf)
        call4(231, 99, 0, 0, 0);
}
void _start(void)
{
    long parent = call4(39, 0, 0, 0, 0);
    long child = call4(57, 0, 0, 0, 0);
    if (child == 0) {
        long me = call4(39, 0, 0, 0, 0);
        long ppid = call4(110, 0, 0, 0, 0);
        emit('C', me, ppid, 0, 0, 0);
        call4(231, 23, 0, 0, 0);
    }
    if (child < 0) call4(231, 98, 0, 0, 0);
    int status = 0;
    long waited = call4(61, child, (long)&status, 0, 0);
    long again = call4(61, child, (long)&status, 0, 0);
    emit('P', parent, child, waited, status, again);
    call4(231, waited == child && status == (23 << 8) && again == -10 ? 42 : 97, 0, 0, 0);
    __builtin_unreachable();
}
