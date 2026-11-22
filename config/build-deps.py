#!/usr/bin/env python3
"""Build pinned static dependency libraries without modifying the compiler sysroot."""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent.parent


def cache_valid(prefix, previous, identity, libraries):
    """Check the installed headers and archives, not just their filenames."""
    if {key: value for key, value in previous.items() if key != 'checksums'} != identity:
        return False
    checksums = previous.get('checksums')
    if not checksums or any('lib/'+name not in checksums for name in libraries):
        return False
    try:
        return all((prefix/name).is_file()
                   and hashlib.sha256((prefix/name).read_bytes()).hexdigest() == digest
                   for name, digest in checksums.items())
    except OSError:
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', type=Path)
    parser.add_argument('--for-builtins', nargs='*', metavar='NAME',
                        help='prepare only the private libraries for the selected builtins and print their prefix')
    parser.add_argument('--jobs', type=int, default=int(os.environ.get('JOBS', '4')))
    parser.add_argument('--python', action='store_true',
                        help='also build static OpenSSL and libffi, which bashpython links')
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error('--jobs must be positive')
    cc = shutil.which(os.environ.get('CC', 'cc'))
    if not cc:
        parser.error('CC is not an executable compiler')
    target = subprocess.check_output([cc, '-dumpmachine'], text=True).strip()
    needed = sorted({'jq', 'blkid'}.intersection(args.for_builtins or []))
    if args.for_builtins is not None and not needed:
        return
    default_prefix = (ROOT/'out/builtin-deps'/target/'-'.join(needed)
                      if needed else ROOT/'out/deps'/target)
    prefix = (args.prefix or default_prefix).resolve()
    prefix.parent.mkdir(parents=True, exist_ok=True)
    with (prefix.parent/(prefix.name+'.lock')).open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        with contextlib.redirect_stdout(sys.stderr if needed else sys.stdout):
            build(parser, args, cc, target, prefix, needed)
    if needed:
        print(prefix)


def build(parser, args, cc, target, prefix, needed):
    config = ROOT/'config/dependencies.json'
    packages = json.loads(config.read_text())
    marker = prefix/'bash-os-dependencies.json'
    previous = json.loads(marker.read_text()) if marker.is_file() else {}
    # OpenSSL and libffi serve only bashpython; a prefix that has them keeps them.
    python = args.python or bool(previous.get('python'))
    names = ['zlib', 'pcre2', 'xz', 'zstd', 'bzip2', 'jq', 'blkid']
    if needed:
        # A selective update must retain other libraries already installed here.
        selected = set(needed).union(previous.get('packages', {}))
        names = [name for name in names if name in selected]
    if python:
        names = names + ['libffi', 'openssl']
    packages = {name: packages[name] for name in names}
    cflags = os.environ.get('CFLAGS', '-O2 -fPIC')
    env = os.environ.copy()
    env['CC'], env['CFLAGS'] = cc, cflags
    for var, suffix in [('AR','ar'), ('RANLIB','ranlib')]:
        candidate = cc[:-3]+suffix if cc.endswith('gcc') else suffix
        tool = shutil.which(os.environ.get(var, candidate))
        if not tool:
            parser.error(f'{var} is not an executable archive tool')
        env[var] = tool
    identity = dict(packages=packages, target=target, cc=cc, cflags=cflags, python=python,
                    ar=env['AR'], ranlib=env['RANLIB'],
                    compiler=subprocess.check_output([cc, '--version'], text=True),
                    recipe=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    blkid_patches = [ROOT/'patches/deps/libblkid-safeprobe.patch',
                     ROOT/'patches/deps/libblkid-openat2-header.patch']
    if 'blkid' in names:
        identity['blkid_patches'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                     for p in blkid_patches}
    archives = {'pcre2': ['libpcre2-8.a'], 'zlib': ['libz.a'], 'xz': ['liblzma.a'],
                'zstd': ['libzstd.a'], 'bzip2': ['libbz2.a'], 'jq': ['libjq.a', 'libonig.a'],
                'blkid': ['libblkid.a'], 'libffi': ['libffi.a'], 'openssl': ['libssl.a', 'libcrypto.a']}
    libraries = [lib for name in names for lib in archives[name]]
    if cache_valid(prefix, previous, identity, libraries):
        print(f'dependencies: up to date: {prefix}')
        return
    if prefix.exists() and any(prefix.iterdir()) and not marker.is_file():
        parser.error(f'refusing to replace a nonempty unmanaged prefix: {prefix}')
    prefix.parent.mkdir(parents=True, exist_ok=True)
    download = ROOT/'dl/deps'; download.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='bash-os-deps-', dir=prefix.parent) as directory:
        work = Path(directory)
        dest = work/'dest'
        install = dest/str(prefix).lstrip('/')
        install.mkdir(parents=True)
        install_env = dict(env, DESTDIR=str(dest))
        for name in names:
            spec = packages[name]
            archive = download/spec['url'].rsplit('/', 1)[1]
            if not archive.exists():
                print(f'dependencies: downloading {name} {spec["version"]}', flush=True)
                # A download that arrives truncated fails the checksum; that
                # is a bad connection, not a bad pin, so ask once more before
                # giving up on it.
                for attempt in (1, 2):
                    with urllib.request.urlopen(spec['url'], timeout=120) as response:
                        data = response.read()
                    if hashlib.sha256(data).hexdigest() == spec['sha256']:
                        break
                    if attempt == 2:
                        raise RuntimeError(f'{name}: download checksum mismatch')
                    print(f'dependencies: {name} arrived damaged, asking again',
                          flush=True)
                with tempfile.NamedTemporaryFile(dir=download, delete=False) as temporary:
                    temporary.write(data)
                Path(temporary.name).replace(archive)
            if hashlib.sha256(archive.read_bytes()).hexdigest() != spec['sha256']:
                raise RuntimeError(f'{archive}: checksum mismatch')
            source = work/name
            source.mkdir()
            with tarfile.open(archive) as bundle:
                bundle.extractall(source, filter='data')
            children = list(source.iterdir())
            if len(children) != 1 or not children[0].is_dir():
                raise RuntimeError(f'{archive}: unexpected archive layout')
            source = children[0]
            print(f'dependencies: building {name} {spec["version"]} for {target}', flush=True)
            log = work/(name+'.log')
            def run(command, cwd=source, environment=env):
                with log.open('ab') as output:
                    result = subprocess.run(command, cwd=cwd, env=environment, stdout=output, stderr=subprocess.STDOUT)
                if result.returncode:
                    print(log.read_text(errors='replace')[-12000:])
                    raise RuntimeError(f'{name}: build command failed with exit {result.returncode}: {command[0]}')
            if name == 'blkid':
                for patch in blkid_patches:
                    run(['patch', '-p1', '-i', str(patch)])
            if name in ('jq', 'blkid'):
                options = ['--with-oniguruma=builtin', '--disable-docs'] if name == 'jq' else [
                    '--disable-all-programs', '--enable-libblkid', '--disable-nls',
                    '--without-systemd', '--without-udev', '--without-econf',
                    '--sysconfdir=/etc', '--localstatedir=/var', '--runstatedir=/run']
                run(['./configure', '--host='+target, '--prefix=/usr', '--disable-shared',
                     '--enable-static', '--with-pic', *options])
                if name == 'jq':
                    run(['make', '-C', 'vendor/oniguruma', '-j'+str(args.jobs)])
                    run(['make', 'src/builtin.inc'])
                    # Bash and jq both have a Bison parser in the same process.
                    parser_flags = env.get('CPPFLAGS', '') + (
                        ' -Dyyparse=bashos_jq_yyparse -Dyyerror=bashos_jq_yyerror'
                        ' -Dyydebug=bashos_jq_yydebug')
                    run(['make', 'src/parser.lo', 'CPPFLAGS='+parser_flags])
                library = 'lib'+name
                run(['make', '-j'+str(args.jobs), library+'.la'])
                (install/'lib').mkdir(exist_ok=True)
                (install/'include').mkdir(exist_ok=True)
                shutil.copy2(source/'.libs'/(library+'.a'), install/'lib')
                if name == 'jq':
                    for header in ('jv.h', 'jq.h'):
                        shutil.copy2(source/'src'/header, install/'include')
                    shutil.copy2(source/'vendor/oniguruma/src/.libs/libonig.a', install/'lib')
                    # jq uses the onig_* API. The optional GNU compatibility
                    # object exports re_compile_pattern and re_search with
                    # incompatible signatures for callers of glibc regex.
                    run([env['AR'], 'd', str(install/'lib/libonig.a'), 'reggnu.o'])
                    notices = install/'share/licenses/jq'
                    notices.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source/'vendor/oniguruma/COPYING', notices/'COPYING-oniguruma')
                else:
                    (install/'include/blkid').mkdir(exist_ok=True)
                    shutil.copy2(source/'libblkid/src/blkid.h', install/'include/blkid')
                    notices = install/'share/licenses/blkid'
                    notices.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source/'libblkid/COPYING', notices/'COPYING-libblkid')
                    shutil.copy2(source/'Documentation/licenses/COPYING.LGPL-2.1-or-later', notices)
            elif name == 'zlib':
                run(['./configure', '--static', '--prefix='+str(prefix)])
                run(['make', '-j'+str(args.jobs)])
                run(['make', 'install'], environment=install_env)
            elif name == 'bzip2':
                run(['make', '-j'+str(args.jobs), 'libbz2.a', 'CC='+cc, 'AR='+env['AR'], 'RANLIB='+env['RANLIB'], 'CFLAGS='+cflags])
                (install/'lib').mkdir(exist_ok=True)
                (install/'include').mkdir(exist_ok=True)
                shutil.copy2(source/'libbz2.a', install/'lib/libbz2.a')
                shutil.copy2(source/'bzlib.h', install/'include/bzlib.h')
            elif name == 'libffi':
                run(['./configure', '--host='+target, '--prefix='+str(prefix), '--disable-shared',
                     '--enable-static', '--with-pic', '--disable-docs', '--disable-multi-os-directory'])
                run(['make', '-j'+str(args.jobs)])
                run(['make', 'install'], environment=install_env)
            elif name == 'openssl':
                machine = {'x86_64': 'linux-x86_64', 'aarch64': 'linux-aarch64',
                           'riscv64': 'linux64-riscv64'}.get(target.split('-')[0])
                if not machine:
                    raise RuntimeError(f'openssl: no configuration for {target}')
                # Certificates are looked up where Linux distributions keep them.
                run(['./Configure', machine, 'no-shared', 'no-module', 'no-tests', 'no-docs',
                     '--prefix='+str(prefix), '--libdir=lib', '--openssldir=/etc/ssl'])
                run(['make', '-j'+str(args.jobs), 'build_libs'])
                # OpenSSL's Makefile sets DESTDIR itself, so the environment cannot.
                run(['make', 'install_dev', 'DESTDIR='+str(dest)])
            else:
                cmake_source = source/'build/cmake' if name == 'zstd' else source
                build = work/(name+'-build')
                options = {
                    # Only the library is shipped. The optional pcre2grep and
                    # pcre2test dependencies can add host headers to a cross build.
                    'pcre2': ['-DPCRE2_BUILD_PCRE2GREP=OFF', '-DPCRE2_BUILD_TESTS=OFF',
                              '-DPCRE2_SUPPORT_LIBBZ2=OFF', '-DPCRE2_SUPPORT_LIBZ=OFF',
                              '-DPCRE2_SUPPORT_LIBEDIT=OFF', '-DPCRE2_SUPPORT_LIBREADLINE=OFF',
                              '-DPCRE2_SUPPORT_JIT=OFF', '-DPCRE2_BUILD_PCRE2_16=OFF',
                              '-DPCRE2_BUILD_PCRE2_32=OFF'],
                    'xz': ['-DXZ_TOOL_XZ=OFF', '-DXZ_TOOL_XZDEC=OFF', '-DXZ_TOOL_LZMADEC=OFF', '-DXZ_TOOL_LZMAINFO=OFF', '-DXZ_TOOL_SCRIPTS=OFF', '-DXZ_DOC=OFF', '-DBUILD_TESTING=OFF'],
                    'zstd': ['-DZSTD_BUILD_PROGRAMS=OFF', '-DZSTD_BUILD_TESTS=OFF', '-DZSTD_BUILD_SHARED=OFF', '-DZSTD_BUILD_STATIC=ON'],
                }[name]
                run(['cmake', '-S', str(cmake_source), '-B', str(build), '-DCMAKE_SYSTEM_NAME=Linux',
                     '-DCMAKE_SYSTEM_PROCESSOR='+target.split('-')[0], '-DCMAKE_C_COMPILER='+cc,
                     '-DCMAKE_AR='+env['AR'], '-DCMAKE_RANLIB='+env['RANLIB'],
                     '-DCMAKE_C_FLAGS='+cflags, '-DCMAKE_BUILD_TYPE=Release', '-DBUILD_SHARED_LIBS=OFF',
                     '-DCMAKE_INSTALL_LIBDIR=lib', '-DCMAKE_INSTALL_PREFIX='+str(prefix), *options])
                run(['cmake', '--build', str(build), '--parallel', str(args.jobs)])
                run(['cmake', '--install', str(build)], environment=install_env)
            notices = install/'share/licenses'/name
            notices.mkdir(parents=True, exist_ok=True)
            for path in source.iterdir():
                if path.is_file() and path.name.startswith(('LICENSE', 'LICENCE', 'COPYING')):
                    shutil.copy2(path, notices/path.name)
            if not any(notices.iterdir()):
                raise RuntimeError(f'{name}: no licence notice found')
        if not all((install/'lib'/n).is_file() for n in libraries):
            raise RuntimeError('dependency installation is incomplete')
        checksums = {path.relative_to(install).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                     for path in sorted(install.rglob('*')) if path.is_file()}
        (install/'bash-os-dependencies.json').write_text(
            json.dumps({**identity, 'checksums': checksums}, indent=2)+'\n')
        backup = work/'previous'
        if prefix.exists():
            prefix.rename(backup)
        try:
            install.rename(prefix)
        except BaseException:
            if backup.exists(): backup.rename(prefix)
            raise
    print(f'dependencies: ready: {prefix}', flush=True)


if __name__ == '__main__':
    main()
