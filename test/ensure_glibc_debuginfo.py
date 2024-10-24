import subprocess

cmd = "gdb -q -ex 'file /lib64/libc.so.6'"
ps = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
try:
        output = ps.communicate(timeout=1)[0].decode('utf-8')
except subprocess.TimeoutExpired:
        ps.kill()
        output = ps.communicate()[0].decode('utf-8')
        subprocess.run('reset')
if 'use: zypper install glibc-debuginfo' in output:
        # example output: "Reading symbols from /lib64/libc.so.6...\n(No debugging symbols found in /lib64/libc.so.6)\nMissing separate debuginfos, use: zypper install glibc-debuginfo-2.31-150300.86.3.x86_64\n(gdb)"
        cmd = output.split('use:')[1].split('\n')[0].strip()
        cmd = cmd.replace('zypper install', 'zypper install -y --oldpackage')
        if cmd.startswith('zypper'):
                print(cmd)
                subprocess.run(cmd, shell=True)