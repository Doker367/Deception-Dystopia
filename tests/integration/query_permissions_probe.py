"""Read-only cross-UID permission probe for an explicitly authorized disposable Ubuntu lab.

Never installs users, touches ACLs, binds sockets, opens host services or reads
file contents. Tests open permissions only. Not part of ordinary pytest suite.
"""
import argparse
import os
from pathlib import Path
import platform
import stat
import subprocess

EVENTS = Path('/var/lib/dystopia/ingest/events.db')
MARKER = Path('/run/dystopia-query-lab-authorized')
CHECK = '''import os,sys
flags=os.O_NOFOLLOW|os.O_NONBLOCK|(os.O_WRONLY if sys.argv[2]=='write' else os.O_RDONLY)
try:
 fd=os.open(sys.argv[1],flags);os.close(fd)
except (OSError,PermissionError):
 sys.exit(1)
sys.exit(0)
'''


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--confirm',required=True)
    args=p.parse_args(argv)
    if (platform.system()!='Linux' or os.geteuid()!=0 or args.confirm!='DISPOSABLE-QUERY-LAB-ONLY'
            or MARKER.is_symlink() or not MARKER.is_file() or MARKER.stat().st_uid!=0
            or stat.S_IMODE(MARKER.stat().st_mode)!=0o600
            or MARKER.read_text().strip()!='purpose=dystopia-disposable-query-lab'):
        p.error('root-owned disposable lab marker and explicit confirmation required')
    if EVENTS.is_symlink() or not EVENTS.is_file():
        p.error('provisioned regular synthetic events.db required')
    checks=[('dystopia-control','read',False),('dystopia-control','write',False),
            ('dystopia-query','read',True),('dystopia-query','write',False),
            ('dystopia-sensor','read',False),('dystopia-ingest','read',True),
            ('dystopia-ingest','write',True)]
    for role,mode,expected in checks:
        result=subprocess.run(['/usr/sbin/runuser','-u',role,'--','/usr/bin/python3','-B','-c',CHECK,
                               str(EVENTS),mode],capture_output=True,timeout=3,
                              env={'PATH':'/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1'})
        success=result.returncode==0
        if success!=expected:
            raise RuntimeError(f'{role} {mode}: expected={expected}, observed={success}')
    print('permission matrix matched; no event contents read or changed')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
