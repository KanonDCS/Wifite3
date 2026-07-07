import os
import pwd
import grp


def get_invoking_user():
    uid = int(os.environ.get('SUDO_UID', os.getuid()))
    gid = int(os.environ.get('SUDO_GID', os.getgid()))
    return uid, gid


def can_drop():
    if os.getuid() != 0:
        return False
    uid, gid = get_invoking_user()
    return uid != 0


def drop():
    if not can_drop():
        return False
    uid, gid = get_invoking_user()
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    os.environ['HOME'] = pwd.getpwuid(uid).pw_dir
    return True


def restore():
    return


def run_as_user(func, *args, **kwargs):
    pid = os.fork()
    if pid == 0:
        try:
            drop()
            result = func(*args, **kwargs)
            os._exit(0)
        except Exception:
            os._exit(1)
    else:
        _, status = os.waitpid(pid, 0)
        return os.WEXITSTATUS(status) == 0
