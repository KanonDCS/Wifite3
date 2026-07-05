#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
wifite/util/termux.py — V3
Detects and adapts to Termux/NetHunter environments.
"""

import os
import sys
import subprocess


def is_termux():
    """
    Returns True if running inside Termux on Android.
    Checks for the Termux data directory and PREFIX env var.
    """
    return (
        os.path.exists('/data/data/com.termux') or
        os.environ.get('PREFIX', '').startswith('/data/data/com.termux')
    )


def is_nethunter():
    """
    Returns True if running on Kali NetHunter (Android + custom kernel).
    NetHunter typically sets NHOME or has /sdcard/nh_files.
    """
    return (
        os.path.exists('/sdcard/nh_files') or
        os.environ.get('NHOME') is not None or
        os.path.exists('/system/xbin/busybox')  # NetHunter kernel indicator
    )


def get_package_manager():
    """
    Returns the appropriate package manager command for this environment.
    - Termux uses 'pkg'
    - Kali/Parrot/Debian use 'apt'
    """
    if is_termux():
        return 'pkg'
    # Detect apt availability
    for pm in ('apt', 'apt-get'):
        try:
            subprocess.run([pm, '--version'], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=True)
            return pm
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
    return 'apt'  # Default fallback


def get_prefix():
    """
    Returns the binary prefix path.
    - Termux: /data/data/com.termux/files/usr
    - Standard Linux: /usr
    """
    if is_termux():
        return os.environ.get('PREFIX', '/data/data/com.termux/files/usr')
    return '/usr'


def get_bin_path():
    """Returns the bin directory for the current environment."""
    return os.path.join(get_prefix(), 'bin')


def adjust_path():
    """
    Ensures the correct binary path is at the front of PATH.
    Important for Termux where tools may not be in standard /usr/bin.
    """
    bin_path = get_bin_path()
    current_path = os.environ.get('PATH', '')
    if bin_path not in current_path.split(':'):
        os.environ['PATH'] = bin_path + ':' + current_path


def get_environment_name():
    """Returns a human-readable string describing the current environment."""
    if is_nethunter():
        return 'Kali NetHunter'
    if is_termux():
        return 'Termux'
    # Try to detect distro
    try:
        with open('/etc/os-release', 'r') as f:
            for line in f:
                if line.startswith('PRETTY_NAME='):
                    return line.split('=', 1)[1].strip().strip('"')
    except IOError:
        pass
    return 'Linux'


if __name__ == '__main__':
    print('Environment : %s' % get_environment_name())
    print('Termux      : %s' % is_termux())
    print('NetHunter   : %s' % is_nethunter())
    print('Pkg manager : %s' % get_package_manager())
    print('Prefix      : %s' % get_prefix())
    print('Bin path    : %s' % get_bin_path())
