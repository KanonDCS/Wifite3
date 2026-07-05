#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
wifite/tools/dependency.py — V3
Dependency management: detection, version checks, and auto-installation.
"""

import re
import subprocess
import sys
import os


class Dependency(object):
    """
    Base class for tool wrappers. Subclasses must define:
        dependency_name    (str)  — binary name, e.g. 'airmon-ng'
        dependency_url     (str)  — where to find/install it
        dependency_required (bool) — whether wifite can run without it
    """
    required_attr_names = ['dependency_name', 'dependency_url', 'dependency_required']

    # https://stackoverflow.com/a/49024227
    def __init_subclass__(cls):
        for attr_name in cls.required_attr_names:
            if not attr_name in cls.__dict__:
                raise NotImplementedError(
                    'Attribute "{}" has not been overridden in class "{}"'
                    .format(attr_name, cls.__name__)
                )

    @classmethod
    def exists(cls):
        from ..util.process import Process
        return Process.exists(cls.dependency_name)

    @classmethod
    def fails_dependency_check(cls):
        from ..util.color import Color
        from ..util.process import Process

        if Process.exists(cls.dependency_name):
            return False

        if cls.dependency_required:
            Color.p('{!} {O}Error: Required app {R}%s{O} was not found' % cls.dependency_name)
            Color.pl('. {W}install @ {C}%s{W}' % cls.dependency_url)
            return True
        else:
            Color.p('{!} {O}Warning: Recommended app {R}%s{O} was not found' % cls.dependency_name)
            Color.pl('. {W}install @ {C}%s{W}' % cls.dependency_url)
            return False

    @classmethod
    def run_dependency_check(cls):
        """Legacy compatibility: delegates to DependencyManager."""
        DependencyManager.ensure_all()


# ---------------------------------------------------------------------------
# V3 Dependency Manager
# ---------------------------------------------------------------------------

# Map of binary name -> apt/pkg package name
_APT_PACKAGES = {
    'hcxdumptool':   'hcxdumptool',
    'hcxpcapngtool': 'hcxtools',
    'tshark':        'tshark',
    'airmon-ng':     'aircrack-ng',
    'airodump-ng':   'aircrack-ng',
    'aireplay-ng':   'aircrack-ng',
    'aircrack-ng':   'aircrack-ng',
    'hashcat':       'hashcat',
    'reaver':        'reaver',
    'bully':         'bully',
    'macchanger':    'macchanger',
    'iw':            'iw',
}

# Minimum required versions for critical tools
_MIN_VERSIONS = {
    'hcxdumptool':   (6, 0),
    'hcxpcapngtool': (6, 0),
    'hashcat':       (6, 0),
}

# Tools that are required vs. optional
_REQUIRED_TOOLS = {
    'airmon-ng',
    'airodump-ng',
    'aireplay-ng',
    'aircrack-ng',
}

_OPTIONAL_TOOLS = {
    'hcxdumptool',
    'hcxpcapngtool',
    'tshark',
    'hashcat',
    'reaver',
    'bully',
    'macchanger',
    'iw',
}


class DependencyManager(object):
    """
    V3 dependency manager with auto-install, version checking,
    and Termux/NetHunter support.
    """

    @staticmethod
    def _binary_exists(name):
        """Returns True if `name` is findable in PATH."""
        try:
            subprocess.run(
                ['which', name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    @staticmethod
    def _get_version(binary):
        """
        Tries to get the version tuple (major, minor) for a binary.
        Returns None if version cannot be determined.
        """
        for flag in ('--version', '-V', '-v'):
            try:
                result = subprocess.run(
                    [binary, flag],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=5
                )
                output = (result.stdout + result.stderr).decode('utf-8', errors='ignore')
                match = re.search(r'(\d+)\.(\d+)', output)
                if match:
                    return (int(match.group(1)), int(match.group(2)))
            except Exception:
                pass
        return None

    @staticmethod
    def _check_version(binary, min_ver):
        """
        Returns True if binary version meets the minimum requirement.
        Returns True (optimistically) if version can't be determined.
        """
        from ..util.color import Color
        ver = DependencyManager._get_version(binary)
        if ver is None:
            # Can't detect version; assume OK, warn user
            Color.pl('{!} {O}Warning: could not detect {C}%s{O} version. '
                     'Minimum required: {R}%d.%d{W}' % (binary, min_ver[0], min_ver[1]))
            return True
        if ver < min_ver:
            Color.pl('{!} {R}Error: {C}%s{R} version {O}%d.%d{R} is below minimum '
                     'required {O}%d.%d{W}' % (binary, ver[0], ver[1], min_ver[0], min_ver[1]))
            return False
        return True

    @staticmethod
    def _install_package(pkg_name):
        """
        Tries to install `pkg_name` using the appropriate package manager.
        Returns True on success, False on failure.
        """
        from ..util.color import Color
        from ..util.termux import get_package_manager, is_termux

        pm = get_package_manager()
        Color.pl('{!} {O}Attempting to install {C}%s{O} via {C}%s{W}...' % (pkg_name, pm))

        try:
            if is_termux():
                cmd = [pm, 'install', '-y', pkg_name]
            else:
                cmd = ['sudo', pm, 'install', '-y', pkg_name]

            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=120
            )
            if result.returncode == 0:
                Color.pl('{+} {G}Installed {C}%s{G} successfully{W}' % pkg_name)
                return True
            else:
                stderr = result.stderr.decode('utf-8', errors='ignore').strip()
                Color.pl('{!} {R}Failed to install {C}%s{R}: %s{W}' % (pkg_name, stderr[:200]))
                return False
        except subprocess.TimeoutExpired:
            Color.pl('{!} {R}Timeout installing {C}%s{W}' % pkg_name)
            return False
        except Exception as e:
            Color.pl('{!} {R}Error installing {C}%s{R}: %s{W}' % (pkg_name, str(e)))
            return False

    @staticmethod
    def ensure_all(auto_install=True):
        """
        Main V3 dependency check:
        1. Detect environment (Kali/Parrot/Termux/NetHunter)
        2. Check all required + optional tools
        3. Auto-install missing tools if possible
        4. Version-check critical tools
        5. Exit if required tools are still missing after install attempts
        """
        from ..util.color import Color
        from ..util.termux import get_environment_name, adjust_path

        # Adjust PATH for Termux
        adjust_path()

        env = get_environment_name()
        Color.pl('{+} {C}Environment: {G}%s{W}' % env)
        Color.pl('{+} Checking dependencies...')

        missing_required = []
        missing_optional = []

        all_tools = list(_REQUIRED_TOOLS) + list(_OPTIONAL_TOOLS)

        for tool in all_tools:
            if DependencyManager._binary_exists(tool):
                continue  # Tool found

            pkg = _APT_PACKAGES.get(tool, tool)
            if tool in _REQUIRED_TOOLS:
                if auto_install:
                    Color.pl('{!} {O}Required tool {R}%s{O} not found. '
                             'Attempting install...{W}' % tool)
                    success = DependencyManager._install_package(pkg)
                    if not success or not DependencyManager._binary_exists(tool):
                        missing_required.append(tool)
                else:
                    missing_required.append(tool)
            else:
                if auto_install:
                    Color.pl('{!} {O}Optional tool {C}%s{O} not found. '
                             'Attempting install...{W}' % tool)
                    DependencyManager._install_package(pkg)
                    if not DependencyManager._binary_exists(tool):
                        missing_optional.append(tool)
                else:
                    missing_optional.append(tool)

        # Report missing optional tools (non-fatal)
        if missing_optional:
            Color.pl('{!} {O}Optional tools not available: {C}%s{W}' %
                     ', '.join(missing_optional))
            Color.pl('{!} {O}Some attack modes will be disabled.{W}')

        # Exit if required tools are still missing
        if missing_required:
            Color.pl('{!} {R}Critical: Required tools missing: {O}%s{W}' %
                     ', '.join(missing_required))
            Color.pl('{!} {R}Wifite cannot continue without these tools.{W}')
            Color.pl('{!} {O}Try running: {C}sudo apt install %s{W}' %
                     ' '.join(_APT_PACKAGES.get(t, t) for t in missing_required))
            sys.exit(1)

        # Version checks for critical tools
        version_ok = True
        for tool, min_ver in _MIN_VERSIONS.items():
            if DependencyManager._binary_exists(tool):
                if not DependencyManager._check_version(tool, min_ver):
                    version_ok = False

        if not version_ok:
            Color.pl('{!} {R}One or more tools are below the minimum required version.{W}')
            Color.pl('{!} {O}Please upgrade: {C}sudo apt update && sudo apt upgrade{W}')
            sys.exit(1)

        Color.pl('{+} {G}All dependency checks passed.{W}')
