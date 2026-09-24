from __future__ import annotations

import os
import platform
import sys

_OS_NAMES = {
    "darwin": "darwin",
    "linux": "linux",
    "windows": "windows",
    "freebsd": "freebsd",
    "openbsd": "openbsd",
    "netbsd": "netbsd",
    "dragonfly": "dragonfly",
    "sunos": "solaris",
    "aix": "aix",
}

_ARCH_NAMES = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "x64": "amd64",
    "i386": "386",
    "i486": "386",
    "i586": "386",
    "i686": "386",
    "x86": "386",
    "aarch64": "arm64",
    "arm64": "arm64",
    "armv8l": "arm64",
    "armv6l": "arm",
    "armv7l": "arm",
    "armv7": "arm",
    "arm": "arm",
    "ppc64le": "ppc64le",
    "ppc64": "ppc64",
    "s390x": "s390x",
    "riscv64": "riscv64",
    "mips": "mips",
    "mipsel": "mipsle",
    "mips64": "mips64",
    "mips64el": "mips64le",
    "loongarch64": "loong64",
}


def current_os() -> str:
    """Return the operating system name using Go naming, e.g. linux or darwin."""
    name = platform.system().lower()
    if name.startswith(("cygwin", "msys", "mingw")):
        return "windows"
    return _OS_NAMES.get(name, name or "unknown")


def current_arch() -> str:
    """Return the CPU architecture using Go naming, e.g. amd64 or arm64."""
    machine = platform.machine().lower()
    arch = _ARCH_NAMES.get(machine, machine or "unknown")
    if arch == "amd64" and sys.maxsize <= 2**32:
        return "386"
    if arch == "arm64" and sys.maxsize <= 2**32:
        return "arm"
    return arch


def current_platform() -> str:
    return f"{current_os()}/{current_arch()}"


def default_ext() -> str:
    return "exe" if current_os() == "windows" else ""


def current_executable() -> str:
    """Path of the running program, used as the default upgrade target."""
    if getattr(sys, "frozen", False) or not sys.argv or not sys.argv[0] or sys.argv[0] == "-c":
        return os.path.realpath(sys.executable)
    return os.path.realpath(sys.argv[0])


def default_program() -> str:
    name = os.path.basename(current_executable())
    ext = default_ext()
    if ext and name.lower().endswith("." + ext):
        name = name[: -(len(ext) + 1)]
    return name


def cpu_count() -> int:
    return os.cpu_count() or 1
