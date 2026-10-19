"""TTY-only installer workspace. No shell interpolation or third-party UI deps."""

import contextlib
import json
import os
import re
import sys

from app import __version__
from .common import InstallError
from .preflight import domain_name


class Screen:
    def __init__(self, tty):
        self.tty = tty
        self.screen = os.environ.get("TERM", "dumb") != "dumb"
        self.color = self.screen and "NO_COLOR" not in os.environ

    def write(self, text):
        self.tty.write(text)
        self.tty.flush()

    def ask(self, label, default=""):
        self.write(label + (f" [{default}]" if default else "") + ": ")
        value = self.tty.readline()
        if not value:
            raise EOFError
        value = value.strip()
        if any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise InstallError("Control characters are not allowed")
        return value or default

    def draw(self, state):
        self.write("\033[2J\033[H" if self.screen else "\n")
        title = "DONINO PANEL  /  SETUP & MANAGEMENT"
        if self.color:
            title = "\033[1;36m" + title + "\033[0m"
        # State is local root-owned metadata, still strip terminal control codes.
        host = re.sub(r"[^a-zA-Z0-9.:-]", "", str(state.get("domain", "Not installed")))
        self.write("\n  " + title + "\n  " + "─" * 58 + "\n")
        self.write(f"  Version {__version__}     Host: {host}\n")
        self.write("  " + "─" * 58 + "\n\n")
        for key, text in (
            ("1", "Install HTTP  /  IPv4 or domain, no SSL"),
            ("2", "Install HTTPS /  automatic Let's Encrypt"),
            ("3", "Install HTTPS /  existing certificate"),
            ("4", "Status and readiness"),
            ("5", "Repair installed services"),
            ("6", "Create encrypted backup"),
            ("7", "Upgrade from a pinned release"),
            ("8", "Create first-owner setup link"),
            ("9", "Uninstall services (preserve data)"),
            ("0", "Exit"),
        ):
            self.write(f"    {key}   {text}\n")
        self.write("\n  HTTPS nodes keep certificate verification enabled.\n\n")

    def plan(self, option, state):
        if option in ("1", "2", "3"):
            mode = {"1": "none", "2": "acme", "3": "existing"}[option]
            host = domain_name(
                self.ask(
                    "Panel IPv4 or domain" if mode == "none" else "Panel domain",
                    state.get("domain", ""),
                ),
                allow_ip=mode == "none",
            )
            args = ["install", "--domain", host, "--tls", mode]
            if mode == "none":
                self.write(
                    "\n  HTTP sends login/cookies without encryption; remote mTLS nodes need HTTPS.\n"
                )
            elif mode == "acme":
                self.write(
                    "\n  Point A/AAAA to this server and open public TCP 80/443.\n"
                )
                email = self.ask("Certificate contact email (optional)")
                if email:
                    args += ["--email", email]
            else:
                args += [
                    "--cert-file",
                    self.ask("Absolute fullchain certificate path"),
                    "--key-file",
                    self.ask("Absolute private-key path"),
                ]
                ca = self.ask("Private CA file (optional)")
                if ca:
                    args += ["--ca-file", ca]
            self.write(
                f"\n  Install {host} / {mode}. PostgreSQL, NGINX, Python and systemd are automatic.\n"
            )
            return args
        return {
            "4": ["doctor"],
            "5": ["repair"],
            "6": ["backup"],
            "8": ["bootstrap"],
            "9": ["uninstall"],
        }.get(option)


def release_ref(version):
    match = re.fullmatch(r"(\d+\.\d+\.\d+)(?:(a|b|rc)(\d+))?", version)
    if not match:
        raise InstallError("Invalid release version")
    return (
        "v"
        + match[1]
        + (
            "-" + {"a": "alpha", "b": "beta", "rc": "rc"}[match[2]] + "." + match[3]
            if match[2]
            else ""
        )
    )


def run_menu(tty, *, execute, read_state, upgrade):
    screen = Screen(tty)
    try:
        if screen.screen:
            screen.write("\033[?1049h")
        while True:
            state = read_state()
            screen.draw(state)
            choice = screen.ask("Choose", "0")
            if choice == "0":
                return 0
            try:
                if choice == "7":
                    ref = screen.ask(
                        "Release tag or full commit", release_ref(__version__)
                    )
                    if not re.fullmatch(
                        r"(?:[0-9a-f]{40}|v\d+\.\d+\.\d+(?:[-.][A-Za-z0-9.]+)?)", ref
                    ):
                        raise InstallError("Use a pinned release tag or full commit")
                    if (
                        screen.ask(
                            "Download verified release and upgrade? y/N", "n"
                        ).lower()
                        == "y"
                    ):
                        result = upgrade(ref)
                    else:
                        continue
                else:
                    args = screen.plan(choice, state)
                    if args is None:
                        screen.write("Invalid option.\n")
                        screen.ask("Press Enter to return")
                        continue
                    if (
                        choice != "4"
                        and screen.ask("Continue? y/N", "n").lower() != "y"
                    ):
                        continue
                    result = execute(args)
                screen.write(
                    f"\n  Operation finished: {'OK' if result == 0 else 'failed (code ' + str(result) + ')'}.\n"
                )
                screen.ask("Press Enter to return to menu")
            except (InstallError, OSError, ValueError) as exc:
                # Never echo arbitrary exception/command data containing credentials.
                screen.write(
                    "\n  Setup failed ("
                    + type(exc).__name__
                    + "). Check installer status and service logs.\n"
                )
                screen.ask("Press Enter to return")
    except (EOFError, KeyboardInterrupt):
        return 0
    finally:
        if screen.screen:
            screen.write("\033[?1049l")


def main():
    if os.geteuid() != 0:
        print("Use sudo donino or sudo sh install.sh menu", file=sys.stderr)
        return 2
    from . import install
    from .bootstrap import main as bootstrap

    def state():
        return json.loads(install.STATE.read_text()) if install.STATE.exists() else {}

    def upgrade(ref):
        return bootstrap(["--ref", ref, "upgrade"])

    try:
        # curl | sudo sh does not leave stdin connected to the keyboard.
        with contextlib.ExitStack() as stack:
            reader = stack.enter_context(open("/dev/tty", "r", encoding="utf8"))
            writer = stack.enter_context(
                open("/dev/tty", "w", encoding="utf8", buffering=1)
            )

            class Terminal:
                readline = reader.readline
                write = writer.write
                flush = writer.flush

            return run_menu(
                Terminal(), execute=install.main, read_state=state, upgrade=upgrade
            )
    except (OSError, ValueError):
        print(
            "Menu needs a terminal and readable installer state. Use explicit install --domain HOST --tls none|acme|existing for automation.",
            file=sys.stderr,
        )
        return 2
