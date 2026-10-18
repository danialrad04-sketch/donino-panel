"""Linux launcher: a temporary probe engine must die with its API worker."""

import argparse
import ctypes
import os
import signal


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parent", required=True, type=int)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not args.command or not os.path.isabs(args.command[0]):
        parser.error("An absolute executable is required")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "Cannot bind probe lifetime to worker")
    if os.getppid() != args.parent:
        raise SystemExit(137)
    os.execv(args.command[0], args.command)


if __name__ == "__main__":
    main()
