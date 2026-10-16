"""Linux engine launcher: the supervised process dies with its parent agent."""

import argparse
import ctypes
import os
import signal


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parent", required=True, type=int)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:  # PR_SET_PDEATHSIG
        raise OSError(ctypes.get_errno(), "Cannot bind engine lifetime to supervisor")
    if os.getppid() != args.parent:
        raise SystemExit(137)
    os.execv(args.binary, [args.binary, "run", "-c", args.config])


if __name__ == "__main__":
    main()
