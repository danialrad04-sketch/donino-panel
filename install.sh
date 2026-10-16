#!/bin/sh
set -eu
donino_source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
case "$0" in
  */install.sh|install.sh) donino_local_source=true ;;
  *) donino_local_source=false ;;
esac
if [ "$donino_local_source" = true ] && [ -f "$donino_source_dir/ops/install.py" ]; then
    cd "$donino_source_dir"
    exec python3 -I -c 'import sys; sys.path.insert(0,sys.argv.pop(1)); from ops.install import main; raise SystemExit(main())' "$donino_source_dir" "$@"
fi
# Ref and downloader hash are pinned for the published checkpoint.
donino_release_ref=${DONINO_REF:-v1.0.0-alpha.6}
donino_bootstrap_sha256=e0b3ecdeba21beee53049dfb9690880b786175ff9b612f457a2bbd53d0f1db3b
exec python3 -I - "$donino_release_ref" "$donino_bootstrap_sha256" "$@" <<'PYTHON'
import hashlib
import re
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
ref, expected = sys.argv[1:3]
if not re.fullmatch(r"(?:[0-9a-f]{40}|v\d+\.\d+\.\d+(?:[-.][A-Za-z0-9.]+)?)", ref):
    raise SystemExit("Use a version tag or full commit ID")
url = "https://raw.githubusercontent.com/danialrad04-sketch/donino-panel/" + ref + "/ops/bootstrap.py"
with urllib.request.urlopen(url, timeout=60) as response:
    content = response.read(262145)
if len(content) > 262144 or hashlib.sha256(content).hexdigest() != expected:
    raise SystemExit("Bootstrap checksum mismatch; refusing execution")
with tempfile.TemporaryDirectory(prefix="donino-bootstrap-") as folder:
    path = Path(folder) / "bootstrap.py"
    path.write_bytes(content)
    result = subprocess.run([sys.executable, "-I", str(path), "--ref", ref, *sys.argv[3:]])
    raise SystemExit(result.returncode)
PYTHON
