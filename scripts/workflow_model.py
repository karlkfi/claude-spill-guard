#!/usr/bin/env python3
"""Read the workflow files through the parser in tools/, as Python data.

Two gates need to know what a workflow says: `action-pins` checks every `uses:`
ref, and `gate-drift` reads the job list. Both used to read the file with a
regular expression, which is wrong in the direction nobody notices -- a `uses:`
in a comment or a `run:` block is not a key, and a job name the pattern misses
is not seen at all. `yaml` is not importable on a machine that satisfies `make
doctor`, so the parse lives in `tools/cmd/workflow` and this is the seam.

Failing closed is the whole point, so every way this can come back empty is an
exit rather than a shorter list: a build that did not run, output that is not
JSON, a file the model does not name.
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
WORKFLOW_DIR = ROOT / ".github" / "workflows"

# `go run` rather than a committed binary: the version is pinned by tools/go.mod
# and nothing has to be rebuilt by hand when it moves. Measured warm, the build
# is a fraction of the gate it sits in.
COMMAND = ("go", "run", "./cmd/workflow")


def workflow_paths():
    """Every workflow file, sorted. Empty is an exit: a pin gate that checked
    nothing passes, and reads exactly like one that checked everything."""
    found = sorted(p for p in WORKFLOW_DIR.glob("*.y*ml") if p.suffix in (".yml", ".yaml"))
    if not found:
        sys.exit(f"workflow: no workflow files under "
                 f"{WORKFLOW_DIR.relative_to(ROOT)}, so nothing below could "
                 f"have failed")
    return found


def load(paths=None):
    """{path relative to the repo: {"jobs": [...], "uses": [...]}}."""
    paths = list(paths) if paths is not None else workflow_paths()
    result = subprocess.run(COMMAND + tuple(str(p) for p in paths), cwd=TOOLS,
                            capture_output=True, text=True, check=False)
    if result.returncode != 0:
        sys.exit(f"workflow: the parser in tools/cmd/workflow exited "
                 f"{result.returncode}. Go is a required tool -- see `make "
                 f"doctor`.\n{result.stderr.strip()}")
    try:
        model = json.loads(result.stdout)
    except json.JSONDecodeError as err:
        sys.exit(f"workflow: the parser wrote something that is not JSON "
                 f"({err}). Anything else on its stdout would be read as the "
                 f"model.\n{result.stdout[:400]}")

    files = {}
    for entry in model.get("files", ()):
        files[str(Path(entry["path"]).resolve().relative_to(ROOT))] = entry
    missing = [str(Path(p).resolve().relative_to(ROOT)) for p in paths
               if str(Path(p).resolve().relative_to(ROOT)) not in files]
    if missing:
        sys.exit(f"workflow: the parser returned no model for "
                 f"{', '.join(missing)}, so those files went unchecked")
    return files
