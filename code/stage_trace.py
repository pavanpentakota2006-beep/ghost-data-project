#!/usr/bin/env python3
"""Stage an agent-trace.zip from folders you name (never auth/config files).
Usage: python3 code/stage_trace.py claude-code=~/.claude/projects/<your-project-folder> [codex=<dir>] ...
Review the staged folder for secrets before submitting."""
import sys, shutil, zipfile
from pathlib import Path

BLOCK = {"auth.json", "config.toml", "config.json", "mcp.json", "mcp_config.json", ".env", "credentials.json"}
stage = Path("agent-trace")
if stage.exists():
    shutil.rmtree(stage)
for arg in sys.argv[1:]:
    name, _, src = arg.partition("=")
    src = Path(src).expanduser()
    for f in ([src] if src.is_file() else src.rglob("*")):
        if f.is_file() and f.name not in BLOCK:
            dst = stage / name / (f.name if src.is_file() else f.relative_to(src))
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, dst)
with zipfile.ZipFile("agent-trace.zip", "w", zipfile.ZIP_DEFLATED) as z:
    for f in stage.rglob("*"):
        if f.is_file():
            z.write(f, f)
print("wrote agent-trace.zip - open it and check for secrets/personal data before uploading")
