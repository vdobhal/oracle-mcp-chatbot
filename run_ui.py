"""Direct entry point to run the Chatbot UI."""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# Ensure local dependencies and source code are in sys.path
pydeps = str(ROOT / ".pydeps")
src = str(ROOT / "src")

if pydeps not in sys.path:
    sys.path.insert(0, pydeps)
if src not in sys.path:
    sys.path.insert(0, src)

# Also update PYTHONPATH in environment for child/reload processes
current_pythonpath = os.environ.get("PYTHONPATH", "")
os.environ["PYTHONPATH"] = f"{pydeps}:{src}:{current_pythonpath}".strip(":")

if __name__ == "__main__":
    import uvicorn
    from oracle_mcp.settings import load_env_file

    load_env_file()
    host = os.environ.get("CHAT_UI_HOST", "127.0.0.1").strip() or "127.0.0.1"
    port_str = os.environ.get("CHAT_UI_PORT", "8090").strip()
    try:
        port = int(port_str)
    except ValueError:
        port = 8090

    print(f"Starting MDM (CDM,IB, Collibra) Data Assistant Web UI on http://{host}:{port} ...")
    uvicorn.run("oracle_mcp.webapp:app", host=host, port=port, reload=True)
