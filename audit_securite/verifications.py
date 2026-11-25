"""V?rifications locales actuelles, aucun acc?s production ni mail r?el."""
from pathlib import Path
import subprocess
import sys
root=Path(__file__).resolve().parents[1]
raise SystemExit(subprocess.call([sys.executable,"-m","unittest","discover","-s",str(root/"cloudflare/tests"),"-v"],cwd=root))
