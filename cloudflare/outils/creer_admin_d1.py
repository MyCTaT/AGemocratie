"""Initialise un unique compte principal sur la base D1 Cloudflare."""
from getpass import getpass
import hashlib
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile

ITERATIONS = 600_000
MIN_PASSWORD_LENGTH = 16
ROOT = Path(__file__).resolve().parents[1]


def main():
    identifiant = input("Identifiant du compte principal (3 ? 32 caract?res) : ").strip().lower()
    if not re.fullmatch(r"[a-z0-9_-]{3,32}", identifiant):
        raise SystemExit("Identifiant invalide.")
    password = getpass("Mot de passe (16 caract?res minimum) : ")
    confirmation = getpass("Confirmer le mot de passe : ")
    if not MIN_PASSWORD_LENGTH <= len(password) <= 256 or password != confirmation:
        raise SystemExit("Mot de passe invalide ou confirmation diff?rente.")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    value = f"pbkdf2_sha256${ITERATIONS}${salt.hex()}${digest.hex()}"
    sql = (
        "UPDATE administrateurs SET identifiant='" + identifiant + "', "
        "mot_de_passe_hash='" + value + "', auth_version=auth_version+1 "
        "WHERE role='principal'; "
        "INSERT INTO administrateurs (identifiant,mot_de_passe_hash,role) "
        f"SELECT '{identifiant}','{value}','principal' WHERE changes()=0"
    )
    temp_dir = ROOT / ".wrangler"
    temp_dir.mkdir(exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix="admin-init-", suffix=".sql", dir=temp_dir)
    try:
        try:
            os.chmod(temp_path, 0o600)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(sql)
        subprocess.run(
            ["uv", "run", "pywrangler", "d1", "execute", "agemocratie-db", "--remote", "--file", temp_path],
            cwd=ROOT,
            check=True,
        )
    finally:
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    main()
