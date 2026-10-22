"""Crée localement un SQL d'initialisation d'un administrateur principal D1.
Ne nécessite pas Cloudflare ni d'accès au fichier .env.
Aucun mot de passe n'est écrit sur disque par le script.
"""
from getpass import getpass
import hashlib
import secrets

ITERATIONS = 390_000

def main():
    mot_de_passe = getpass("Mot de passe du compte 'admin' (12 caractères min.) : ")
    confirmation = getpass("Confirmer le mot de passe : ")
    if not (12 <= len(mot_de_passe) <= 256) or mot_de_passe != confirmation:
        raise SystemExit("Mot de passe invalide ou confirmation différente.")
    sel = secrets.token_bytes(16)
    empreinte = hashlib.pbkdf2_hmac("sha256", mot_de_passe.encode("utf-8"), sel, ITERATIONS)
    valeur = f"pbkdf2_sha256${ITERATIONS}${sel.hex()}${empreinte.hex()}"
    print("\nColle cette instruction dans la console de ta base D1 :\n")
    print("INSERT INTO administrateurs (identifiant, mot_de_passe_hash, role) "
          f"VALUES ('admin', '{valeur}', 'principal');")
    print("\nSi le compte admin existe déjà, ne l'écrase pas automatiquement.")

if __name__ == '__main__':
    main()
