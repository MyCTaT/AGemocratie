"""Prépare les secrets MFA privés, sans les afficher ni contacter Cloudflare."""
import argparse,base64,json,secrets,re
from pathlib import Path
from urllib.parse import quote
ROOT=Path(__file__).resolve().parents[2]

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--username',default='admin');args=parser.parse_args()
    user=args.username.strip().lower()
    if not re.fullmatch('[a-z0-9_-]{3,32}',user):raise SystemExit('Identifiant invalide')
    path=ROOT/'.env';lines=path.read_text(encoding='utf8').splitlines() if path.exists() else []
    raw=next((line.split('=',1)[1] for line in lines if line.startswith('ADMIN_TOTP_SECRETS=')),'{}')
    data=json.loads(raw);data.setdefault(user,base64.b32encode(secrets.token_bytes(20)).decode())
    lines=[line for line in lines if not line.startswith('ADMIN_TOTP_SECRETS=')]
    lines.append('ADMIN_TOTP_SECRETS='+json.dumps(data,separators=(',',':')))
    path.write_text('\n'.join(lines)+'\n',encoding='utf8')
    folder=ROOT/'.apercu_local/.state';folder.mkdir(parents=True,exist_ok=True)
    (folder/'admin_totp_secrets.json').write_text(json.dumps(data,separators=(',',':')),encoding='utf8')
    text='MFA administration AGemocratie — fichier prive, ne pas partager.\nAjouter une cle manuellement dans une application TOTP (30 secondes, 6 chiffres, SHA1).\n'
    for username,seed in data.items():
        uri='otpauth://totp/'+quote('AGemocratie:'+username)+'?secret='+seed+'&issuer=AGemocratie&digits=6&period=30'
        text+='\nCompte : '+username+'\nCle secrete : '+seed+'\nURI : '+uri+'\n'
    (folder/'mfa_admin.txt').write_text(text,encoding='utf8')
    print('MFA prepare. Ouvrir le fichier prive .apercu_local/.state/mfa_admin.txt pour configurer votre application. Aucun secret affiche.')

if __name__=='__main__':main()
