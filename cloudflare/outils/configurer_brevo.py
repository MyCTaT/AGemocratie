"""Configuration locale privée Brevo. Aucun mail envoyé par cet outil."""
import argparse
import getpass
import json
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request

CF=Path(__file__).resolve().parents[1]
ROOT=CF.parent
sys.path.insert(0,str(CF))
from brevo_mail import validate_settings

def read_env(path):
    result={}
    if path.exists():
        for line in path.read_text(encoding='utf-8-sig').splitlines():
            if not line.strip() or line.lstrip().startswith('#') or '=' not in line:continue
            key,value=line.split('=',1);value=value.strip()
            if len(value)>1 and value[0]==value[-1] and value[0] in ('"',"'"):value=value[1:-1]
            result[key.strip()]=value
    return result

def verify_sender(settings):
    validate_settings(settings)
    request=urllib.request.Request('https://api.brevo.com/v3/senders',
        headers={'api-key':settings['BREVO_API_KEY'],'accept':'application/json'})
    try:

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*args):return None
        with urllib.request.build_opener(NoRedirect).open(request,timeout=20) as response:
            data=json.load(response)
    except (urllib.error.URLError,ValueError):
        raise RuntimeError('Vérification Brevo impossible. Contrôler la clé API, les restrictions IP et la connexion.') from None
    if not any(sender.get('active') is True and sender.get('email','').lower()==settings['BREVO_SENDER_EMAIL'].lower() for sender in data.get('senders',[])):
        raise RuntimeError('Cet expéditeur doit être validé et actif dans Brevo avant activation.')

def write_env(path,updates):
    text=path.read_text(encoding='utf-8-sig') if path.exists() else ''
    lines=[];remaining=dict(updates)
    for line in text.splitlines():
        match=re.match(r'^\s*([A-Z_][A-Z_0-9]*)\s*=',line)
        if match and match[1] in updates:
            if match[1] in remaining:lines.append(match[1]+'='+remaining.pop(match[1]))
        else:lines.append(line)
    lines.extend(key+'='+value for key,value in remaining.items())
    path.write_text('\n'.join(lines)+'\n',encoding='utf-8')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verifier',action='store_true',help='vérifie la configuration sans envoyer de mail ni modifier .env')
    args=parser.parse_args();path=ROOT/'.env';settings=read_env(path)
    if args.verifier:
        verify_sender(settings)
        print('Clé API et expéditeur Brevo vérifiés. Aucun mail envoyé. Les réglages de conservation se vérifient dans Brevo.')
        return
    print('Dans Brevo : Paramètres > Emails transactionnels > Règles de conservation.')
    print('Choisir de ne jamais conserver les aperçus et limiter les journaux à un mois, puis enregistrer.')
    print('Désactiver aussi le suivi des ouvertures et clics pour les mails transactionnels.')
    if input('Ces réglages ont-ils été enregistrés ? Taper oui : ').strip().lower()!='oui':
        raise RuntimeError('Configuration laissée inchangée.')
    sender=input('Adresse expéditeur déjà validée dans Brevo : ').strip()
    key=getpass.getpass('Clé API Brevo (saisie masquée, jamais à coller dans le chat) : ').strip()
    updates={'BREVO_API_KEY':key,'BREVO_SENDER_EMAIL':sender,'BREVO_PRIVACY_CONFIRMED':'1','MAIL_MODE':'brevo'}
    verify_sender(updates)
    write_env(path,updates)
    print('Configuration privée enregistrée. Relancer l’aperçu pour activer Brevo. Aucun mail envoyé.')

if __name__=='__main__':
    try:main()
    except (RuntimeError,EOFError,KeyboardInterrupt) as error:
        print(str(error) or 'Configuration interrompue.',file=sys.stderr);sys.exit(1)
