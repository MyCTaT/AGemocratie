"""Message OTP Brevo commun au Worker et aux outils locaux, sans accès Gmail."""
import re

ENDPOINT='https://api.brevo.com/v3/smtp/email'
KEYS=('BREVO_API_KEY','BREVO_SENDER_EMAIL','BREVO_PRIVACY_CONFIRMED')
UNIVERSITY_PATTERN=r"[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(etu\.sorbonne-universite\.fr|sorbonne-universite\.fr)"

def validate_settings(settings):
    missing=[key for key in KEYS if not settings.get(key)]
    if missing:raise RuntimeError('Configuration Brevo manquante : '+', '.join(missing))
    key=settings['BREVO_API_KEY']
    if not isinstance(key,str) or len(key)<20 or not key.isascii() or any(c.isspace() for c in key):
        raise RuntimeError('Clé API Brevo invalide')
    sender=settings['BREVO_SENDER_EMAIL']
    if not isinstance(sender,str) or len(sender)>254 or not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}",sender):
        raise RuntimeError('Adresse expéditeur Brevo invalide')
    if settings['BREVO_PRIVACY_CONFIRMED']!='1':
        raise RuntimeError('Confirmer la désactivation des aperçus dans le compte Brevo avant activation')

def payload(settings,to,otp):
    validate_settings(settings)
    if not isinstance(to,str) or len(to)>254 or not re.fullmatch(UNIVERSITY_PATTERN,to):
        raise ValueError('Adresse universitaire invalide')
    if not isinstance(otp,str) or not re.fullmatch('[0-9]{6}',otp):
        raise ValueError('Seul un code de vérification de six chiffres est autorisé')

    return {
        'sender':{'name':'AGémocratie','email':settings['BREVO_SENDER_EMAIL']},
        'to':[{'email':to}],
        'subject':'AGémocratie — vérification de votre adresse',
        'textContent':'Votre code de vérification : '+otp+'\nValable 10 minutes. Ce code ne permet pas de voter. Ne le partagez pas.',
    }
