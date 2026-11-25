"""Seul ajout au Worker : délivrance autonome d'un code d'AG par mail."""
import asyncio
import hashlib
import hmac
import json
import re
import secrets
import time
from typing import Annotated

from fastapi import HTTPException, Request, Path as PathParam
from workers import fetch
from security_controls import consume_attempts, migrate_legacy_address
from brevo_mail import ENDPOINT as BREVO_ENDPOINT, KEYS as BREVO_KEYS, payload as brevo_payload

AgId = Annotated[int, PathParam(ge=1, le=9_007_199_254_740_991)]
EMAIL_PATTERN = r"[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(etu\.sorbonne-universite\.fr|sorbonne-universite\.fr)"


def adresse_universitaire(value):
    value = value.strip().lower()
    if len(value) > 254 or not re.fullmatch(EMAIL_PATTERN, value):
        raise HTTPException(400, "Utilisez une adresse @etu.sorbonne-universite.fr ou @sorbonne-universite.fr.")
    return value


def _binding(core, request, name):
    for env in (core['cloudflare_env'], request.scope.get('env')):
        value = getattr(env, name, None) if env is not None else None
        if hasattr(value, 'to_py'):
            value = value.to_py()
        if isinstance(value, str) and value:
            return value
    raise RuntimeError('Configuration mail manquante')


async def envoyer_verification(core, request, *, to, otp):
    """Fournisseur explicite ; jamais de repli automatique vers un autre circuit."""
    if not isinstance(otp,str) or not re.fullmatch('[0-9]{6}',otp):
        raise ValueError('Seul un code de vérification de six chiffres est autorisé')
    adresse_universitaire(to)
    try:provider=_binding(core,request,'AG_MAIL_PROVIDER')
    except RuntimeError:provider='gmail'
    if provider=='gmail':
        url=_binding(core,request,'AG_MAIL_URL');key=_binding(core,request,'AG_MAIL_SECRET')
        if not re.fullmatch(r'https://script\.google\.com/macros/s/[A-Za-z0-9_-]+/exec',url) or len(key)<32:
            raise RuntimeError('Configuration Gmail invalide')
        payload=json.dumps({'to':to,'otp':otp,'timestamp':int(time.time()),'id':secrets.token_hex(24)},separators=(',',':'))
        signature=hmac.new(key.encode(),payload.encode(),hashlib.sha256).hexdigest()
        async def send_gmail():
            response=await fetch(url,method='POST',redirect='follow',headers={'content-type':'application/json'},
                body=json.dumps({'payload':payload,'signature':signature}))
            data=await response.json()
            if hasattr(data,'to_py'):data=data.to_py()
            if response.status!=200 or dict(data).get('ok') is not True:raise RuntimeError('Envoi Gmail indisponible')
        await asyncio.wait_for(send_gmail(),timeout=25)
        return
    if provider!='brevo':raise RuntimeError('Fournisseur mail invalide')
    settings={name:_binding(core,request,name) for name in BREVO_KEYS}
    body=brevo_payload(settings,to,otp)
    async def send():
        response=await fetch(BREVO_ENDPOINT,method='POST',redirect='error',
            headers={'content-type':'application/json','accept':'application/json','api-key':settings['BREVO_API_KEY']},
            body=json.dumps(body,ensure_ascii=False,separators=(',',':')))

        if response.status!=201:raise RuntimeError('Envoi Brevo indisponible')
    await asyncio.wait_for(send(), timeout=25)


def installer(app, core):
    bdd = core['_bdd']
    objet = core['_objet']
    rendu = core['_rendu']
    signature = core['_signature']
    secret = core['_secret']
    detail = core['_ag_detail']
    csrf = core['_csrf_valide']
    lien = core['_lien']

    def cookie(ag_id):
        return f'__Host-ag-mail-{ag_id}'

    def token_hash(request, token):
        return signature(secret(request), ('ag-mail-token:' + token).encode())

    def empreinte_ancienne(request, email):

        return signature(core['_secret_codes'](request), ('ag-mail-address:' + email).encode())

    async def challenge(request, ag_id):
        token = request.cookies.get(cookie(ag_id), '')
        if not re.fullmatch('[A-Za-z0-9_-]{43}', token):
            return None
        return objet(await bdd(request).prepare(
            'SELECT * FROM ag_mail_verifications WHERE token_hash=? AND assemblee_id=?'
        ).bind(token_hash(request, token), ag_id).first())

    async def access_page(request, ag, compte=None, *, statut=200, email_error=None, email_value=''):
        row = await challenge(request, ag['id'])
        active = bool(row and int(row['expire_le']) > int(time.time())
                      and (row['verifie'] or int(row['essais']) < 5))
        return rendu(request, 'ag_access.html', compte=compte, ag=ag, statut=statut,
                     pending=active, verified=bool(active and row['verifie']),
                     email_error=email_error, email_value=email_value)

    async def rate_limit(request, email):

        window = int(time.time()) // 900
        scopes = [(signature(secret(request), f'ag-mail-ip-v2:{window}:{core["_ip_normalisee"](request)}'.encode()), 300),
                  (signature(secret(request), f'ag-mail-rate-v2:{window}:{email}'.encode()), 5)]
        if not await consume_attempts(bdd(request), scopes):
            raise HTTPException(429, 'Trop de demandes. Réessayez dans 15 minutes.')

    @app.post('/ag/{id_ag}/email/send')
    async def send_code(request: Request, id_ag: AgId):
        ag = await detail(request, id_ag)
        form = await request.form()

        csrf(request, secret(request), form)
        value = str(form.get('email', ''))[:255]
        try:
            email = adresse_universitaire(value)
            await rate_limit(request, email)
            scoped_hash = await migrate_legacy_address(bdd(request), core["_secret_codes"](request), id_ag, empreinte_ancienne(request, email))
            token = secrets.token_urlsafe(32)
            hashed_token = token_hash(request, token)
            otp = f'{secrets.randbelow(1000000):06d}'
            db = bdd(request)
            previous = request.cookies.get(cookie(id_ag), '')
            await db.batch([
                db.prepare('DELETE FROM ag_mail_verifications WHERE expire_le<=? OR token_hash=?').bind(
                    int(time.time()), token_hash(request, previous)),
                db.prepare('INSERT INTO ag_mail_verifications(token_hash,assemblee_id,email_hash,otp_hash,expire_le) VALUES (?,?,?,?,?)').bind(
                    hashed_token, id_ag, scoped_hash,
                    signature(secret(request), (hashed_token + ':' + otp).encode()), int(time.time()) + 600),
            ])
            try:
                await envoyer_verification(core, request, to=email, otp=otp)
            except Exception:
                await db.prepare('DELETE FROM ag_mail_verifications WHERE token_hash=?').bind(hashed_token).run()
                raise HTTPException(503, "Le mail n'a pas pu être envoyé. Réessayez dans un instant.") from None
        except HTTPException as error:
            return await access_page(request, ag, statut=error.status_code, email_error=error.detail, email_value=value[:254])
        response = lien(f'/ag/{id_ag}')
        response.set_cookie(cookie(id_ag), token, max_age=600, secure=True, httponly=True, samesite='lax', path='/')
        return response

    @app.post('/ag/{id_ag}/email/verify')
    async def verify_code(request: Request, id_ag: AgId):
        ag = await detail(request, id_ag)
        form = await request.form()
        csrf(request, secret(request), form)
        row = await challenge(request, id_ag)
        error = 'Code expiré ou trop de tentatives. Demandez un nouveau code.'
        if row and not row['verifie'] and int(row['expire_le']) > int(time.time()) and int(row['essais']) < 5:
            otp = str(form.get('otp', '')).strip()
            otp_hash = signature(secret(request), (row['token_hash'] + ':' + otp).encode())

            await bdd(request).prepare("""UPDATE ag_mail_verifications
                SET essais=essais+1,verifie=CASE WHEN otp_hash=? THEN 1 ELSE 0 END
                WHERE token_hash=? AND assemblee_id=? AND verifie=0 AND essais<5 AND expire_le>?""").bind(
                    otp_hash, row['token_hash'], id_ag, int(time.time())).run()
            current = await challenge(request, id_ag)
            if current and current['verifie']:
                return lien(f'/ag/{id_ag}')
            error = 'Code de vérification incorrect (5 essais maximum).'
        return await access_page(request, ag, statut=400, email_error=error)

    @app.post('/ag/{id_ag}/email/generate')
    async def generate_code(request: Request, id_ag: AgId):
        ag = await detail(request, id_ag)
        csrf(request, secret(request), await request.form())
        row = await challenge(request, id_ag)
        if not row or not row['verifie'] or int(row['expire_le']) <= int(time.time()):
            return await access_page(request, ag, statut=403,
                                     email_error='Vérifiez votre adresse universitaire avant de générer votre code.')
        db = bdd(request)
        for _ in range(5):
            code = f'{secrets.randbelow(10**12):012d}'
            code_id = secrets.randbelow(2**52 - 2**40) + 2**40
            try:
                operations = await db.batch([
                    db.prepare("""INSERT OR IGNORE INTO ag_mail_delivrances_v2(assemblee_id,email_hash)
                        SELECT assemblee_id,email_hash FROM ag_mail_verifications
                        WHERE token_hash=? AND assemblee_id=? AND verifie=1 AND expire_le>?""").bind(
                            row['token_hash'], id_ag, int(time.time())),
                    db.prepare("""INSERT INTO ag_codes(id,assemblee_id,empreinte_code,jeton_acces,expire_le)
                        SELECT ?,?,?,?,? WHERE changes()=1""").bind(
                            code_id, id_ag, core['_empreinte_code_ag'](core['_secret_codes'](request), id_ag, code),
                            secrets.token_hex(24), (int(time.time()) // 86400 + 90) * 86400),
                    db.prepare('DELETE FROM ag_mail_verifications WHERE token_hash=? AND changes()=1').bind(row['token_hash']),
                ])
            except Exception:

                continue
            if int(operations[0].meta.changes) != 1:
                return await access_page(request, ag, statut=409,
                    email_error='Un code a déjà été généré pour cette adresse et cette AG. Utilisez celui que vous avez conservé ; il ne peut pas être récupéré par mail.')
            break
        else:
            return await access_page(request, ag, statut=503, email_error='Génération temporairement indisponible. Réessayez.')

        response = rendu(request, 'ag_code_generated.html', ag=ag, code=code, participant=True)
        response.delete_cookie(cookie(id_ag), path='/', secure=True, httponly=True, samesite='lax')
        return response

    return access_page
