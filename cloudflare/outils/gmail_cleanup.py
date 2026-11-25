"""Nettoyage des seules copies OTP identifiées par un Message-ID du site."""
import email.parser
import email.policy
import email.utils
import imaplib
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import threading
import time

SUBJECT='AGémocratie — vérification de votre adresse'
MARKER='otp-v1'
ID_PATTERN=r'<ag-verification-[0-9a-f]{48}@agemocratie\.fr>'
RECIPIENT=r"[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(etu\.sorbonne-universite\.fr|sorbonne-universite\.fr)"

def new_message_id():return '<ag-verification-'+secrets.token_hex(24)+'@agemocratie.fr>'

def _ok(result):
    status,data=result
    if status!='OK':raise RuntimeError('Opération Gmail de nettoyage indisponible')
    return data

def gmail_client(settings):
    if settings.get('SMTP_HOST','').lower()!='smtp.gmail.com':
        raise RuntimeError('Le nettoyage automatique est réservé au compte Gmail configuré')
    client=imaplib.IMAP4_SSL('imap.gmail.com',993,ssl_context=ssl.create_default_context(),timeout=15)
    try:
        client.login(settings['SMTP_USERNAME'],''.join(settings['SMTP_PASSWORD'].split()))
        caps={c.decode().upper() if isinstance(c,bytes) else c.upper() for c in client.capabilities}
        if not {'UIDPLUS','X-GM-EXT-1'}<=caps:raise RuntimeError('Gmail doit proposer UIDPLUS et ses identifiants de message')
        return client
    except Exception:
        try:client.logout()
        except Exception:pass
        raise

def folders(client):
    result={}
    for row in _ok(client.list()) or []:
        if not isinstance(row,bytes):continue
        match=re.match(rb'^\(([^)]*)\)\s+(?:"(?:[^"\\]|\\.)*"|NIL)\s+(.+)$',row)
        if not match:continue
        for flag in (b'\\Sent',b'\\Trash'):
            if flag.lower() in match[1].lower().split():result[flag]=match[2]
    if len(result)!=2:raise RuntimeError('Dossiers Gmail envoyés/corbeille introuvables')
    return result

def _find(client,folder,message_id):
    _ok(client.select(folder))
    rows=_ok(client.uid('search',None,'HEADER','Message-ID','"'+message_id+'"'))
    ids=rows[0].split() if rows and rows[0] else []
    if len(ids)>1:raise RuntimeError('Nettoyage refusé : identifiant de message ambigu')
    return ids[0] if ids else None

def _verify(client,uid,message_id,settings):
    rows=_ok(client.uid('fetch',uid,'(X-GM-MSGID BODY.PEEK[HEADER.FIELDS (MESSAGE-ID X-AGEMOCRATIE-VERIFICATION SUBJECT FROM TO)])'))
    item=next((r for r in rows if isinstance(r,tuple)),None)
    if item is None:raise RuntimeError('Message de nettoyage introuvable')
    message=email.parser.BytesParser(policy=email.policy.default).parsebytes(item[1])
    recipients=email.utils.getaddresses([str(message.get('To',''))])
    sender=email.utils.parseaddr(str(message.get('From','')))[1].lower()
    expected=email.utils.parseaddr(settings['SMTP_FROM'])[1].lower()
    gm_id=re.search(rb'X-GM-MSGID ([0-9]+)',item[0])
    if (str(message.get('Message-ID','')).strip()!=message_id
        or str(message.get('X-AGemocratie-Verification','')).strip()!=MARKER
        or str(message.get('Subject',''))!=SUBJECT
        or sender!=expected or len(recipients)!=1
        or not re.fullmatch(RECIPIENT,recipients[0][1].lower()) or gm_id is None):
        raise RuntimeError('Nettoyage refusé : le message ne correspond pas à un OTP du site')
    return gm_id[1]

def remove_copy(client,settings,message_id,known_folders=None):
    """N'utilise jamais EXPUNGE sans UID ni CLOSE : les autres mails sont préservés."""
    if not isinstance(message_id,str) or not re.fullmatch(ID_PATTERN,message_id):
        raise ValueError('Seuls les nouveaux messages marqués par le site sont autorisés')
    boxes=known_folders or folders(client)
    sent=_find(client,boxes[b'\\Sent'],message_id);gm_id=None
    if sent:
        gm_id=_verify(client,sent,message_id,settings)


        _ok(client.uid('copy',sent,boxes[b'\\Trash']))
    trash=_find(client,boxes[b'\\Trash'],message_id)
    if not trash:return False
    found_id=_verify(client,trash,message_id,settings)
    if gm_id is not None and found_id!=gm_id:
        raise RuntimeError('Nettoyage refusé : la copie Gmail ne désigne pas le même message')
    _ok(client.uid('store',trash,'+FLAGS.SILENT',r'(\Deleted)'))
    _ok(client.uid('expunge',trash))

    return _find(client,boxes[b'\\Trash'],message_id) is None and _find(client,boxes[b'\\Sent'],message_id) is None

class CleanupQueue:
    def __init__(self,settings,path):
        self.settings=settings;self.path=Path(path);self.lock=threading.Lock()
        self.stop_event=threading.Event();self.wake=threading.Event();self.thread=None
        try:self.pending=json.loads(self.path.read_text(encoding='utf-8')) if self.path.exists() else {}
        except ValueError:raise RuntimeError('File privée de nettoyage Gmail à vérifier') from None
        if not isinstance(self.pending,dict) or any(not re.fullmatch(ID_PATTERN,k) for k in self.pending):
            raise RuntimeError('File privée de nettoyage Gmail invalide')
    def _save(self):
        self.path.parent.mkdir(parents=True,exist_ok=True)
        temporary=self.path.with_name(self.path.name+'.tmp')
        if temporary.resolve().parent!=self.path.resolve().parent:raise RuntimeError('Chemin de nettoyage invalide')
        temporary.write_text(json.dumps(self.pending),encoding='utf-8')
        os.replace(temporary,self.path)
    def add(self,message_id):
        if not re.fullmatch(ID_PATTERN,message_id):raise ValueError('Message-ID invalide')
        with self.lock:
            if len(self.pending)>=1000:raise RuntimeError('File de nettoyage pleine')
            self.pending[message_id]=int(time.time());self._save()
        self.wake.set()
    def start(self):
        with gmail_client(self.settings) as client:folders(client)
        self.thread=threading.Thread(target=self._run,daemon=True);self.thread.start()
    def _run(self):
        while not self.stop_event.is_set():
            self.wake.wait(5);self.wake.clear()
            if self.stop_event.is_set():break
            with self.lock:batch=list(self.pending)[:20]
            if not batch:continue
            try:
                with gmail_client(self.settings) as client:
                    boxes=folders(client)
                    for message_id in batch:
                        if self.stop_event.is_set():break
                        if remove_copy(client,self.settings,message_id,boxes):
                            with self.lock:self.pending.pop(message_id,None);self._save()
            except Exception:

                print('Nettoyage Gmail en attente : nouvelle tentative automatique.',flush=True)
    def stop(self):
        self.stop_event.set();self.wake.set()
        if self.thread:self.thread.join(timeout=20)
