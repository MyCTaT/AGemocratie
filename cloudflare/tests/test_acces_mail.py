"""Tests du Worker réel, D1 simulé par SQLite, envoi externe simulé."""
import asyncio
import hashlib
import hmac
import importlib.util
import json
import re
import secrets
import sqlite3
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient

ROOT=Path(__file__).resolve().parents[1]

class Statement:
    def __init__(self, db, sql, args=()): self.db,self.sql,self.args=db,sql,args
    def bind(self,*args): return Statement(self.db,self.sql,args)
    async def first(self):
        db=self.db.connect()
        try:
            row=db.execute(self.sql,self.args).fetchone()
            return dict(row) if row else None
        finally: db.close()
    async def all(self):
        db=self.db.connect()
        try: return types.SimpleNamespace(results=[dict(x) for x in db.execute(self.sql,self.args)])
        finally: db.close()
    async def run(self):
        db=self.db.connect()
        try:
            before=db.total_changes
            db.execute(self.sql,self.args)
            return types.SimpleNamespace(meta=types.SimpleNamespace(changes=db.total_changes-before))
        finally: db.close()

class D1:
    def __init__(self,path): self.path=path
    def connect(self):
        db=sqlite3.connect(self.path,isolation_level=None,timeout=20)
        db.row_factory=sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        return db
    def prepare(self,sql): return Statement(self,sql)
    async def batch(self,statements):
        db=self.connect()
        try:
            db.execute('BEGIN IMMEDIATE'); results=[]
            for stmt in statements:
                before=db.total_changes
                db.execute(stmt.sql,stmt.args)
                results.append(types.SimpleNamespace(meta=types.SimpleNamespace(changes=db.total_changes-before)))
            db.execute('COMMIT');return results
        except Exception:
            if db.in_transaction:db.execute('ROLLBACK')
            raise
        finally:db.close()

class MailTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.db=D1(str(Path(self.tmp.name)/'test.sqlite3'))
        db=self.db.connect()
        db.executescript("""
        CREATE TABLE administrateurs(id INTEGER PRIMARY KEY,identifiant TEXT,mot_de_passe_hash TEXT,role TEXT,cree_le TEXT);
        CREATE TABLE scrutins(id INTEGER PRIMARY KEY,titre TEXT,description TEXT DEFAULT '',debut_utc TEXT,fin_utc TEXT,cree_par INTEGER,cree_le TEXT DEFAULT '2026-01-01');
        CREATE TABLE choix(id INTEGER PRIMARY KEY,scrutin_id INTEGER REFERENCES scrutins(id) ON DELETE CASCADE,intitule TEXT,position INTEGER);
        CREATE TABLE codes_vote(id INTEGER PRIMARY KEY,scrutin_id INTEGER);
        CREATE TABLE votes(id INTEGER PRIMARY KEY,scrutin_id INTEGER,choix_id INTEGER);
        """)
        for migration in sorted((ROOT/'migrations').glob('*.sql')):
            db.executescript(migration.read_text(encoding='utf8'))
        db.execute("INSERT INTO administrateurs(id,identifiant,mot_de_passe_hash,role) VALUES (1,'admin','unused','principal')")
        db.execute("INSERT INTO assemblees(id,titre,cree_par) VALUES (1,'AG une',1),(2,'AG deux',1)")
        for i,ag in [(11,1),(12,1),(21,2)]:
            db.execute("INSERT INTO scrutins(id,assemblee_id,titre,debut_utc,fin_utc,cree_par) VALUES (?,?,?,strftime('%Y-%m-%dT%H:%M:%SZ','now','-1 day'),strftime('%Y-%m-%dT%H:%M:%SZ','now','+1 day'),1)",(i,ag,f'Sujet {i}'))
            db.execute("INSERT INTO choix(id,scrutin_id,intitule,position) VALUES (?,?,'Oui',0),(?,?,'Non',1)",(i*10,i,i*10+1,i))
        db.close()
        self.env=types.SimpleNamespace(DB=self.db,APP_SECRET_KEY=secrets.token_urlsafe(48),AG_CODE_KEY=secrets.token_urlsafe(48),LEGACY_AG_CODE_KEY=secrets.token_urlsafe(48),AG_MAIL_URL='https://script.google.com/macros/s/test/exec',AG_MAIL_SECRET=secrets.token_urlsafe(48),ADMIN_TOTP_SECRETS='{"admin":"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"}')
        self.env.BREVO_API_KEY=secrets.token_urlsafe(48)
        self.env.AG_MAIL_PROVIDER='brevo'
        self.env.BREVO_SENDER_EMAIL='verification@example.org'
        self.env.BREVO_PRIVACY_CONFIRMED='1'
        workers=types.ModuleType('workers');workers.env=self.env
        workers.asgi=types.SimpleNamespace(entrypoint=lambda app:type('LocalEntrypoint',(),{}))
        async def no_network(*args,**kwargs):raise AssertionError('Unexpected network request')
        workers.fetch=no_network
        self.module_patch=patch.dict(sys.modules,{'workers':workers});self.module_patch.start();self.addCleanup(self.module_patch.stop)
        self.path_patch=patch.object(sys,'path',[str(ROOT),*sys.path]);self.path_patch.start();self.addCleanup(self.path_patch.stop)
        spec=importlib.util.spec_from_file_location('worker_mail_test',ROOT/'worker.py')
        self.worker=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.worker)
        self.mail=sys.modules['email_access'];self.sent=[]
        async def capture(core,request,**message):self.sent.append(message)
        self.sender_patch=patch.object(self.mail,'envoyer_verification',capture);self.sender_patch.start();self.addCleanup(self.sender_patch.stop)
        self.worker.app.middleware('http')(self.inject_env)
        self.client=TestClient(self.worker.app,base_url='https://testserver',headers={'origin':'https://testserver'})
        self.addCleanup(self.client.close)
    async def inject_env(self,request,next):
        request.scope['env']=self.env
        return await next(request)
    def token(self,client=None,ag=1):
        client=client or self.client;r=client.get(f'/ag/{ag}')
        self.assertEqual(r.status_code,200,r.text)
        return re.search(r'name="csrf_token" value="([^"]+)"',r.text)[1]
    def send(self,email='test@etu.sorbonne-universite.fr',ag=1,client=None):
        client=client or self.client;t=self.token(client,ag)
        return client.post(f'/ag/{ag}/email/send',data={'csrf_token':t,'email':email})
    def verified(self,email='test@etu.sorbonne-universite.fr',ag=1,client=None):
        client=client or self.client
        r=self.send(email,ag,client);self.assertEqual(r.status_code,200,r.text)
        t=self.token(client,ag);otp=self.sent[-1]['otp']
        r=client.post(f'/ag/{ag}/email/verify',data={'csrf_token':t,'otp':otp})
        self.assertEqual(r.status_code,200,r.text);return t
    def test_parcours_un_code_pour_plusieurs_sujets(self):
        t=self.verified();r=self.client.post('/ag/1/email/generate',data={'csrf_token':t})
        self.assertEqual(r.status_code,200,r.text)
        code=re.search(r'<strong>([0-9]{12})</strong>',r.text)[1]
        self.assertEqual(len(self.sent),1)
        self.assertEqual(set(self.sent[0]),{'to','otp'})
        self.assertNotIn(code,str(self.sent))
        r=self.client.post('/ag/1/access',data={'csrf_token':t,'code':code});self.assertEqual(r.status_code,200,r.text)
        for poll in [11,12]:
            for _ in range(2):
                r=self.client.post(f'/ag/1/vote/{poll}',data={'csrf_token':t,'option_id':poll*10})
                self.assertEqual(r.status_code,200,r.text)
        db=self.db.connect()
        self.assertEqual(db.execute('SELECT count(*) FROM ag_bulletins').fetchone()[0],2)
        self.assertEqual(db.execute('SELECT count(*) FROM ag_emargements').fetchone()[0],2)
        self.assertEqual(db.execute('SELECT count(*) FROM ag_codes').fetchone()[0],1)
        self.assertEqual(db.execute('SELECT count(*) FROM ag_mail_verifications').fetchone()[0],0)
        db.close()
        t=self.token(ag=2)
        self.assertEqual(self.client.post('/ag/2/access',data={'csrf_token':t,'code':code}).status_code,401)
    def test_email_uniquement_et_erreurs_html(self):
        for email in ['bad@gmail.com','a@fake.sorbonne-universite.fr','a@sorbonne-universite.fr.evil','a@@sorbonne-universite.fr']:
            r=self.send(email);self.assertEqual(r.status_code,400)
            self.assertIn('text/html',r.headers['content-type']);self.assertIn('role="alert"',r.text)
        self.assertEqual(self.sent,[])
        self.assertEqual(self.send('Prof@SORBONNE-UNIVERSITE.FR').status_code,200)
        self.assertEqual(self.sent[-1]['to'],'prof@sorbonne-universite.fr')
    def test_csrf_et_generation_non_verifiee(self):
        self.token()
        r=self.client.post('/ag/1/email/send',data={'email':'test@etu.sorbonne-universite.fr','csrf_token':'bad'})
        self.assertEqual(r.status_code,403);self.assertEqual(self.sent,[])
        t=self.token();self.assertEqual(self.client.post('/ag/1/email/generate',data={'csrf_token':t}).status_code,403)
    def test_expiration_et_cinq_essais(self):
        self.send();otp=self.sent[-1]['otp'];t=self.token()
        for _ in range(5):self.assertEqual(self.client.post('/ag/1/email/verify',data={'csrf_token':t,'otp':'bad'}).status_code,400)
        self.assertEqual(self.client.post('/ag/1/email/verify',data={'csrf_token':t,'otp':otp}).status_code,400)
        self.send();otp=self.sent[-1]['otp']
        db=self.db.connect();db.execute('UPDATE ag_mail_verifications SET expire_le=0');db.close()
        self.assertEqual(self.client.post('/ag/1/email/verify',data={'csrf_token':t,'otp':otp}).status_code,400)
    def test_un_seul_code_par_adresse_et_par_ag(self):
        t=self.verified();self.assertEqual(self.client.post('/ag/1/email/generate',data={'csrf_token':t}).status_code,200)
        t=self.verified();self.assertEqual(self.client.post('/ag/1/email/generate',data={'csrf_token':t}).status_code,409)
        t=self.verified(ag=2);self.assertEqual(self.client.post('/ag/2/email/generate',data={'csrf_token':t}).status_code,200)
    def test_limite_envois(self):
        for _ in range(5):self.assertEqual(self.send().status_code,200)
        self.assertEqual(self.send().status_code,429);self.assertEqual(len(self.sent),5)
    def test_panne_mail_et_code_affiche(self):
        async def failed(*args,**kwargs):raise OSError('relay down')
        with patch.object(self.mail,'envoyer_verification',failed):self.assertEqual(self.send().status_code,503)
        db=self.db.connect();self.assertEqual(db.execute('SELECT count(*) FROM ag_mail_verifications').fetchone()[0],0);db.close()
        t=self.verified()
        with patch.object(self.mail,'envoyer_verification',failed):r=self.client.post('/ag/1/email/generate',data={'csrf_token':t})
        self.assertEqual(r.status_code,200);self.assertIn('Copiez votre code',r.text)
        code=re.search(r'<strong>([0-9]{12})</strong>',r.text)[1]
        self.assertEqual(self.client.post('/ag/1/access',data={'csrf_token':t,'code':code}).status_code,200)
    def test_batch_unique_en_concurrence_et_migration_rejouable(self):
        t=self.verified();cookie=self.client.cookies.get('__Host-ag-mail-1')
        other=TestClient(self.worker.app,base_url='https://testserver',headers={'origin':'https://testserver'})
        self.addCleanup(other.close)
        for name,value in self.client.cookies.items():other.cookies.set(name,value)
        from concurrent.futures import ThreadPoolExecutor
        def generate(client):return client.post('/ag/1/email/generate',data={'csrf_token':t}).status_code
        with ThreadPoolExecutor(2) as pool:statuses=list(pool.map(generate,[self.client,other]))
        self.assertEqual(statuses.count(200),1,statuses)
        db=self.db.connect()
        self.assertEqual(db.execute('SELECT count(*) FROM ag_codes').fetchone()[0],1)
        before=db.execute('SELECT count(*) FROM scrutins').fetchone()[0]
        db.executescript((ROOT/'migrations/005_acces_mail.sql').read_text(encoding='utf8'))
        self.assertEqual(db.execute('SELECT count(*) FROM scrutins').fetchone()[0],before);db.close()
    def test_anciens_codes_fonctionnent_et_admin_sans_nouveau_bloc(self):
        db=self.db.connect();code='123456789012'
        db.execute('INSERT INTO ag_codes(id,assemblee_id,empreinte_code,jeton_acces,expire_le) VALUES (1,1,?,?,?)',
                   (self.worker._empreinte_code_ag(self.env.AG_CODE_KEY.encode(),1,code),'old-token',int(time.time())+3600));db.close()
        t=self.token();self.assertEqual(self.client.post('/ag/1/access',data={'csrf_token':t,'code':code}).status_code,200)
        compte={'id':1,'identifiant':'admin','role':'principal','auth_version':1}
        self.client.cookies.set(self.worker.SESSION,self.worker._creer_session(self.env.APP_SECRET_KEY.encode(),compte))
        r=self.client.get('/admin/ags/1');self.assertEqual(r.status_code,200,r.text)
        self.assertNotIn('Codes enregistrés',r.text);self.assertNotIn('Révoquer',r.text)
        t=re.search(r'name="csrf_token" value="([^"]+)"',r.text)[1]
        self.assertEqual(self.client.post('/admin/ags/1/codes',data={'csrf_token':t}).status_code,403)

        self.assertEqual(self.client.post('/admin/polls/11/close',data={'csrf_token':t}).status_code,200)
        self.assertEqual(self.client.post('/admin/ags/1/delete',data={'csrf_token':t,'confirmation_titre':'AG une'}).status_code,200)
    def test_brevo_sends_only_otp_without_gmail_copy(self):
        from starlette.requests import Request
        request=Request({'type':'http','env':self.env})
        captured=[]
        async def fake_fetch(url,**options):
            captured.append((url,options))
            class Reply:
                status=201
            return Reply()
        original=self.sender_patch.temp_original
        with patch.object(self.mail,'fetch',fake_fetch):
            asyncio.run(original(vars(self.worker),request,to='test@etu.sorbonne-universite.fr',otp='012345'))
        self.assertEqual(captured[0][0],'https://api.brevo.com/v3/smtp/email')
        self.assertEqual(captured[0][1]['headers']['api-key'],self.env.BREVO_API_KEY)
        self.assertEqual(captured[0][1]['redirect'],'error')
        body=json.loads(captured[0][1]['body'])
        self.assertEqual(set(body),{'sender','to','subject','textContent'})
        self.assertEqual(body['to'],[{'email':'test@etu.sorbonne-universite.fr'}])
        self.assertIn('012345',body['textContent'])
        self.assertNotIn(self.env.BREVO_API_KEY,captured[0][1]['body'])
        with patch.object(self.mail,'fetch',fake_fetch):
            with self.assertRaises(ValueError):
                asyncio.run(original(vars(self.worker),request,to='test@etu.sorbonne-universite.fr',otp='123456789012'))
        self.assertEqual(len(captured),1)
    def test_brevo_failure_never_falls_back_to_gmail(self):
        from starlette.requests import Request
        request=Request({'type':'http','env':self.env});calls=[]
        async def failure(url,**options):
            calls.append(url)
            return types.SimpleNamespace(status=429)
        with patch.object(self.mail,'fetch',failure):
            with self.assertRaises(RuntimeError):
                asyncio.run(self.sender_patch.temp_original(vars(self.worker),request,to='test@etu.sorbonne-universite.fr',otp='012345'))
        self.assertEqual(calls,['https://api.brevo.com/v3/smtp/email'])
    def test_brevo_requires_privacy_acknowledgement(self):
        from starlette.requests import Request
        request=Request({'type':'http','env':self.env});self.env.BREVO_PRIVACY_CONFIRMED='0'
        async def forbidden(*args,**kwargs):raise AssertionError('No request before configuration')
        with patch.object(self.mail,'fetch',forbidden):
            with self.assertRaises(RuntimeError):
                asyncio.run(self.sender_patch.temp_original(vars(self.worker),request,to='test@etu.sorbonne-universite.fr',otp='012345'))
    def test_gmail_provider_is_signed_and_never_calls_brevo(self):
        from starlette.requests import Request
        self.env.AG_MAIL_PROVIDER='gmail';request=Request({'type':'http','env':self.env});calls=[]
        async def capture(url,**options):
            calls.append((url,options))
            class Reply:
                status=200
                async def json(self):return {'ok':True}
            return Reply()
        with patch.object(self.mail,'fetch',capture):
            asyncio.run(self.sender_patch.temp_original(vars(self.worker),request,to='test@etu.sorbonne-universite.fr',otp='012345'))
        self.assertEqual(calls[0][0],self.env.AG_MAIL_URL)
        envelope=json.loads(calls[0][1]['body'])
        expected=hmac.new(self.env.AG_MAIL_SECRET.encode(),envelope['payload'].encode(),hashlib.sha256).hexdigest()
        self.assertEqual(envelope['signature'],expected)
        self.assertEqual(set(json.loads(envelope['payload'])),{'to','otp','timestamp','id'})

    def test_pas_de_lien_enregistre_entre_mail_code_et_bulletin(self):
        email='private@etu.sorbonne-universite.fr'
        t=self.verified(email=email)
        db=self.db.connect()
        columns={row['name'] for row in db.execute('PRAGMA table_info(ag_mail_verifications)')}
        self.assertNotIn('email',columns)
        self.assertNotIn(email,'\n'.join(db.iterdump()))
        db.close()
        r=self.client.post('/ag/1/email/generate',data={'csrf_token':t})
        code=re.search(r'<strong>([0-9]{12})</strong>',r.text)[1]
        self.assertEqual(len(self.sent),1)
        self.assertNotIn(code,str(self.sent))
        self.assertNotIn(email,r.text)
        db=self.db.connect()
        self.assertEqual({row['name'] for row in db.execute('PRAGMA table_info(ag_mail_delivrances_v2)')},{'assemblee_id','email_hash'})
        self.assertEqual({row['name'] for row in db.execute('PRAGMA table_info(ag_bulletins)')},{'bulletin_id','scrutin_id','choix_id'})
        self.assertNotIn(email,'\n'.join(db.iterdump()))
        self.assertEqual(db.execute('SELECT expire_le FROM ag_codes').fetchone()[0]%86400,0)
        db.close()
    def test_hash_natif_respecte_plafond_cloudflare(self):
        calls=[]
        async def import_key(*args): return object()
        async def derive_bits(options,key,size):
            calls.append(options['iterations'])
            if options['iterations']>100_000:
                raise RuntimeError('Cloudflare WebCrypto PBKDF2 iteration limit')
            return b'\x00'*32
        js=types.ModuleType('js')
        js.crypto=types.SimpleNamespace(subtle=types.SimpleNamespace(importKey=import_key,deriveBits=derive_bits))
        js.TextEncoder=types.SimpleNamespace(new=lambda:types.SimpleNamespace(encode=lambda value:value.encode()))
        js.Uint8Array=types.SimpleNamespace(new=lambda value:types.SimpleNamespace(to_py=lambda:value))
        js.Object=types.SimpleNamespace(fromEntries=None)
        ffi=types.ModuleType('pyodide.ffi');ffi.to_js=lambda value,**kwargs:value
        with patch.dict(sys.modules,{'js':js,'pyodide.ffi':ffi}):
            result=asyncio.run(self.worker._hash_mdp('test-only-password'))
        self.assertEqual(calls,[100_000])
        self.assertTrue(result.startswith('pbkdf2_sha256$100000$'))

    def test_code_historique_avec_secret_application(self):
        del self.env.LEGACY_AG_CODE_KEY
        code='1234567890'
        fingerprint=self.worker._empreinte_code_legacy(self.env.APP_SECRET_KEY.encode(),1,code)
        db=self.db.connect()
        db.execute("INSERT INTO ag_codes(assemblee_id,empreinte_code,jeton_acces,expire_le) VALUES (1,?,'ancien-code',?)",(fingerprint,int(time.time())+86400))
        db.close()
        response=self.client.post('/ag/1/access',data={'csrf_token':self.token(),'code':code},follow_redirects=False)
        self.assertEqual(response.status_code,303,response.text)
        self.assertIn('set-cookie',response.headers)

    def test_migration_retire_adresse_et_preserve_verifications(self):
        db=self.db.connect()
        db.execute('DROP TABLE ag_mail_verifications')
        db.executescript((ROOT/'migrations/005_acces_mail.sql').read_text(encoding='utf8'))
        db.execute("INSERT INTO ag_mail_verifications(token_hash,assemblee_id,email_hash,email,otp_hash,expire_le,verifie) VALUES ('token',1,'hash','private@etu.sorbonne-universite.fr','otp',?,1)",(int(time.time())+600,))
        for _ in range(2):db.executescript((ROOT/'migrations/006_confidentialite_mail.sql').read_text(encoding='utf8'))
        self.assertNotIn('email',{row['name'] for row in db.execute('PRAGMA table_info(ag_mail_verifications)')})
        self.assertEqual(db.execute("SELECT verifie FROM ag_mail_verifications WHERE token_hash='token'").fetchone()[0],1)
        self.assertEqual(db.execute('SELECT count(*) FROM scrutins').fetchone()[0],3)
        db.close()

if __name__=='__main__':unittest.main()
