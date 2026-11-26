import asyncio
import base64
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import re
import secrets
import sqlite3
import struct
import sys
import time
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
spec=importlib.util.spec_from_file_location('security_fixture',ROOT/'tests/test_acces_mail.py')
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
from security_controls import RequestLimitsMiddleware,protect_results,scoped_email_hash,maintenance,totp_step,consume_attempts

def otp(seed,step=None):
    step=int(time.time())//30 if step is None else step
    key=base64.b32decode(seed)
    value=hmac.new(key,struct.pack('>Q',step),hashlib.sha1).digest();offset=value[-1]&15
    return f"{(int.from_bytes(value[offset:offset+4],'big')&0x7fffffff)%1000000:06d}"

class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.MailTests('test_csrf_et_generation_non_verifiee');self.f.setUp();self.addCleanup(self.f.doCleanups)
    def test_body_rejected_before_csrf(self):
        r=self.f.client.post('/ag/1/email/send',content=b'x'*65537,headers={'content-type':'application/x-www-form-urlencoded'})
        self.assertEqual(r.status_code,413);self.assertEqual(self.f.sent,[])
    def test_streamed_body_counted_even_with_false_length(self):
        async def test():
            called=[];responses=[];chunks=iter([{'type':'http.request','body':b'x'*60000,'more_body':True},{'type':'http.request','body':b'x'*6000,'more_body':False}])
            async def receive():return next(chunks)
            async def send(message):responses.append(message)
            async def app(*args):called.append(True)
            await RequestLimitsMiddleware(app)({'type':'http','method':'POST','headers':[(b'host',b'testserver'),(b'content-length',b'1')]},receive,send)
            self.assertEqual(called,[]);self.assertEqual(responses[0]['status'],413)
        asyncio.run(test())
    def test_bad_host_rejected(self):
        self.assertEqual(self.f.client.get('/',headers={'host':'evil/anything'}).status_code,400)
    def test_pseudonyms_are_separate_per_ag_and_rate_purpose(self):
        f=self.f;address='person@etu.sorbonne-universite.fr'
        for ag in [1,2]:
            t=f.verified(email=address,ag=ag)
            self.assertEqual(f.client.post(f'/ag/{ag}/email/generate',data={'csrf_token':t}).status_code,200)
        db=f.db.connect();rows=db.execute('SELECT email_hash FROM ag_mail_delivrances_v2').fetchall()
        self.assertEqual(len({r[0] for r in rows}),2)
        rates={r[0] for r in db.execute('SELECT empreinte FROM limites_connexion')}
        self.assertFalse(rates & {r[0] for r in rows});db.close()
    def test_legacy_right_preserved_without_global_hash(self):
        f=self.f;address='legacy@etu.sorbonne-universite.fr'
        old=hmac.new(f.env.AG_CODE_KEY.encode(),('ag-mail-address:'+address).encode(),hashlib.sha256).hexdigest()
        db=f.db.connect();db.execute('INSERT INTO ag_mail_delivrances(assemblee_id,email_hash) VALUES (1,?)',(old,));db.close()
        t=f.verified(email=address)
        self.assertEqual(f.client.post('/ag/1/email/generate',data={'csrf_token':t}).status_code,409)
        db=f.db.connect();self.assertEqual(db.execute('SELECT count(*) FROM ag_mail_delivrances').fetchone()[0],0)
        self.assertEqual(db.execute('SELECT email_hash FROM ag_mail_delivrances_v2').fetchone()[0],scoped_email_hash(f.env.AG_CODE_KEY.encode(),1,old));db.close()
    def test_six_distinct_people_behind_nat(self):
        for n in range(6):self.assertEqual(self.f.send(email=f'p{n}@etu.sorbonne-universite.fr').status_code,200)
    def test_sixth_request_for_same_email_still_blocked(self):
        for n in range(5):self.assertEqual(self.f.send().status_code,200)
        self.assertEqual(self.f.send().status_code,429)
    def test_rate_limit_atomic(self):
        from concurrent.futures import ThreadPoolExecutor
        def attempt(_):return asyncio.run(consume_attempts(self.f.db,[('test-atomic',5)]))
        with ThreadPoolExecutor(10) as pool:results=list(pool.map(attempt,range(20)))
        self.assertEqual(sum(results),5)
    def test_maintenance_purges_and_migrates_without_votes(self):
        db=self.f.db.connect()
        db.execute("INSERT INTO ag_mail_verifications(token_hash,assemblee_id,email_hash,otp_hash,expire_le) VALUES ('old',1,'hash','otp',0)")
        db.execute("INSERT INTO limites_connexion(empreinte,debut_fenetre,echecs) VALUES ('old',0,1)")
        db.execute("INSERT INTO ag_mail_delivrances(assemblee_id,email_hash) VALUES (1,'legacy'),(2,'legacy')");db.close()
        asyncio.run(maintenance(self.f.db,self.f.env.AG_CODE_KEY.encode()))
        db=self.f.db.connect();self.assertEqual(db.execute('SELECT count(*) FROM ag_mail_verifications').fetchone()[0],0)
        self.assertEqual(db.execute('SELECT count(*) FROM limites_connexion').fetchone()[0],0)
        rows=db.execute('SELECT email_hash FROM ag_mail_delivrances_v2').fetchall();self.assertEqual(len(rows),2);self.assertNotEqual(rows[0][0],rows[1][0]);db.close()
    def test_dates_under_real_d1_pattern_limit(self):
        db=self.f.db.connect();db.setlimit(sqlite3.SQLITE_LIMIT_LIKE_PATTERN_LENGTH,50)
        db.execute("INSERT INTO scrutins(id,assemblee_id,titre,debut_utc,fin_utc,cree_par) VALUES (50,1,'Valide','2026-11-10T12:00:00Z','2026-11-10T13:00:00Z',1)")
        for invalid in [None,'2026-02-30T12:00:00Z','2026-11-10T24:00:00Z','2026-13-10T12:00:00Z','2026-11-10 12:00:00','garbage']:
            with self.assertRaises(sqlite3.IntegrityError):db.execute('UPDATE scrutins SET debut_utc=? WHERE id=50',(invalid,))
        db.executescript((ROOT/'migrations/007_dates_compatibles_d1.sql').read_text(encoding='utf8'));db.executescript((ROOT/'migrations/008_securite_acces.sql').read_text(encoding='utf8'));db.close()
    def test_small_unanimous_and_small_cells_hidden(self):
        for counts in ([1,0],[4,0],[6,0],[4,1],[5,2],[0,0]):self.assertIsNone(protect_results([{'total':n} for n in counts]))
        self.assertIsNotNone(protect_results([{'total':3},{'total':3}]))
    def test_early_closure_never_advances_results(self):
        f=self.f;t=f.verified();r=f.client.post('/ag/1/email/generate',data={'csrf_token':t});code=re.search(r'<strong>([0-9]{12})</strong>',r.text)[1]
        f.client.post('/ag/1/access',data={'csrf_token':t,'code':code})
        f.client.post('/ag/1/vote/11',data={'csrf_token':t,'option_id':110})
        db=f.db.connect();db.execute('UPDATE scrutins SET ferme_manuellement=1 WHERE id=11')
        for n,choice in enumerate([110,110,111,111,111]):db.execute('INSERT INTO ag_bulletins(bulletin_id,scrutin_id,choix_id) VALUES (?,11,?)',(str(n),choice))
        db.close()
        r=f.client.get('/ag/1/vote/11');self.assertNotIn('3 voix',r.text);self.assertIn('Les résultats ne sont pas publiés',r.text)
        db=f.db.connect();db.execute("UPDATE scrutins SET fin_utc=strftime('%Y-%m-%dT%H:%M:%SZ','now','-1 second') WHERE id=11");db.close()
        self.assertIn('3 voix',f.client.get('/ag/1/vote/11').text)
    def test_totp_rfc_vector(self):
        seed='GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
        self.assertEqual(totp_step(seed,'287082',59),1)
        self.assertIsNone(totp_step(seed,'287082',121))
        self.assertIsNone(totp_step(seed,'123456789012',59))
    def second_admin(self):
        f=self.f;db=f.db.connect()
        db.execute("INSERT INTO administrateurs(id,identifiant,mot_de_passe_hash,role) VALUES (2,'second','unused','admin')")
        row=dict(db.execute('SELECT * FROM administrateurs WHERE id=2').fetchone());db.close()
        f.client.cookies.set(f.worker.SESSION,f.worker._creer_session(f.env.APP_SECRET_KEY.encode(),row))
        return f

    def test_other_admin_can_read_ag_and_subject(self):
        f=self.second_admin()
        r=f.client.get('/admin/ags/1');self.assertEqual(r.status_code,200)
        self.assertIn('/admin/ags/1/delete',r.text)
        self.assertEqual(f.client.get('/admin/polls/11').status_code,200)
        self.assertEqual(f.client.get('/admin/polls/new?ag_id=1').status_code,200)

    def test_other_admin_can_close_subject_and_is_recorded(self):
        f=self.second_admin();r=f.client.get('/admin/polls/11')
        t=re.search(r'name="csrf_token" value="([^"]+)"',r.text)[1]
        r=f.client.post('/admin/polls/11/close',data={'csrf_token':t},follow_redirects=False)
        self.assertEqual(r.status_code,303,r.text)
        db=f.db.connect()
        self.assertEqual(tuple(db.execute('SELECT ferme_manuellement,ferme_par FROM scrutins WHERE id=11').fetchone()),(1,2))
        self.assertEqual(db.execute("SELECT admin_id FROM journal_admin WHERE action='close_poll'").fetchone()[0],2)
        db.close()

    def test_other_admin_can_delete_ag_but_not_manage_accounts(self):
        f=self.second_admin();r=f.client.get('/admin/ags/1')
        t=re.search(r'name="csrf_token" value="([^"]+)"',r.text)[1]
        self.assertEqual(f.client.get('/admin/users').status_code,403)
        r=f.client.post('/admin/ags/1/delete',data={'csrf_token':t,'confirmation_titre':'AG une'},follow_redirects=False)
        self.assertEqual(r.status_code,303,r.text)
        db=f.db.connect()
        self.assertEqual(db.execute('SELECT count(*) FROM assemblees WHERE id=1').fetchone()[0],0)
        self.assertEqual(db.execute('SELECT count(*) FROM assemblees WHERE id=2').fetchone()[0],1)
        db.close()

    def test_login_with_password_only_and_logout(self):
        f=self.f
        async def check(password,stored):return password=='correct'
        with patch.object(f.worker,'_verifie_mdp',check),patch.object(f.worker,'_iterations_mdp',lambda value:600000):
            r=f.client.get('/admin/login');t=re.search(r'name="csrf_token" value="([^"]+)"',r.text)[1]
            data={'csrf_token':t,'username':'admin','password':'correct'}
            self.assertNotIn('name="otp"',r.text)
            r=f.client.post('/admin/login',data=data);self.assertEqual(r.status_code,200);self.assertNotIn('/login',str(r.url))
            t=re.search(r'name="csrf_token" value="([^"]+)"',r.text)[1]
            f.client.post('/admin/logout',data={'csrf_token':t})
            r=f.client.get('/admin/login');t=re.search(r'name="csrf_token" value="([^"]+)"',r.text)[1]
            self.assertEqual(f.client.post('/admin/login',data={'csrf_token':t,'username':'admin','password':'wrong'}).status_code,401)
    def test_login_does_not_need_mfa_configuration(self):
        f=self.f;f.env.ADMIN_TOTP_SECRETS='{}'
        async def check(*args):return True
        with patch.object(f.worker,'_verifie_mdp',check),patch.object(f.worker,'_iterations_mdp',lambda value:600000):
            r=f.client.get('/admin/login');t=re.search(r'name="csrf_token" value="([^"]+)"',r.text)[1]
            self.assertEqual(f.client.post('/admin/login',data={'csrf_token':t,'username':'admin','password':'correct'}).status_code,200)
    def test_scheduled_handler_runs_maintenance(self):
        db=self.f.db.connect()
        db.execute("INSERT INTO limites_connexion(empreinte,debut_fenetre,echecs) VALUES ('stale',0,1)")
        db.close()
        asyncio.run(self.f.worker.Default().scheduled(None,self.f.env,None))
        db=self.f.db.connect();self.assertEqual(db.execute("SELECT count(*) FROM limites_connexion WHERE empreinte='stale'").fetchone()[0],0);db.close()
    def test_rgpd_document_is_linked_and_matches_source(self):
        with patch.object(self.f.worker,'_bdd',side_effect=AssertionError('no database')):
            with patch.object(self.f.worker,'_secret',side_effect=AssertionError('no secret')):
                for path in ['/confidentialite','/document-prive.md','/static/document-prive.md']:
                    response=self.f.client.get(path)
                    self.assertEqual(response.status_code,404,path)
                    self.assertNotIn('set-cookie',response.headers)
                    self.assertNotIn('Achille Thibon-Soula',response.text)
        page=self.f.client.get('/ag/1')
        self.assertIn('href="/documents/rgpd.txt"',page.text)
        self.assertNotIn('anonymat cryptographique',page.text)
        source=ROOT.parent/'POLITIQUE_CONFIDENTIALITE.md'
        public=ROOT/'public/documents/rgpd.txt'
        self.assertEqual(public.read_bytes(),source.read_bytes())
        self.assertIn('Achille Thibon-Soula',public.read_text(encoding='utf-8'))
    def test_internal_error_does_not_log_sensitive_exception(self):
        with patch.object(self.f.worker,'_bdd',side_effect=RuntimeError('private-email@example.test private-code')):
            with self.assertLogs('agemocratie.security',level='ERROR') as captured:
                response=self.f.client.get('/health?email=private-email@example.test')
        self.assertEqual(response.status_code,500)
        self.assertEqual(captured.output,['ERROR:agemocratie.security:worker_error'])
    def test_retention_boundary_and_complete_ag_cleanup(self):
        f=self.f;t=f.verified()
        response=f.client.post('/ag/1/email/generate',data={'csrf_token':t})
        code=re.search(r'<strong>([0-9]{12})</strong>',response.text)[1]
        f.client.post('/ag/1/access',data={'csrf_token':t,'code':code})
        f.client.post('/ag/1/vote/11',data={'csrf_token':t,'option_id':110})
        db=f.db.connect()
        now=int(time.time());cutoff=now-30*86400
        db.execute("UPDATE scrutins SET debut_utc=strftime('%Y-%m-%dT%H:%M:%SZ',?,'unixepoch'),fin_utc=strftime('%Y-%m-%dT%H:%M:%SZ',?,'unixepoch') WHERE assemblee_id=1",(cutoff-86400,cutoff+1))
        db.execute("INSERT INTO votes(id,scrutin_id,choix_id) VALUES (999,11,110)")
        db.execute("INSERT INTO codes_vote(id,scrutin_id) VALUES (999,11)")
        db.execute("INSERT INTO journal_admin(action,cible_type,cible_id) VALUES ('test','ag','1'),('test','poll','11')")
        db.close()
        with patch('security_controls.time.time',return_value=now):asyncio.run(maintenance(f.db,f.env.AG_CODE_KEY.encode()))
        db=f.db.connect();self.assertIsNotNone(db.execute('SELECT 1 FROM assemblees WHERE id=1').fetchone());db.close()
        with patch('security_controls.time.time',return_value=now+1):asyncio.run(maintenance(f.db,f.env.AG_CODE_KEY.encode()))
        db=f.db.connect()
        self.assertIsNone(db.execute('SELECT 1 FROM assemblees WHERE id=1').fetchone())
        self.assertIsNotNone(db.execute('SELECT 1 FROM assemblees WHERE id=2').fetchone())
        for table in ['ag_codes','ag_emargements','ag_bulletins','ag_mail_delivrances_v2','votes','codes_vote','journal_admin']:
            self.assertEqual(db.execute(f'SELECT count(*) FROM {table}').fetchone()[0],0,table)
        self.assertEqual(db.execute('SELECT count(*) FROM choix WHERE scrutin_id IN (11,12)').fetchone()[0],0)
        db.close()
    def test_retention_uses_latest_subject_and_preserves_admin(self):
        db=self.f.db.connect();now=int(time.time());cutoff=now-30*86400
        db.execute("UPDATE scrutins SET debut_utc=strftime('%Y-%m-%dT%H:%M:%SZ',?,'unixepoch'),fin_utc=strftime('%Y-%m-%dT%H:%M:%SZ',?,'unixepoch') WHERE id=11",(cutoff-86400,cutoff-1))
        db.execute("INSERT INTO assemblees(id,titre,cree_le) VALUES (3,'Vide',strftime('%Y-%m-%dT%H:%M:%SZ',?,'unixepoch'))",(cutoff,))
        db.execute("INSERT INTO journal_admin(action,cible_type,le) VALUES ('old','admin',strftime('%Y-%m-%dT%H:%M:%SZ',?,'unixepoch'))",(cutoff,))
        db.close()
        with patch('security_controls.time.time',return_value=now):asyncio.run(maintenance(self.f.db,self.f.env.AG_CODE_KEY.encode()))
        db=self.f.db.connect();self.assertIsNotNone(db.execute('SELECT 1 FROM assemblees WHERE id=1').fetchone());self.assertIsNone(db.execute('SELECT 1 FROM assemblees WHERE id=3').fetchone());self.assertEqual(db.execute('SELECT count(*) FROM administrateurs').fetchone()[0],1);self.assertEqual(db.execute('SELECT count(*) FROM journal_admin').fetchone()[0],0);db.close()
    def test_delete_ag_with_cascading_mail_rights(self):
        f=self.f;t=f.verified()
        self.assertEqual(f.client.post('/ag/1/email/generate',data={'csrf_token':t}).status_code,200)
        account={'id':1,'identifiant':'admin','role':'principal','auth_version':1}
        f.client.cookies.set(f.worker.SESSION,f.worker._creer_session(f.env.APP_SECRET_KEY.encode(),account))
        r=f.client.get('/admin/ags/1');t=re.search(r'name="csrf_token" value="([^"]+)"',r.text)[1]
        r=f.client.post('/admin/ags/1/delete',data={'csrf_token':t,'confirmation_titre':'AG une'})
        self.assertEqual(r.status_code,200,r.text)
        db=f.db.connect();self.assertIsNone(db.execute('SELECT 1 FROM assemblees WHERE id=1').fetchone());self.assertEqual(db.execute('SELECT count(*) FROM ag_mail_delivrances_v2').fetchone()[0],0);db.close()
    def test_signed_admin_session_without_mfa_marker_is_accepted(self):
        import base64
        f=self.f
        payload={'i':1,'v':1,'e':int(time.time())+3600,'n':'legacy'}
        encoded=base64.urlsafe_b64encode(json.dumps(payload,separators=(',',':')).encode()).rstrip(b'=').decode()
        value=encoded+'.'+hmac.new(f.env.APP_SECRET_KEY.encode(),b'session:'+encoded.encode(),hashlib.sha256).hexdigest()
        f.client.cookies.set(f.worker.SESSION,value)
        r=f.client.get('/admin')
        self.assertEqual(r.status_code,200)
        self.assertNotIn('/admin/login',str(r.url))
    def test_upgraded_form_parser_enforces_fields(self):
        from starlette.requests import Request
        async def check():
            async def receive():return {'type':'http.request','body':b'a=1&b=2&c=3','more_body':False}
            request=Request({'type':'http','method':'POST','headers':[(b'content-type',b'application/x-www-form-urlencoded')]},receive)
            from starlette.formparsers import MultiPartException
            with self.assertRaises(MultiPartException):await request.form(max_fields=1)
        asyncio.run(check())

if __name__=='__main__':unittest.main()
