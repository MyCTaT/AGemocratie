"""Preuves bornées et locales ; aucun accès production ou envoi de mail."""
from pathlib import Path
import asyncio
import hashlib
import hmac
import importlib.util
import re
import sqlite3
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('audit_fixture',ROOT/'cloudflare/tests/test_acces_mail.py')
fixtures=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixtures)

class AuditTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.MailTests('test_csrf_et_generation_non_verifiee')
        self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.f=self.fixture
    def test_snapshots_reconstituent_mail_code_et_choix(self):
        f=self.f;email='victime@etu.sorbonne-universite.fr';t=f.verified(email=email)
        db=f.db.connect()
        issued_before={r['id'] for r in db.execute('SELECT id FROM ag_codes')}
        expected=hmac.new(f.env.AG_CODE_KEY.encode(),('ag-mail-address:'+email).encode(),hashlib.sha256).hexdigest()
        self.assertEqual(db.execute('SELECT email_hash FROM ag_mail_verifications').fetchone()[0],expected)
        r=f.client.post('/ag/1/email/generate',data={'csrf_token':t});self.assertEqual(r.status_code,200)
        ids_after={r['id'] for r in db.execute('SELECT id FROM ag_codes')}
        new_ids=ids_after-issued_before;self.assertEqual(len(new_ids),1);code_id=new_ids.pop()
        self.assertEqual(db.execute('SELECT email_hash FROM ag_mail_delivrances').fetchone()[0],expected)
        code=re.search(r'<strong>([0-9]{12})</strong>',r.text)[1]
        f.client.post('/ag/1/access',data={'csrf_token':t,'code':code})
        before_e={tuple(r) for r in db.execute('SELECT code_id,scrutin_id FROM ag_emargements')}
        before_b={tuple(r) for r in db.execute('SELECT bulletin_id,scrutin_id,choix_id FROM ag_bulletins')}
        r=f.client.post('/ag/1/vote/11',data={'csrf_token':t,'option_id':110});self.assertEqual(r.status_code,200)
        new_e={tuple(r) for r in db.execute('SELECT code_id,scrutin_id FROM ag_emargements')}-before_e
        new_b={tuple(r) for r in db.execute('SELECT bulletin_id,scrutin_id,choix_id FROM ag_bulletins')}-before_b
        self.assertEqual(new_e,{(code_id,11)})
        self.assertEqual(len(new_b),1);self.assertEqual(next(iter(new_b))[2],110)
        db.close()


    def test_meme_pseudonyme_sur_deux_ag(self):
        f=self.f;email='meme@etu.sorbonne-universite.fr'
        for ag in [1,2]:
            t=f.verified(email=email,ag=ag)
            self.assertEqual(f.client.post(f'/ag/{ag}/email/generate',data={'csrf_token':t}).status_code,200)
        db=f.db.connect();rows=db.execute('SELECT assemblee_id,email_hash FROM ag_mail_delivrances ORDER BY assemblee_id').fetchall()
        self.assertEqual(len(rows),2);self.assertEqual(rows[0]['email_hash'],rows[1]['email_hash']);db.close()
    def test_sixieme_adresse_bloquee_sur_ip_partagee(self):
        f=self.f
        for n in range(5):self.assertEqual(f.send(email=f'etudiant{n}@etu.sorbonne-universite.fr').status_code,200)
        self.assertEqual(f.send(email='autre@etu.sorbonne-universite.fr').status_code,429)
    def test_cloture_apres_un_vote_revele_le_resultat_individuel(self):
        f=self.f;t=f.verified()
        r=f.client.post('/ag/1/email/generate',data={'csrf_token':t});code=re.search(r'<strong>([0-9]{12})</strong>',r.text)[1]
        f.client.post('/ag/1/access',data={'csrf_token':t,'code':code})
        f.client.post('/ag/1/vote/11',data={'csrf_token':t,'option_id':110})
        account={'id':1,'identifiant':'admin','role':'principal','auth_version':1}
        f.client.cookies.set(f.worker.SESSION,f.worker._creer_session(f.env.APP_SECRET_KEY.encode(),account))
        r=f.client.get('/admin/ags/1');t=re.search(r'name="csrf_token" value="([^"]+)"',r.text)[1]
        r=f.client.post('/admin/polls/11/close',data={'csrf_token':t});self.assertEqual(r.status_code,200)
        self.assertIn('Oui',r.text)
        db=f.db.connect();self.assertEqual(db.execute('SELECT choix_id FROM ag_bulletins').fetchone()[0],110);db.close()
        r=f.client.get('/ag/1/vote/11');self.assertIn('1 voix',r.text)
    def test_acces_aux_otp_permet_de_se_faire_passer_pour_le_destinataire(self):
        f=self.f

        r=f.send(email='cible@etu.sorbonne-universite.fr');self.assertEqual(r.status_code,200)
        stolen_otp=f.sent[-1]['otp'];t=f.token()
        self.assertEqual(f.client.post('/ag/1/email/verify',data={'csrf_token':t,'otp':stolen_otp}).status_code,200)
        self.assertEqual(f.client.post('/ag/1/email/generate',data={'csrf_token':t}).status_code,200)
    def test_deux_adresses_de_la_meme_personne_peuvent_obtenir_deux_codes(self):
        f=self.f
        for address in ['personne@etu.sorbonne-universite.fr','personne@sorbonne-universite.fr']:
            t=f.verified(email=address)
            self.assertEqual(f.client.post('/ag/1/email/generate',data={'csrf_token':t}).status_code,200)
        db=f.db.connect();self.assertEqual(db.execute('SELECT count(*) FROM ag_codes').fetchone()[0],2);db.close()

    def test_starlette_ignore_limite_urlencoded_sur_cette_version(self):
        from starlette.requests import Request
        async def check():
            sent=False
            async def receive():
                nonlocal sent
                if sent:return {'type':'http.disconnect'}
                sent=True;return {'type':'http.request','body':b'a=1&b=2&c=3','more_body':False}
            r=Request({'type':'http','method':'POST','headers':[(b'content-type',b'application/x-www-form-urlencoded')]},receive)
            form=await r.form(max_fields=1,max_part_size=1)
            self.assertEqual(len(form),3)
        asyncio.run(check())
    def test_glob_76_octets_incompatible_limite_d1_50(self):
        text=(ROOT/'cloudflare/migrations/004_durcissement.sql').read_text(encoding='utf8')
        patterns=re.findall(r"GLOB '([^']+)'",text);self.assertTrue(all(len(p.encode())==76 for p in patterns))
        db=sqlite3.connect(':memory:');db.setlimit(sqlite3.SQLITE_LIMIT_LIKE_PATTERN_LENGTH,50)
        with self.assertRaises(sqlite3.OperationalError):db.execute('SELECT ? GLOB ?',('2026-11-10T12:00:00Z',patterns[0])).fetchone()
        db.close()

if __name__=='__main__':unittest.main(verbosity=2)
