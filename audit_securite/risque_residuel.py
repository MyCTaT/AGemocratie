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
        legacy=hmac.new(f.env.AG_CODE_KEY.encode(),('ag-mail-address:'+email).encode(),hashlib.sha256).hexdigest()
        from security_controls import scoped_email_hash
        expected=scoped_email_hash(f.env.AG_CODE_KEY.encode(),1,legacy)
        self.assertEqual(db.execute('SELECT email_hash FROM ag_mail_verifications').fetchone()[0],expected)
        r=f.client.post('/ag/1/email/generate',data={'csrf_token':t});self.assertEqual(r.status_code,200)
        ids_after={r['id'] for r in db.execute('SELECT id FROM ag_codes')}
        new_ids=ids_after-issued_before;self.assertEqual(len(new_ids),1);code_id=new_ids.pop()
        self.assertEqual(db.execute('SELECT email_hash FROM ag_mail_delivrances_v2').fetchone()[0],expected)
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


if __name__ == "__main__": unittest.main()
