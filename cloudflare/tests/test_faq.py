import asyncio
import re
import time
import unittest
import test_acces_mail as fixture


class FaqTests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.MailTests('test_csrf_et_generation_non_verifiee')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)

    def token(self,path='/faq'):
        r=self.f.client.get(path)
        self.assertEqual(r.status_code,200,r.text)
        return re.search(r'name="csrf_token" value="([^"]+)"',r.text)[1]

    def admin(self):
        f=self.f
        db=f.db.connect()
        row=dict(db.execute('SELECT * FROM administrateurs WHERE id=1').fetchone())
        db.close()
        f.client.cookies.set(f.worker.SESSION,f.worker._creer_session(f.env.APP_SECRET_KEY.encode(),row))

    def test_question_private_until_admin_publishes_then_deletable(self):
        f=self.f;token=self.token()
        question='Comment fonctionne cette consultation ?'
        r=f.client.post('/faq',data={'csrf_token':token,'question':question})
        self.assertEqual(r.status_code,200)
        self.assertNotIn(question,r.text)
        self.assertEqual(f.client.get('/admin/faq',follow_redirects=False).status_code,303)
        db=f.db.connect();qid=db.execute('SELECT id FROM faq_questions').fetchone()[0];db.close()
        self.assertEqual(f.client.post(f'/admin/faq/{qid}/publish',data={'question':question,'answer':'test'},follow_redirects=False).status_code,303)
        self.admin();token=self.token('/admin/faq')
        self.assertEqual(f.client.post(f'/admin/faq/{qid}/publish',data={'question':question,'answer':'test'}).status_code,403)
        r=f.client.post(f'/admin/faq/{qid}/publish',data={'csrf_token':token,'question':question,'answer':'<script>alert(1)</script>'})
        self.assertEqual(r.status_code,200)
        r=f.client.get('/faq');self.assertIn(question,r.text)
        self.assertIn('&lt;script&gt;',r.text);self.assertNotIn('<script>',r.text)
        token=self.token('/admin/faq')
        self.assertEqual(f.client.post(f'/admin/faq/{qid}/delete',data={'csrf_token':token}).status_code,200)
        self.assertNotIn(question,f.client.get('/faq').text)

    def test_csrf_limits_and_rate_limit(self):
        f=self.f;t=self.token()
        self.assertEqual(f.client.post('/faq',data={'question':'Test question suffisamment longue'}).status_code,403)
        self.assertEqual(f.client.post('/faq',data={'csrf_token':t,'question':'x'*1001}).status_code,400)
        for _ in range(5):
            self.assertEqual(f.client.post('/faq',data={'csrf_token':t,'question':'Question suffisamment longue'},follow_redirects=False).status_code,303)
        self.assertEqual(f.client.post('/faq',data={'csrf_token':t,'question':'Question suffisamment longue'}).status_code,429)

    def test_purge_only_unpublished_questions_after_thirty_days(self):
        f=self.f;db=f.db.connect();old=int(time.time())-31*86400
        db.execute("INSERT INTO faq_questions VALUES (1,'Question ancienne','',?,NULL)",(old,))
        db.execute("INSERT INTO faq_questions VALUES (2,'Question publiee','Une reponse',?,?)",(old,old))
        db.close()
        asyncio.run(f.worker.Default().scheduled(None,f.env,None))
        db=f.db.connect();self.assertEqual([r[0] for r in db.execute('SELECT id FROM faq_questions')],[2]);db.close()
