import os,sys,re, tempfile, importlib, datetime, zoneinfo
from pathlib import Path
from fastapi.testclient import TestClient


def test_parcours_complet():
    with tempfile.TemporaryDirectory() as tmp:
        os.environ['APP_SECRET_KEY']='x'*64
        os.environ['ADMIN_PASSWORD']='Un-Mot-De-Passe-Long-123'
        os.environ['DATABASE_PATH']=str(Path(tmp)/'votes.sqlite3')
        os.environ['COOKIE_SECURE']='0'
        sys.modules.pop('app',None)
        module=importlib.import_module('app')
        c=TestClient(module.app)
        def jeton(url):
            r=c.get(url); assert r.status_code==200, (url,r.status_code,r.text[:500]);m=re.search(r'name="csrf_token" value="([^"]+)"',r.text); assert m,(url,r.text[:1000]);return m.group(1)
        assert c.get('/health').json()=={'status':'ok'}
        assert c.get('/').status_code==200
        t=jeton('/admin/login')
        r=c.post('/admin/login',data={'csrf_token':t,'username':'admin','password':os.environ['ADMIN_PASSWORD']},follow_redirects=True)
        assert r.status_code==200, r.text[:500]
        t=jeton('/admin/polls/new')
        tz=zoneinfo.ZoneInfo('Europe/Paris')
        now=datetime.datetime.now(tz)
        debut=(now-datetime.timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M')
        fin=(now+datetime.timedelta(days=2)).strftime('%Y-%m-%dT%H:%M')
        r=c.post('/admin/polls/new',data={'csrf_token':t,'title':'Sujet de test en français','description':'Exemple','options':'Oui\nNon','starts_at':debut,'ends_at':fin},follow_redirects=True)
        assert r.status_code==200, (r.status_code,r.text[:1500])
        assert 'Sujet de test en français' in r.text
        assert 'Masquée jusqu\'à la fin' in r.text, r.text[:1500]
        id_sujet=1
        t=jeton('/admin/polls/1')
        r=c.post('/admin/polls/1/codes',data={'csrf_token':t},follow_redirects=True)
        assert r.status_code==200
        m=re.search(r'Votre nouveau code[^<]*</h3><h2>(\d{10})</h2>',r.text)
        assert m,r.text[:2500]
        code=m.group(1)
        assert code not in c.get('/admin/polls/1').text
        with module.connect_db() as bdd:
            assert bdd.execute('SELECT COUNT(*) FROM access_codes').fetchone()[0]==1
        t=jeton('/admin/users')
        r=c.post('/admin/users/create', data={'csrf_token':t,'username':'test_admin','password':'MotDePasseSecondaire123!'},follow_redirects=True)
        assert r.status_code==200,(r.status_code,r.text[:600])
        assert 'test_admin' in r.text
        t=jeton('/admin/users')
        r=c.post('/admin/users/2/delete',data={'csrf_token':t,'confirmation_identifiant':'test_admin'},follow_redirects=True)
        assert r.status_code==200,r.text[:600]
        t=jeton('/admin/polls/1')
        r=c.post('/admin/logout',data={'csrf_token':t},follow_redirects=True)
        assert r.status_code==200
        t=jeton('/polls/1')
        r=c.post('/polls/1/access',data={'csrf_token':t,'code':code},follow_redirects=True)
        assert r.status_code==200, r.text[:600]
        assert 'Sujet de test en français' in r.text
        t=jeton('/vote')
        with module.connect_db() as bdd:
            choix=bdd.execute('SELECT id FROM poll_options WHERE poll_id=1 ORDER BY id').fetchone()['id']
        r=c.post('/vote',data={'csrf_token':t,'option_id':str(choix)},follow_redirects=True)
        assert r.status_code==200, r.text[:1000]
        t=jeton('/polls/1')
        r=c.post('/polls/1/access',data={'csrf_token':t,'code':code},follow_redirects=True)
        assert r.status_code==400 or 'Code invalide' in r.text
        t=jeton('/admin/login')
        c.post('/admin/login',data={'csrf_token':t,'username':'admin','password':os.environ['ADMIN_PASSWORD']},follow_redirects=True)
        r=c.get('/admin/polls/1')
        assert 'Masquée jusqu\'à la fin' in r.text, r.text[:2000]
        t=jeton('/admin/polls/1')
        r=c.post('/admin/polls/1/close',data={'csrf_token':t},follow_redirects=True)
        assert r.status_code==200
        assert 'Masquée jusqu\'à la fin' not in r.text
        assert '1' in r.text
        t=jeton('/admin/polls/1')
        r=c.post('/admin/polls/1/delete',data={'csrf_token':t,'confirmation_titre':'Sujet de test en français'},follow_redirects=True)
        assert r.status_code==200, (r.status_code,r.text[:1000])
        with module.connect_db() as bdd:
            assert bdd.execute('SELECT COUNT(*) FROM polls').fetchone()[0]==0
            assert bdd.execute('SELECT COUNT(*) FROM ballots').fetchone()[0]==0
        print('OK : accueil, comptes admin, sujet, code, un vote, résultats masqués, clôture et suppression.')
