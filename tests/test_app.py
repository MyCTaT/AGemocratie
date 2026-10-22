import os,sys,re, sqlite3, tempfile, importlib, datetime, zoneinfo, time
from pathlib import Path
from fastapi.testclient import TestClient


def charger_app(tmp):
    os.environ['APP_SECRET_KEY']='x'*64
    os.environ['ADMIN_PASSWORD']='Un-Mot-De-Passe-Long-123'
    os.environ['DATABASE_PATH']=str(Path(tmp)/'votes.sqlite3')
    os.environ['COOKIE_SECURE']='0'
    sys.modules.pop('app',None)
    return importlib.import_module('app')


def outils(c):
    def jeton(url):
        r=c.get(url); assert r.status_code==200, (url,r.status_code,r.text[:500]);m=re.search(r'name="csrf_token" value="([^"]+)"',r.text); assert m,(url,r.text[:1000]);return m.group(1)
    def connexion_admin():
        t=jeton('/admin/login')
        r=c.post('/admin/login',data={'csrf_token':t,'username':'admin','password':os.environ['ADMIN_PASSWORD']},follow_redirects=True)
        assert r.status_code==200, r.text[:500]
    return jeton, connexion_admin


def horaires():
    now=datetime.datetime.now(zoneinfo.ZoneInfo('Europe/Paris'))
    return ((now-datetime.timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M'),
            (now+datetime.timedelta(days=2)).strftime('%Y-%m-%dT%H:%M'))


def test_parcours_complet():
    with tempfile.TemporaryDirectory() as tmp:
        module=charger_app(tmp)
        c=TestClient(module.app)
        jeton, connexion_admin = outils(c)
        assert c.get('/health').json()=={'status':'ok'}
        assert c.get('/').status_code==200
        connexion_admin()
        t=jeton('/admin/ag/new')
        r=c.post('/admin/ag/new',data={'csrf_token':t,'title':'AG de printemps','description':'Ordre du jour'},follow_redirects=True)
        assert r.status_code==200 and 'AG de printemps' in r.text, r.text[:1000]
        debut,fin=horaires()
        for titre in ('Approbation des comptes','Élection du bureau'):
            t=jeton('/admin/ag/1/polls/new')
            r=c.post('/admin/ag/1/polls/new',data={'csrf_token':t,'title':titre,'description':'','options':'Oui\nNon','starts_at':debut,'ends_at':fin},follow_redirects=True)
            assert r.status_code==200, (r.status_code,r.text[:1500])
            assert titre in r.text
            assert 'Masquée jusqu\'à la fin' in r.text, r.text[:1500]
        t=jeton('/admin/ag/1')
        r=c.post('/admin/ag/1/codes',data={'csrf_token':t},follow_redirects=True)
        assert r.status_code==200
        m=re.search(r'Votre nouveau code[^<]*</h3><h2>(\d{10})</h2>',r.text)
        assert m,r.text[:2500]
        code=m.group(1)
        assert code not in c.get('/admin/ag/1').text
        t=jeton('/admin/users')
        r=c.post('/admin/users/create', data={'csrf_token':t,'username':'test_admin','password':'MotDePasseSecondaire123!'},follow_redirects=True)
        assert r.status_code==200 and 'test_admin' in r.text,(r.status_code,r.text[:600])
        t=jeton('/admin/users')
        r=c.post('/admin/users/2/delete',data={'csrf_token':t,'confirmation_identifiant':'test_admin'},follow_redirects=True)
        assert r.status_code==200,r.text[:600]
        t=jeton('/admin/ag/1')
        r=c.post('/admin/logout',data={'csrf_token':t},follow_redirects=True)
        assert r.status_code==200

        # Un seul code pour toute l'AG : une voix sur chacun des deux sujets.
        t=jeton('/ag/1')
        r=c.post('/ag/1/access',data={'csrf_token':t,'code':'0000000000'},follow_redirects=True)
        assert r.status_code==400
        r=c.post('/ag/1/access',data={'csrf_token':t,'code':code},follow_redirects=True)
        assert r.status_code==200 and 'Votre code est actif' in r.text, r.text[:600]
        with module.connect_db() as bdd:
            sujets=[ligne['id'] for ligne in bdd.execute('SELECT id FROM polls ORDER BY id')]
        for id_sujet in sujets:
            t=jeton(f'/vote/{id_sujet}')
            with module.connect_db() as bdd:
                choix=bdd.execute('SELECT id FROM poll_options WHERE poll_id=? ORDER BY id',(id_sujet,)).fetchone()['id']
            r=c.post(f'/vote/{id_sujet}',data={'csrf_token':t,'option_id':str(choix)},follow_redirects=True)
            assert r.status_code==200 and 'Votre vote a été enregistré' in r.text, r.text[:1000]
            # Second vote sur le même sujet refusé.
            r=c.post(f'/vote/{id_sujet}',data={'csrf_token':t,'option_id':str(choix)},follow_redirects=False)
            assert r.status_code==303 and r.headers['location']=='/ag/1'
        assert c.get('/ag/1').text.count('✓ Vote enregistré')==2
        with module.connect_db() as bdd:
            assert bdd.execute('SELECT COUNT(*) FROM ballots').fetchone()[0]==2
            assert bdd.execute('SELECT COUNT(*) FROM code_uses').fetchone()[0]==2
        t=jeton('/ag/1')
        c.post('/ag/leave',data={'csrf_token':t})
        assert 'Votre code est actif' not in c.get('/ag/1').text

        connexion_admin()
        r=c.get(f'/admin/polls/{sujets[0]}')
        assert 'Masquée jusqu\'à la fin' in r.text, r.text[:2000]
        t=jeton(f'/admin/polls/{sujets[0]}')
        r=c.post(f'/admin/polls/{sujets[0]}/close',data={'csrf_token':t},follow_redirects=True)
        assert r.status_code==200
        assert 'Masquée jusqu\'à la fin' not in r.text
        t=jeton(f'/admin/polls/{sujets[0]}')
        r=c.post(f'/admin/polls/{sujets[0]}/delete',data={'csrf_token':t,'confirmation_titre':'Approbation des comptes'},follow_redirects=True)
        assert r.status_code==200, (r.status_code,r.text[:1000])
        with module.connect_db() as bdd:
            assert bdd.execute('SELECT COUNT(*) FROM polls').fetchone()[0]==1
            assert bdd.execute('SELECT COUNT(*) FROM assembly_codes').fetchone()[0]==1
        t=jeton('/admin/ag/1')
        r=c.post('/admin/ag/1/delete',data={'csrf_token':t,'confirmation_titre':'AG de printemps'},follow_redirects=True)
        assert r.status_code==200, (r.status_code,r.text[:1000])
        with module.connect_db() as bdd:
            for table in ('assemblies','polls','assembly_codes','code_uses','ballots','poll_options'):
                assert bdd.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]==0, table
        print('OK : AG, deux sujets, un code, deux votes, double vote refusé, clôture et suppression.')


def test_migration_ancienne_base():
    """Une base de la version « un code par sujet » est reprise sans perte."""
    with tempfile.TemporaryDirectory() as tmp:
        chemin=Path(tmp)/'votes.sqlite3'
        cle='x'*64
        import hmac, hashlib
        empreinte=lambda code: hmac.new(cle.encode(), code.encode(), hashlib.sha256).hexdigest()
        maintenant=int(time.time())
        bdd=sqlite3.connect(chemin)
        bdd.executescript("""
            CREATE TABLE polls (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '', is_open INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL, starts_at INTEGER, ends_at INTEGER);
            CREATE TABLE poll_options (id INTEGER PRIMARY KEY AUTOINCREMENT, poll_id INTEGER NOT NULL REFERENCES polls(id),
                label TEXT NOT NULL, position INTEGER NOT NULL);
            CREATE TABLE access_codes (id INTEGER PRIMARY KEY AUTOINCREMENT, poll_id INTEGER NOT NULL REFERENCES polls(id),
                code_hash TEXT NOT NULL UNIQUE, used_at INTEGER, created_at INTEGER NOT NULL);
            CREATE TABLE ballots (id INTEGER PRIMARY KEY AUTOINCREMENT, poll_id INTEGER NOT NULL REFERENCES polls(id),
                option_id INTEGER NOT NULL REFERENCES poll_options(id), created_at INTEGER NOT NULL);
        """)
        bdd.execute("INSERT INTO polls VALUES (1,'Ancien sujet','Desc',1,?,?,?)",(maintenant,maintenant-60,maintenant+86400))
        bdd.execute("INSERT INTO poll_options VALUES (1,1,'Oui',0),(2,1,'Non',1)")
        bdd.execute("INSERT INTO access_codes VALUES (1,1,?,?,?)",(empreinte('1111111111'),maintenant,maintenant))
        bdd.execute("INSERT INTO access_codes VALUES (2,1,?,NULL,?)",(empreinte('2222222222'),maintenant))
        bdd.execute("INSERT INTO ballots VALUES (1,1,1,?)",(maintenant,))
        bdd.commit(); bdd.close()

        module=charger_app(tmp)
        assert list(Path(tmp).glob('votes.avant-migration-ag.*.bak')), 'sauvegarde absente'
        with module.connect_db() as bdd:
            assert bdd.execute("SELECT title FROM assemblies").fetchone()['title']=='Ancien sujet'
            assert bdd.execute("SELECT assembly_id FROM polls WHERE id=1").fetchone()[0]==1
            assert bdd.execute("SELECT COUNT(*) FROM assembly_codes").fetchone()[0]==2
            assert bdd.execute("SELECT COUNT(*) FROM code_uses").fetchone()[0]==1
            assert bdd.execute("SELECT COUNT(*) FROM ballots").fetchone()[0]==1
            assert bdd.execute("SELECT 1 FROM sqlite_master WHERE name='access_codes'").fetchone() is None
        c=TestClient(module.app)
        jeton,_=outils(c)
        assert c.get('/polls/1',follow_redirects=False).headers['location']=='/ag/1'
        t=jeton('/ag/1')
        # Le code déjà utilisé reste valide pour l'AG mais ne peut plus voter sur l'ancien sujet.
        c.post('/ag/1/access',data={'csrf_token':t,'code':'1111111111'})
        assert '✓ Vote enregistré' in c.get('/ag/1').text
        assert c.get('/vote/1',follow_redirects=False).status_code==303
        t=jeton('/ag/1')
        c.post('/ag/leave',data={'csrf_token':t})
        t=jeton('/ag/1')
        c.post('/ag/1/access',data={'csrf_token':t,'code':'2222222222'})
        t=jeton('/vote/1')
        r=c.post('/vote/1',data={'csrf_token':t,'option_id':'2'},follow_redirects=True)
        assert 'Votre vote a été enregistré' in r.text
        # Un second démarrage ne refait pas la migration.
        module=charger_app(tmp)
        assert len(list(Path(tmp).glob('*.bak')))==1
