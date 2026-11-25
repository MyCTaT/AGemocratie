"""Protections communes, sans dépendance cryptographique artisanale."""
import base64
import hashlib
import hmac
import json
import re
import struct
import time
from starlette.responses import HTMLResponse

MAX_BODY_BYTES=65536
MIN_RESULT_VOTERS=6
MIN_RESULT_CELL=3
AG_RETENTION_SECONDS=30*24*60*60

class RequestLimitsMiddleware:
    def __init__(self,app):self.app=app
    async def __call__(self,scope,receive,send):
        if scope['type']!='http':return await self.app(scope,receive,send)
        headers=scope.get('headers',[])
        hosts=[v.decode('latin1') for k,v in headers if k.lower()==b'host']
        if len(hosts)!=1 or len(hosts[0])>260 or not re.fullmatch(r'(?:[A-Za-z0-9][A-Za-z0-9.-]*|\[[0-9a-fA-F:]+\])(?::[0-9]{1,5})?',hosts[0]):
            return await HTMLResponse('Hôte invalide',status_code=400)(scope,receive,send)
        if scope.get('method') not in ('POST','PUT','PATCH'):return await self.app(scope,receive,send)
        lengths=[v for k,v in headers if k.lower()==b'content-length']
        if lengths:
            try:declared=int(lengths[0])
            except ValueError:declared=-1
            if len(lengths)!=1 or declared<0:return await HTMLResponse('Requête invalide',status_code=400)(scope,receive,send)
            if declared>MAX_BODY_BYTES:return await HTMLResponse('Formulaire trop volumineux (64 Kio maximum)',status_code=413)(scope,receive,send)
        chunks=[];size=0
        while True:
            message=await receive()
            if message['type']=='http.disconnect':return
            chunk=message.get('body',b'');size+=len(chunk)
            if size>MAX_BODY_BYTES:return await HTMLResponse('Formulaire trop volumineux (64 Kio maximum)',status_code=413)(scope,receive,send)
            chunks.append(chunk)
            if not message.get('more_body'):break
        pending=True
        async def replay():
            nonlocal pending
            if pending:
                pending=False;return {'type':'http.request','body':b''.join(chunks),'more_body':False}
            return await receive()
        return await self.app(scope,replay,send)

async def consume_attempts(db,scopes):
    now=int(time.time())
    sql="""INSERT INTO limites_connexion(empreinte,debut_fenetre,echecs) VALUES (?,?,1)
       ON CONFLICT(empreinte) DO UPDATE SET
       echecs=CASE WHEN excluded.debut_fenetre-limites_connexion.debut_fenetre>=900 THEN 1 ELSE limites_connexion.echecs+1 END,
       debut_fenetre=CASE WHEN excluded.debut_fenetre-limites_connexion.debut_fenetre>=900 THEN excluded.debut_fenetre ELSE limites_connexion.debut_fenetre END
       WHERE excluded.debut_fenetre-limites_connexion.debut_fenetre>=900 OR limites_connexion.echecs<?"""
    results=await db.batch([db.prepare(sql).bind(scope,now,limit) for scope,limit in scopes])
    return all(int(result.meta.changes)==1 for result in results)

def scoped_email_hash(key,ag_id,legacy_hash):
    return hmac.new(key,f'ag-mail-v2:{ag_id}:{legacy_hash}'.encode(),hashlib.sha256).hexdigest()

async def migrate_legacy_address(db,key,ag_id,legacy):
    scoped=scoped_email_hash(key,ag_id,legacy)
    await db.batch([
        db.prepare("""INSERT OR IGNORE INTO ag_mail_delivrances_v2(assemblee_id,email_hash)
            SELECT assemblee_id,? FROM ag_mail_delivrances WHERE assemblee_id=? AND email_hash=?""").bind(scoped,ag_id,legacy),
        db.prepare('DELETE FROM ag_mail_delivrances WHERE assemblee_id=? AND email_hash=?').bind(ag_id,legacy),
    ])
    return scoped

async def maintenance(db,key):
    now=int(time.time())
    await db.batch([


        db.prepare("""DELETE FROM assemblees WHERE id IN (
            SELECT a.id FROM assemblees a
            WHERE COALESCE((SELECT MAX(unixepoch(s.fin_utc)) FROM scrutins s
                            WHERE s.assemblee_id=a.id),unixepoch(a.cree_le))<=?
            ORDER BY a.id LIMIT 5)""").bind(now-AG_RETENTION_SECONDS),
        db.prepare('DELETE FROM ag_mail_verifications WHERE expire_le<=?').bind(now),
        db.prepare('DELETE FROM limites_connexion WHERE debut_fenetre<=?').bind(now-900),
        db.prepare('DELETE FROM journal_admin WHERE unixepoch(le)<=?').bind(now-AG_RETENTION_SECONDS),
    ])
    result=await db.prepare('SELECT assemblee_id,email_hash FROM ag_mail_delivrances LIMIT 5').all()
    rows=result.results.to_py() if hasattr(result.results,'to_py') else result.results
    for row in rows:await migrate_legacy_address(db,key,int(row['assemblee_id']),str(row['email_hash']))

def protect_results(rows):
    counts=[int(row['total']) for row in rows]
    nonzero=[n for n in counts if n]
    return rows if sum(counts)>=MIN_RESULT_VOTERS and len(nonzero)>=2 and min(nonzero)>=MIN_RESULT_CELL else None

def totp_step(seed,code,now=None):
    if not isinstance(seed,str) or not re.fullmatch('[A-Z2-7]{32,64}',seed):return None
    if not isinstance(code,str) or not re.fullmatch('[0-9]{6}',code):return None
    try:key=base64.b32decode(seed+'='*((-len(seed))%8))
    except ValueError:return None
    step=int(time.time() if now is None else now)//30
    for current in (step,step-1,step+1):
        if current<0:continue
        digest=hmac.new(key,struct.pack('>Q',current),hashlib.sha1).digest();offset=digest[-1]&15
        number=(struct.unpack('>I',digest[offset:offset+4])[0]&0x7fffffff)%1000000
        if hmac.compare_digest(code,f'{number:06d}'):return current
    return None

async def admin_mfa(request,core,account,code):
    raw=None
    for env in (core['cloudflare_env'],request.scope.get('env')):
        candidate=getattr(env,'ADMIN_TOTP_SECRETS',None) if env is not None else None
        if hasattr(candidate,'to_py'):candidate=candidate.to_py()
        if candidate:raw=candidate;break
    try:
        seeds=json.loads(raw or '{}')
        seed=seeds.get(account['identifiant'].lower()) if isinstance(seeds,dict) else None
    except (ValueError,TypeError):seed=None
    step=totp_step(seed,code)
    if step is None:return False
    result=await core['_bdd'](request).prepare("""INSERT INTO admin_mfa_replays(admin_id,last_step) VALUES (?,?)
        ON CONFLICT(admin_id) DO UPDATE SET last_step=excluded.last_step WHERE excluded.last_step>admin_mfa_replays.last_step""").bind(int(account['id']),step).run()
    return int(result.meta.changes)==1
