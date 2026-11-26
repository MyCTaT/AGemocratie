import secrets
import time
from typing import Annotated

from fastapi import HTTPException, Request, Path
from security_controls import consume_attempts

QuestionId = Annotated[int, Path(ge=1, le=9_007_199_254_740_991)]


async def purger_questions(db):
    await db.prepare('DELETE FROM faq_questions WHERE publie_le IS NULL AND cree_le<=?').bind(int(time.time())-30*86400).run()


def installer(app, core):
    async def page(request, *, error=None, value='', status=200):
        rows = await core['_bdd'](request).prepare(
            "SELECT question,reponse FROM faq_questions WHERE publie_le IS NOT NULL AND reponse<>'' ORDER BY publie_le DESC,id DESC LIMIT 100"
        ).all()
        return core['_rendu'](request, 'faq.html', compte=await core['_compte'](request),
            questions=core['_lignes'](rows), error=error, question_value=value, statut=status,
            sent=request.query_params.get('sent')=='1')

    @app.get('/faq')
    async def faq(request: Request):
        return await page(request)

    @app.post('/faq')
    async def poser_question(request: Request):
        form=await request.form()
        secret=core['_secret'](request)
        core['_csrf_valide'](request,secret,form)
        question=str(form.get('question','')).strip()
        if not 10<=len(question)<=1000:
            return await page(request,error='La question doit contenir entre 10 et 1 000 caractères.',value=question[:1000],status=400)
        db=core['_bdd'](request)
        scope=core['_signature'](secret,f"faq:{int(time.time())//900}:{core['_ip_normalisee'](request)}".encode())
        if not await consume_attempts(db,[(scope,5)]):
            return await page(request,error='Trop de questions. Réessayez dans 15 minutes.',value=question,status=429)
        await db.prepare('INSERT INTO faq_questions(id,question,cree_le) VALUES (?,?,?)').bind(secrets.randbelow(2**52-1)+1,question,int(time.time())).run()
        return core['_lien']('/faq?sent=1')

    @app.get('/admin/faq')
    async def administration(request: Request):
        compte,refus=await core['_auth'](request)
        if refus is not None:
            return refus
        rows=await core['_bdd'](request).prepare(
            'SELECT id,question,reponse,publie_le FROM faq_questions ORDER BY (publie_le IS NOT NULL),cree_le,id LIMIT 100'
        ).all()
        return core['_rendu'](request,'faq_admin.html',compte=compte,questions=core['_lignes'](rows),saved=request.query_params.get('saved')=='1')

    @app.post('/admin/faq/{question_id}/publish')
    async def publier(request: Request, question_id: QuestionId):
        compte,refus=await core['_auth'](request)
        if refus is not None:
            return refus
        form=await request.form()
        core['_csrf_valide'](request,core['_secret'](request),form)
        question=str(form.get('question','')).strip()
        reponse=str(form.get('answer','')).strip()
        if not 10<=len(question)<=1000 or not 1<=len(reponse)<=5000:
            raise HTTPException(400,detail='Question ou réponse invalide.')
        db=core['_bdd'](request)
        results=await db.batch([
            db.prepare('UPDATE faq_questions SET question=?,reponse=?,publie_le=? WHERE id=?').bind(question,reponse,int(time.time()),question_id),
            db.prepare("INSERT INTO journal_admin(admin_id,action,cible_type,cible_id) SELECT ?,'publish_faq','faq',? WHERE changes()=1").bind(int(compte['id']),str(question_id)),
        ])
        if not results[0].meta.changes:
            raise HTTPException(404,detail='Question introuvable.')
        return core['_lien']('/admin/faq?saved=1')

    @app.post('/admin/faq/{question_id}/delete')
    async def supprimer(request: Request, question_id: QuestionId):
        compte,refus=await core['_auth'](request)
        if refus is not None:
            return refus
        form=await request.form()
        core['_csrf_valide'](request,core['_secret'](request),form)
        db=core['_bdd'](request)
        await db.batch([
            db.prepare('DELETE FROM faq_questions WHERE id=?').bind(question_id),
            db.prepare("INSERT INTO journal_admin(admin_id,action,cible_type,cible_id) SELECT ?,'delete_faq','faq',? WHERE changes()=1").bind(int(compte['id']),str(question_id)),
        ])
        return core['_lien']('/admin/faq?saved=1')
