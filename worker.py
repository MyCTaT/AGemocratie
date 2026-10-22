
from fastapi import FastAPI
from workers import asgi
from fastapi import Request

@app.get("/api/test-db")
async def tester_base(requete: Request):
    bdd = requete.scope["env"].DB

    await bdd.prepare(
        "SELECT 1 AS connexion_ok"
    ).run()

    return {"d1": "connectee"}

app = FastAPI()

@app.get("/")
async def accueil():
    return {"message": "AGemocratie fonctionne sur Cloudflare"}

Default = asgi.entrypoint(app)
