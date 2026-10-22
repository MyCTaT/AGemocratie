
from fastapi import FastAPI, Request
from workers import asgi

# Créer l'application avant les routes
app = FastAPI()


@app.get("/")
async def accueil():
    return {
        "message": "AGemocratie fonctionne sur Cloudflare"
    }


@app.get("/api/test-db")
async def tester_bdd(requete: Request):
    bdd = requete.scope["env"].DB

    await bdd.prepare(
        "SELECT 1 AS connexion_ok"
    ).run()

    return {"d1": "connectee"}


# Point d'entrée Cloudflare
Default = asgi.entrypoint(app)
