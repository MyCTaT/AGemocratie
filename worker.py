
from fastapi import FastAPI, Request
from workers import asgi

# Création de l'application FastAPI
app = FastAPI()


# Page d'accueil de test
@app.get("/")
async def accueil():
    return {
        "message": "AGemocratie fonctionne sur Cloudflare"
    }


# Vérification de la connexion à Cloudflare D1
@app.get("/api/test-db")
async def tester_base(requete: Request):

    bdd = requete.scope["env"].DB

    resultat = await bdd.prepare(
        "SELECT 1 AS connexion_ok"
    ).first("connexion_ok")

    return {
        "d1": "connectee" if resultat == 1 else "erreur"
    }


# Point d'entrée Cloudflare Workers
Default = asgi.entrypoint(app)
