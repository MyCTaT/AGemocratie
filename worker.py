from fastapi import FastAPI, Request
from workers import asgi


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/")
async def accueil():
    return {
        "message": "AGemocratie fonctionne sur Cloudflare"
    }


Default = asgi.entrypoint(app)
