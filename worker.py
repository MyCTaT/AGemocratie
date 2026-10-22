
from fastapi import FastAPI
from workers import asgi

app = FastAPI()

@app.get("/")
async def accueil():
    return {"message": "AGemocratie fonctionne sur Cloudflare"}

Default = asgi.entrypoint(app)
