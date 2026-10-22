"""Entrée Cloudflare autonome : aperçu public en lecture seule sur D1.

Ne pas importer app.py : celui-ci dépend d'une base SQLite locale,
de variables .env et de fonctions non disponibles dans Workers.
Les opérations de vote et l'administration sont désactivées tant que
leur migration sécurisée n'est pas terminée.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape
from workers import asgi


DOSSIER = Path(__file__).resolve().parent
PARIS = ZoneInfo("Europe/Paris")

modeles = Environment(
    loader=FileSystemLoader(str(DOSSIER / "templates")),
    autoescape=select_autoescape(["html", "xml"]),
)


def _date_utc(valeur):
    """Convertit les dates ISO UTC de D1 en datetime aware."""
    if not valeur or not isinstance(valeur, str):
        return None
    try:
        resultat = datetime.fromisoformat(valeur.replace("Z", "+00:00"))
        if resultat.tzinfo is None:
            resultat = resultat.replace(tzinfo=timezone.utc)
        return resultat.astimezone(timezone.utc)
    except ValueError:
        return None


def local_date(valeur):
    """Filtre Jinja d'origine, alimenté avec des dates converties en UTC."""
    if valeur is None:
        return "Non définie"
    return datetime.fromtimestamp(valeur, PARIS).strftime("%d/%m/%Y à %H:%M")


modeles.filters["local_date"] = local_date
app = FastAPI(title="AGemocratie Cloudflare (aperçu public)", docs_url=None,
              redoc_url=None, openapi_url=None)


@app.middleware("http")
async def en_tetes_de_securite(requete: Request, suivant):
    reponse = await suivant(requete)
    reponse.headers["X-Content-Type-Options"] = "nosniff"
    reponse.headers["X-Frame-Options"] = "DENY"
    reponse.headers["Referrer-Policy"] = "no-referrer"
    reponse.headers["Cache-Control"] = "no-store"
    reponse.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'none'; style-src 'self'; "
        "img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    )
    return reponse


def _lignes_python(resultat):
    """Convertit l'array JS de D1 avant de le remettre à Jinja."""
    lignes = resultat.results
    if hasattr(lignes, "to_py"):
        lignes = lignes.to_py()
    return [dict(ligne) for ligne in lignes]


def _scrutin_affichable(ligne):
    debut = _date_utc(ligne.get("debut_utc"))
    fin = _date_utc(ligne.get("fin_utc"))
    maintenant = datetime.now(timezone.utc)
    # Dates absentes/incorrectes : fail-closed, jamais 'open'.
    if debut is None or fin is None or fin <= maintenant:
        phase = "ended"
    elif maintenant < debut:
        phase = "upcoming"
    else:
        phase = "open"
    return {
        "id": int(ligne["id"]),
        "title": str(ligne["titre"]),
        "description": str(ligne.get("description") or ""),
        "starts_at": int(debut.timestamp()) if debut else None,
        "ends_at": int(fin.timestamp()) if fin else None,
        "phase": phase,
    }


def _rendu(nom: str, *, status_code: int = 200, **contexte):
    # Variables attendues par les templates ORIGINAUX d'AGémocratie.
    html = modeles.get_template(nom).render(
        csrf_token="", is_admin=False, is_owner=False,
        admin_username=None, **contexte
    )
    return HTMLResponse(content=html, status_code=status_code)


def _base(requete: Request):
    env = requete.scope.get("env")
    if env is None or not hasattr(env, "DB"):
        raise HTTPException(503, detail="Binding Cloudflare DB indisponible")
    return env.DB


@app.get("/health")
async def health(requete: Request):
    bdd = _base(requete)
    await bdd.prepare("SELECT 1 AS ok").first("ok")
    return {"status": "ok"}


@app.get("/api/test-db")
async def test_db(requete: Request):
    bdd = _base(requete)
    resultat = await bdd.prepare("SELECT 1 AS ok").first("ok")
    return {"d1": "connectee" if resultat == 1 else "indisponible"}


@app.get("/")
async def accueil(requete: Request):
    bdd = _base(requete)
    resultat = await bdd.prepare(
        "SELECT id, titre, description, debut_utc, fin_utc "
        "FROM scrutins ORDER BY id DESC"
    ).all()
    sujets = [_scrutin_affichable(ligne) for ligne in _lignes_python(resultat)]
    priorite = {"open": 0, "upcoming": 1, "ended": 2}
    sujets.sort(key=lambda s: (priorite[s["phase"]], -s["id"]))
    # Ne pas afficher une fausse confirmation après un GET.
    return _rendu("home.html", request=requete, polls=sujets, success=False)


@app.get("/polls/{id_sujet}")
async def apercu_sujet(requete: Request, id_sujet: int):
    bdd = _base(requete)
    ligne = await bdd.prepare(
        "SELECT id, titre, description, debut_utc, fin_utc "
        "FROM scrutins WHERE id = ?"
    ).bind(id_sujet).first()
    if ligne is None:
        raise HTTPException(404, detail="Sujet introuvable")
    if hasattr(ligne, "to_py"):
        ligne = ligne.to_py()
    sujet = _scrutin_affichable(dict(ligne))
    return _rendu("poll_preview.html", request=requete,
                  poll=sujet, phase=sujet["phase"])


@app.api_route("/admin", methods=["GET", "POST"])
@app.api_route("/admin/{chemin:path}", methods=["GET", "POST"])
@app.api_route("/access", methods=["GET", "POST"])
@app.api_route("/vote", methods=["GET", "POST"])
@app.api_route("/polls/{id_sujet}/access", methods=["GET", "POST"])
async def fonctionnalite_non_active(requete: Request, chemin: str = "",
                                   id_sujet: int = 0):
    return _rendu("non_disponible.html", status_code=503,
                  request=requete)


# Adaptateur ASGI officiel Cloudflare FastAPI.
Default = asgi.entrypoint(app)
