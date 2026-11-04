"""AGémocratie / Cloudflare Workers.

Application locale inchangée. Administration D1 (connexion, comptes,
création/calendrier/clôture/suppression de scrutins et assemblées générales). Le vote demeure
volontairement désactivé jusqu'à la migration atomique des codes.

Secrets requis dans Cloudflare Worker (pas dans Git) : APP_SECRET_KEY.
"""
from __future__ import annotations

from typing import Annotated

import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import re
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

from fastapi import FastAPI, HTTPException, Request, Path as PathParam
from fastapi.responses import HTMLResponse, RedirectResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape
from workers import asgi, env as cloudflare_env

DOSSIER = Path(__file__).resolve().parent
PARIS = ZoneInfo("Europe/Paris")
SESSION = "__Host-ag_session"
CSRF = "__Host-ag_csrf"
COOKIE_CODE_REVEAL = "__Host-ag_code_reveal"
DUREE_ACCES_AG = 4 * 60 * 60
DUREE_SESSION = 4 * 60 * 60
DUREE_LIMITE = 15 * 60
ITERATIONS_MIN = 100_000  # accepte les empreintes existantes, qui seront renforcées à la connexion
ITERATIONS_MAX = 1_000_000
ITERATIONS_COURANTES = 600_000
MOT_DE_PASSE_MIN = 16

modeles = Environment(loader=FileSystemLoader(str(DOSSIER / "templates")),
                      autoescape=select_autoescape(["html", "xml"]))


def _utc(valeur):
    if not valeur or not isinstance(valeur, str):
        return None
    try:
        date = datetime.fromisoformat(valeur.replace("Z", "+00:00"))
        if date.tzinfo is None:
            date = date.replace(tzinfo=timezone.utc)
        return date.astimezone(timezone.utc)
    except ValueError:
        return None


def _local_date(valeur):
    if valeur is None:
        return "Non définie"
    return datetime.fromtimestamp(valeur, PARIS).strftime("%d/%m/%Y à %H:%M")


def _local_input(valeur):
    if valeur is None:
        return ""
    return datetime.fromtimestamp(valeur, PARIS).strftime("%Y-%m-%dT%H:%M")


modeles.filters.update(local_date=_local_date, local_input=_local_input)
logger = logging.getLogger("agemocratie.security")
app = FastAPI(title="AGémocratie Cloudflare", docs_url=None,
              redoc_url=None, openapi_url=None)


@app.middleware("http")
async def securite(requete: Request, suivant):
    try:
        reponse = await suivant(requete)
    except Exception:
        logger.exception("worker_error path=%s method=%s", requete.url.path, requete.method)
        reponse = HTMLResponse("Service indisponible", status_code=500)
    reponse.headers["X-Content-Type-Options"] = "nosniff"
    reponse.headers["X-Frame-Options"] = "DENY"
    reponse.headers["Referrer-Policy"] = "same-origin"
    reponse.headers["Cache-Control"] = "no-store"
    reponse.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'none'; style-src 'self'; "
        "img-src 'self'; object-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    )
    reponse.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    reponse.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    reponse.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    reponse.headers["Strict-Transport-Security"] = "max-age=31536000"
    return reponse


@app.exception_handler(Exception)
async def erreur_interne(requete: Request, erreur: Exception):
    logger.exception("worker_error path=%s method=%s", requete.url.path, requete.method)
    return HTMLResponse("Service indisponible", status_code=500)


def _bdd(requete):
    environnement = requete.scope.get("env")
    if environnement is None or not hasattr(environnement, "DB"):
        raise HTTPException(503, detail="Service indisponible")
    return environnement.DB


def _cle_valide(cle):
    return (isinstance(cle,str) and len(cle.encode("utf-8"))>=32
            and len(set(cle))>=12 and "REMPLACER" not in cle.upper())


def _secret(requete):
    # Le binding global est documenté par Cloudflare pour les Python Workers.
    # Le binding ASGI reste disponible en secours selon le contexte d'exécution.
    for environnement in (cloudflare_env, requete.scope.get("env")):
        if environnement is None:
            continue
        cle = getattr(environnement, "APP_SECRET_KEY", None)
        if cle is None:
            continue
        if hasattr(cle, "to_py"):
            cle = cle.to_py()
        if _cle_valide(cle):
            return cle.encode("utf-8")
    raise HTTPException(503, detail="Service indisponible")


def _secret_codes(requete):
    for environnement in (cloudflare_env, requete.scope.get("env")):
        if environnement is None:
            continue
        cle = getattr(environnement, "AG_CODE_KEY", None)
        if hasattr(cle, "to_py"):
            cle = cle.to_py()
        if _cle_valide(cle):
            return cle.encode("utf-8")
    raise HTTPException(503, detail="Service indisponible")


def _secret_legacy_codes(requete):
    for environnement in (cloudflare_env, requete.scope.get("env")):
        if environnement is None:
            continue
        cle = getattr(environnement, "LEGACY_AG_CODE_KEY", None)
        if hasattr(cle, "to_py"):
            cle = cle.to_py()
        if _cle_valide(cle):
            return cle.encode("utf-8")
    raise HTTPException(503, detail="Service indisponible")

def _objet(ligne):
    if ligne is None:
        return None
    if hasattr(ligne, "to_py"):
        ligne = ligne.to_py()
    return dict(ligne)


def _lignes(resultat):
    lignes = resultat.results
    if hasattr(lignes, "to_py"):
        lignes = lignes.to_py()
    return [dict(ligne) for ligne in lignes]


def _lien(chemin):
    return RedirectResponse(url=chemin, status_code=303)


def _signature(secret, donnees: bytes):
    return hmac.new(secret, donnees, hashlib.sha256).hexdigest()


def _jeton_csrf(secret, compte=None):
    contenu = {"t": int(time.time()), "i": int(compte["id"]) if compte else 0,
               "v": int(compte["auth_version"]) if compte else 0,
               "n": secrets.token_urlsafe(24)}
    enc = base64.urlsafe_b64encode(json.dumps(contenu, separators=(",", ":")).encode()).rstrip(b"=").decode()
    return f"{enc}.{_signature(secret, b'csrf:' + enc.encode())}"


def _csrf_contenu(jeton, secret):
    try:
        enc, sig = jeton.rsplit(".", 1)
        if not hmac.compare_digest(sig.encode(), _signature(secret, b"csrf:" + enc.encode()).encode()):
            return None
        contenu = json.loads(base64.urlsafe_b64decode(enc + "=" * (-len(enc) % 4)))
        if (type(contenu.get("t")) is not int or int(time.time()) - contenu["t"] > DUREE_SESSION
                or contenu["t"] > int(time.time()) + 60
                or type(contenu.get("i")) is not int or type(contenu.get("v")) is not int):
            return None
        return contenu
    except (ValueError, KeyError, TypeError, UnicodeError, AttributeError):
        return None


def _csrf_valide(requete, secret, formulaire):
    
    origine = requete.headers.get("origin")

    if origine:
        hote = requete.headers.get("host", "").strip().lower()
        origine_attendue = f"https://{hote}"
        if not hote or not hmac.compare_digest(origine.rstrip("/").lower().encode(), origine_attendue.encode()):
            raise HTTPException(
                403,
                detail="Origine du formulaire invalide"
            )
    else:
        referent = requete.headers.get("referer", "")
        parsed = urlparse(referent)
        hote = requete.headers.get("host", "").strip().lower()
        if not hote or parsed.scheme != "https" or (parsed.netloc or "").lower() != hote:
            raise HTTPException(403, detail="Origine du formulaire invalide")
    cookie = requete.cookies.get(CSRF, "")
    jeton = str(formulaire.get("csrf_token", ""))
    if not cookie or not jeton or not hmac.compare_digest(cookie.encode(), jeton.encode()):
        raise HTTPException(403, detail="Formulaire expiré ou invalide")
    token_data = _csrf_contenu(cookie, secret)
    if token_data is None:
        raise HTTPException(403, detail="Formulaire invalide")
    session = _lire_session(requete, secret)
    if token_data["i"] != (session["i"] if session else 0) or token_data["v"] != (session["v"] if session else 0):
        raise HTTPException(403, detail="Formulaire expiré ou invalide")


def _creer_session(secret, compte):
    # Les rôles ne sont pas dans le cookie : toujours relire D1.
    expiration = int(time.time()) + DUREE_SESSION
    contenu = {"i": int(compte["id"]), "v": int(compte["auth_version"]),
               "e": expiration, "n": secrets.token_urlsafe(12)}
    brut = json.dumps(contenu, separators=(",", ":")).encode()
    enc = base64.urlsafe_b64encode(brut).rstrip(b"=").decode()
    return enc + "." + _signature(secret, b"session:" + enc.encode())


def _lire_session(requete, secret):
    cookie = requete.cookies.get(SESSION, "")
    if not cookie or len(cookie) > 1024:
        return None
    try:
        enc, sig = cookie.rsplit(".", 1)
        if not hmac.compare_digest(sig.encode(), _signature(secret, b"session:" + enc.encode()).encode()):
            return None
        brut = base64.urlsafe_b64decode(enc + "=" * (-len(enc) % 4))
        donnees = json.loads(brut)
        if (not isinstance(donnees["i"], int) or isinstance(donnees["i"], bool)
                or not isinstance(donnees["v"], int) or isinstance(donnees["v"], bool)
                or not isinstance(donnees["e"], int) or donnees["e"] <= int(time.time())):
            return None
        return donnees
    except (ValueError, KeyError, TypeError, UnicodeError):
        return None


async def _compte(requete):
    secret = _secret(requete)
    session = _lire_session(requete, secret)
    if session is None:
        return None
    ligne = await _bdd(requete).prepare(
        "SELECT id, identifiant, role, auth_version FROM administrateurs WHERE id = ?"
    ).bind(session["i"]).first()
    compte = _objet(ligne)
    if compte is None or int(compte["auth_version"]) != session["v"]:
        return None
    return compte


async def _auth(requete, *, principal=False):
    compte = await _compte(requete)
    if compte is None:
        return None, _lien("/admin/login")
    if principal and compte["role"] != "principal":
        raise HTTPException(403, detail="Réservé à l'administrateur principal")
    return compte, None


def _autoriser_gestion(compte, createur_id):
    if compte["role"] != "principal" and createur_id != int(compte["id"]):
        raise HTTPException(403, detail="Action réservée au créateur ou au principal")


def _rendu(requete, nom, *, compte=None, statut=200, **contexte):
    secret = _secret(requete)
    token = requete.cookies.get(CSRF, "")
    contenu_token = _csrf_contenu(token, secret) if token and len(token) < 512 else None
    session = _lire_session(requete, secret)
    identifiant_session = session["i"] if session else 0
    version_session = session["v"] if session else 0
    valide = bool(contenu_token and contenu_token["i"] == identifiant_session
                  and contenu_token["v"] == version_session)
    if not valide:
        token = _jeton_csrf(secret, compte)
    html = modeles.get_template(nom).render(
        csrf_token=token, is_admin=compte is not None,
        is_owner=bool(compte and compte["role"] == "principal"),
        admin_id=int(compte["id"]) if compte else None,
        admin_username=compte["identifiant"] if compte else None,
        **contexte,
    )
    reponse = HTMLResponse(html, status_code=statut)
    if not valide:
        reponse.set_cookie(CSRF, token, max_age=DUREE_SESSION,
                           secure=True, httponly=True, samesite="lax", path="/")
    return reponse


def _scrutin(ligne):
    debut, fin = _utc(ligne.get("debut_utc")), _utc(ligne.get("fin_utc"))
    now = datetime.now(timezone.utc)
    if int(ligne.get("ferme_manuellement") or 0):
        phase = "ended"
    elif not debut or not fin:
        phase = "invalid"
    elif fin <= now:
        phase = "ended"
    elif now < debut:
        phase = "upcoming"
    else:
        phase = "open"
    return {
        "id": int(ligne["id"]), "ag_id": int(ligne["assemblee_id"]) if ligne.get("assemblee_id") is not None else None,
        "created_by": int(ligne["cree_par"]) if ligne.get("cree_par") is not None else None,
        "title": str(ligne["titre"]),
        "description": str(ligne.get("description") or ""),
        "starts_at": int(debut.timestamp()) if debut else None,
        "ends_at": int(fin.timestamp()) if fin else None,
        "phase": phase,
    }



def _entier_formulaire(valeur, nom):
    texte = str(valeur or "")
    if not re.fullmatch(r"[0-9]{1,16}", texte):
        raise HTTPException(400, detail=f"{nom} invalide")
    nombre = int(texte)
    if nombre < 1 or nombre > 9_007_199_254_740_991:
        raise HTTPException(400, detail=f"{nom} invalide")
    return nombre

def _horaires(formulaire):
    try:
        raw_start=str(formulaire.get("starts_at", "") or "").strip()
        raw_end=str(formulaire.get("ends_at", "") or "").strip()
        pattern=r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}"
        if not re.fullmatch(pattern,raw_start) or not re.fullmatch(pattern,raw_end):
            return None
        a=datetime.strptime(raw_start,"%Y-%m-%dT%H:%M")
        b=datetime.strptime(raw_end,"%Y-%m-%dT%H:%M")
        def date(value):
            first=value.replace(tzinfo=PARIS,fold=0)
            second=value.replace(tzinfo=PARIS,fold=1)
            utc_first=first.astimezone(timezone.utc)
            utc_second=second.astimezone(timezone.utc)
            valid_first=utc_first.astimezone(PARIS).replace(tzinfo=None)==value
            valid_second=utc_second.astimezone(PARIS).replace(tzinfo=None)==value
            if not valid_first and not valid_second:
                raise ValueError("heure inexistante")
            if valid_first and valid_second and first.utcoffset()!=second.utcoffset():
                raise ValueError("heure ambigu?")
            return utc_first if valid_first else utc_second
        debut,fin=date(a),date(b)
        if debut>=fin or fin<=datetime.now(timezone.utc):
            return None
        def iso(value):
            return value.isoformat(timespec="seconds").replace("+00:00","Z")
        return iso(debut),iso(fin)
    except (ValueError,TypeError,OverflowError):
        return None


async def _verifie_mdp(mot_de_passe: str, valeur: str):
    """PBKDF2 natif WebCrypto, compatible avec le format de app.py.

    Évite de calculer 390 000 itérations en Python interprété.
    """
    try:
        alg, iterations, hex_sel, hex_attendu = valeur.split("$")
        n = int(iterations)
        if alg != "pbkdf2_sha256" or not ITERATIONS_MIN <= n <= ITERATIONS_MAX:
            return False
        sel = bytes.fromhex(hex_sel)
        attendu = bytes.fromhex(hex_attendu)
        if len(sel) != 16 or len(attendu) != 32:
            return False
    except (ValueError, AttributeError):
        return False
    from js import crypto, TextEncoder, Uint8Array, Object
    from pyodide.ffi import to_js
    encoder = TextEncoder.new()
    cle = await crypto.subtle.importKey("raw", encoder.encode(mot_de_passe),
                                       "PBKDF2", False, to_js(["deriveBits"]))
    algorithme = to_js({"name": "PBKDF2", "hash": "SHA-256",
                      "salt": to_js(sel), "iterations": n},
                      dict_converter=Object.fromEntries)
    bits = await crypto.subtle.deriveBits(algorithme, cle, 256)
    obtenu = bytes(Uint8Array.new(bits).to_py())
    return hmac.compare_digest(obtenu, attendu)


async def _hash_mdp(mot_de_passe):
    # Pour les créations et changements de comptes en ligne.
    from js import crypto, TextEncoder, Uint8Array, Object
    from pyodide.ffi import to_js
    sel = secrets.token_bytes(16)
    cle = await crypto.subtle.importKey("raw", TextEncoder.new().encode(mot_de_passe),
                                       "PBKDF2", False, to_js(["deriveBits"]))
    options = to_js({"name": "PBKDF2", "hash": "SHA-256",
                     "salt": to_js(sel), "iterations": ITERATIONS_COURANTES},
                     dict_converter=Object.fromEntries)
    bits = await crypto.subtle.deriveBits(options, cle, 256)
    empreinte = bytes(Uint8Array.new(bits).to_py())
    return f"pbkdf2_sha256${ITERATIONS_COURANTES}${sel.hex()}${empreinte.hex()}"


def _iterations_mdp(valeur):
    try:
        algorithme, iterations, *_ = valeur.split("$")
        return int(iterations) if algorithme == "pbkdf2_sha256" else 0
    except (AttributeError, TypeError, ValueError):
        return 0


def _portees(requete, identifiant, secret):
    return [(_signature(secret, f"login-ip:{_ip_normalisee(requete)}".encode()), 30)]


def _ip_normalisee(requete):
    ip = requete.headers.get("cf-connecting-ip") or (requete.client.host if requete.client else "unknown")
    try:
        adresse = ipaddress.ip_address(ip)
        if isinstance(adresse, ipaddress.IPv6Address):
            return f"{ipaddress.ip_network(f'{adresse}/64', strict=False).network_address}/64"
        return str(adresse)
    except ValueError:
        return "unknown"


async def _limite(bdd, portees):
    now = int(time.time())
    for portee, seuil in portees:
        ligne = _objet(await bdd.prepare(
            "SELECT debut_fenetre, echecs FROM limites_connexion WHERE empreinte=?"
        ).bind(portee).first())
        if ligne and now - int(ligne["debut_fenetre"]) < DUREE_LIMITE and int(ligne["echecs"]) >= seuil:
            return True
    return False


async def _echec(bdd, portees):
    now = int(time.time())
    statement = f"""INSERT INTO limites_connexion (empreinte, debut_fenetre, echecs)
                   VALUES (?, ?, 1)
                   ON CONFLICT(empreinte) DO UPDATE SET
                   echecs=CASE WHEN excluded.debut_fenetre-limites_connexion.debut_fenetre>={DUREE_LIMITE}
                          THEN 1 ELSE limites_connexion.echecs+1 END,
                   debut_fenetre=CASE WHEN excluded.debut_fenetre-limites_connexion.debut_fenetre>={DUREE_LIMITE}
                          THEN excluded.debut_fenetre ELSE limites_connexion.debut_fenetre END"""
    operations = [bdd.prepare("DELETE FROM limites_connexion WHERE debut_fenetre < ?").bind(now - DUREE_LIMITE)]
    operations.extend(bdd.prepare(statement).bind(p, now) for p, _ in portees)
    await bdd.batch(operations)


@app.get("/health")
async def etat(requete: Request):
    await _bdd(requete).prepare("SELECT 1").run()
    return {"status": "ok"}


def _ag(ligne):
    return {
        "id": int(ligne["id"]), "title": str(ligne["titre"]),
        "created_by": int(ligne["cree_par"]) if ligne.get("cree_par") is not None else None,
        "description": str(ligne.get("description") or ""),
        "total_sujets": int(ligne.get("total_sujets") or 0),
        "total_codes": int(ligne.get("total_codes") or 0),
    }


async def _ag_detail(requete, id_ag):
    ligne = _objet(await _bdd(requete).prepare(
        "SELECT id,titre,description,cree_par FROM assemblees WHERE id=?"
    ).bind(id_ag).first())
    if ligne is None:
        raise HTTPException(404, detail="AG introuvable")
    return _ag(ligne)


def _empreinte_code_ag(secret: bytes, ag_id: int, code: str) -> str:
    return "v1$" + _signature(secret, f"ag-code:{ag_id}:{code}".encode())


def _empreinte_code_legacy(secret: bytes, ag_id: int, code: str) -> str:
    return _signature(secret, f"ag-code:{ag_id}:{code}".encode())


def _cookie_ag(ag_id):
    return f"__Host-ag-access-{int(ag_id)}"


def _creer_acces_ag(secret: bytes, ag_id: int, jeton_acces: str) -> str:
    donnees = {"a": ag_id, "c": jeton_acces, "e": int(time.time()) + DUREE_ACCES_AG,
               "n": secrets.token_urlsafe(12)}
    brut = json.dumps(donnees, separators=(",", ":")).encode()
    enc = base64.urlsafe_b64encode(brut).rstrip(b"=").decode()
    return enc + "." + _signature(secret, b"ag-access:" + enc.encode())


async def _acces_ag(requete: Request, ag_id: int):
    cookie = requete.cookies.get(_cookie_ag(ag_id), "")
    if not cookie or len(cookie) > 1024:
        return None
    try:
        enc, sig = cookie.rsplit(".", 1)
        if not hmac.compare_digest(sig.encode(), _signature(_secret(requete), b"ag-access:" + enc.encode()).encode()):
            return None
        donnees = json.loads(base64.urlsafe_b64decode(enc + "=" * (-len(enc) % 4)))
        if (type(donnees.get("a")) is not int or not isinstance(donnees.get("c"), str)
                or type(donnees.get("e")) is not int or donnees["a"] != ag_id
                or donnees["e"] <= int(time.time())):
            return None
        jeton = donnees["c"]
    except (KeyError, ValueError, UnicodeError, TypeError, OverflowError):
        return None
    ligne = await _bdd(requete).prepare(
        "SELECT id FROM ag_codes WHERE jeton_acces=? AND assemblee_id=? "
        "AND revoque_le IS NULL AND (expire_le IS NULL OR expire_le>?)"
    ).bind(jeton, ag_id, int(time.time())).first()
    return int(ligne["id"]) if ligne is not None else None


def _retour_ag(id_ag):
    return _lien(f"/ag/{id_ag}")


@app.get("/")
async def accueil(requete: Request):
    compte = await _compte(requete)
    lignes = await _bdd(requete).prepare("""
        SELECT a.id,a.titre,a.description,
          (SELECT count(*) FROM scrutins s WHERE s.assemblee_id=a.id) AS total_sujets
        FROM assemblees a ORDER BY a.cree_le DESC,a.id DESC
    """).all()
    ags = [_ag(x) for x in _lignes(lignes)]
    return _rendu(requete, "home.html", compte=compte, ags=ags)


@app.get("/polls/{id_sujet}")
async def ancien_lien_sujet(requete: Request, id_sujet: Annotated[int, PathParam(ge=1, le=9_007_199_254_740_991)]):
    ligne = _objet(await _bdd(requete).prepare(
        "SELECT assemblee_id FROM scrutins WHERE id=?"
    ).bind(id_sujet).first())
    if not ligne or ligne.get("assemblee_id") is None:
        raise HTTPException(404, detail="Sujet introuvable")
    return _retour_ag(int(ligne["assemblee_id"]))


@app.get("/ag/{id_ag}")
async def page_ag(requete: Request, id_ag: Annotated[int, PathParam(ge=1, le=9_007_199_254_740_991)]):
    ag = await _ag_detail(requete, id_ag)
    compte = await _compte(requete)
    code_id = await _acces_ag(requete, id_ag)
    if code_id is None:
        return _rendu(requete, "ag_access.html", compte=compte, ag=ag)
    lignes = await _bdd(requete).prepare("""
        SELECT s.id,s.assemblee_id,s.titre,s.description,s.debut_utc,s.fin_utc,
               s.ferme_manuellement,
               EXISTS(SELECT 1 FROM ag_emargements v
                      WHERE v.scrutin_id=s.id AND v.code_id=?) AS deja_vote
        FROM scrutins s WHERE s.assemblee_id=? ORDER BY s.cree_le,s.id
    """).bind(code_id, id_ag).all()
    sujets = []
    for ligne in _lignes(lignes):
        sujet = _scrutin(ligne)
        sujet["deja_vote"] = bool(ligne["deja_vote"])
        sujets.append(sujet)
    return _rendu(requete, "ag_topics.html", compte=compte, ag=ag, polls=sujets,
                  voted=requete.query_params.get("voted") == "1",
                  already=requete.query_params.get("already") == "1",
                  unavailable=requete.query_params.get("unavailable") == "1")


def _portees_code_ag(requete: Request, secret: bytes, id_ag: Annotated[int, PathParam(ge=1, le=9_007_199_254_740_991)]):
    ip = _ip_normalisee(requete)
    # Une limite par AG permettrait à un seul visiteur de bloquer tous les électeurs.
    return [(_signature(secret, f"ag-ip:{id_ag}:{ip}".encode()), 12)]


@app.post("/ag/{id_ag}/access")
async def entrer_ag(requete: Request, id_ag: Annotated[int, PathParam(ge=1, le=9_007_199_254_740_991)]):
    ag = await _ag_detail(requete, id_ag)
    secret = _secret(requete)
    form = await requete.form()
    _csrf_valide(requete, secret, form)
    code = str(form.get("code", "")).strip()
    bdd = _bdd(requete)
    portees = _portees_code_ag(requete, secret, id_ag)
    if await _limite(bdd, portees):
        return _rendu(requete, "ag_access.html", statut=429,
                      ag=await _ag_detail(requete, id_ag),
                      error="Trop de tentatives. Réessayez dans 15 minutes.")
    ligne = None
    if re.fullmatch(r"(?:[0-9]{10}|[0-9]{12})", code):
        empreinte_nouvelle = _empreinte_code_ag(_secret_codes(requete), id_ag, code)
        empreinte_ancienne = _empreinte_code_legacy(_secret_legacy_codes(requete), id_ag, code)
        ligne = _objet(await bdd.prepare(
            "SELECT id,jeton_acces FROM ag_codes WHERE assemblee_id=? AND empreinte_code IN (?,?) "
            "AND revoque_le IS NULL AND (expire_le IS NULL OR expire_le>?)"
        ).bind(id_ag, empreinte_nouvelle, empreinte_ancienne, int(time.time())).first())
    if ligne is None:
        await _echec(bdd, portees)
        return _rendu(requete, "ag_access.html", statut=401,
                      ag=await _ag_detail(requete, id_ag),
                      error="Code d'accès invalide.")
    reponse = _retour_ag(id_ag)
    reponse.set_cookie(_cookie_ag(id_ag), _creer_acces_ag(secret, id_ag, ligne["jeton_acces"]),
                       max_age=DUREE_ACCES_AG, httponly=True,
                       secure=True, samesite="lax", path="/")
    return reponse


@app.post("/ag/{id_ag}/exit")
async def quitter_ag(requete: Request, id_ag: Annotated[int, PathParam(ge=1, le=9_007_199_254_740_991)]):
    form = await requete.form()
    _csrf_valide(requete, _secret(requete), form)
    reponse = _lien("/")
    reponse.delete_cookie(_cookie_ag(id_ag), path="/", secure=True, httponly=True, samesite="lax")
    return reponse


@app.get("/ag/{id_ag}/vote/{id_sujet}")
async def page_vote_ag(requete: Request, id_ag: Annotated[int, PathParam(ge=1, le=9_007_199_254_740_991)], id_sujet: Annotated[int, PathParam(ge=1, le=9_007_199_254_740_991)]):
    code_id = await _acces_ag(requete, id_ag)
    if code_id is None:
        return _retour_ag(id_ag)
    ag = await _ag_detail(requete, id_ag)
    ligne = _objet(await _bdd(requete).prepare(
        "SELECT id,assemblee_id,titre,description,debut_utc,fin_utc,ferme_manuellement "
        "FROM scrutins WHERE id=? AND assemblee_id=?"
    ).bind(id_sujet, id_ag).first())
    if ligne is None:
        raise HTTPException(404, detail="Sujet introuvable dans cette AG")
    sujet = _scrutin(ligne)
    dej = await _bdd(requete).prepare(
        "SELECT code_id FROM ag_emargements WHERE code_id=? AND scrutin_id=?"
    ).bind(code_id, id_sujet).first()
    options = _lignes(await _bdd(requete).prepare(
        "SELECT id,intitule FROM choix WHERE scrutin_id=? ORDER BY position"
    ).bind(id_sujet).all())
    resultats = None
    if sujet["phase"] == "ended":
        # Résultats uniquement après la clôture, votes historiques inclus.
        comptes = _lignes(await _bdd(requete).prepare("""
            SELECT c.id,c.intitule,
              ((SELECT count(*) FROM votes v WHERE v.choix_id=c.id AND v.scrutin_id=?)
              +(SELECT count(*) FROM ag_bulletins v WHERE v.choix_id=c.id AND v.scrutin_id=?)) AS total
            FROM choix c WHERE c.scrutin_id=? ORDER BY c.position
        """).bind(id_sujet, id_sujet, id_sujet).all())
        resultats = comptes
    return _rendu(requete, "ag_vote.html", ag=ag, poll=sujet, options=options,
                  deja_vote=dej is not None, resultats=resultats)


@app.post("/ag/{id_ag}/vote/{id_sujet}")
async def enregistrer_vote_ag(requete: Request, id_ag: Annotated[int, PathParam(ge=1, le=9_007_199_254_740_991)], id_sujet: Annotated[int, PathParam(ge=1, le=9_007_199_254_740_991)]):
    code_id = await _acces_ag(requete, id_ag)
    if code_id is None:
        return _retour_ag(id_ag)
    form = await requete.form()
    _csrf_valide(requete, _secret(requete), form)
    try:
        choix_id = _entier_formulaire(form.get("option_id"), "Choix")
    except ValueError:
        raise HTTPException(400, detail="Choix invalide") from None
    # L'insertion unique, effectuée par D1, résiste aux soumissions concurrentes.
    # La vérification de l'AG et du créneau du sujet est faite en SQL,
    # dans la même instruction que l'insertion du vote.
    bdd = _bdd(requete)
    emargement = bdd.prepare("""
        INSERT OR IGNORE INTO ag_emargements(code_id,scrutin_id,assemblee_id)
        SELECT ac.id,s.id,s.assemblee_id FROM scrutins s
        JOIN choix c ON c.scrutin_id=s.id AND c.id=?
        JOIN ag_codes ac ON ac.assemblee_id=s.assemblee_id AND ac.id=?
        WHERE s.id=? AND s.assemblee_id=? AND s.ferme_manuellement=0
          AND unixepoch(s.debut_utc)<=unixepoch('now')
          AND unixepoch(s.fin_utc)>unixepoch('now')
          AND ac.revoque_le IS NULL AND (ac.expire_le IS NULL OR ac.expire_le>unixepoch('now'))
    """).bind(choix_id, code_id, id_sujet, id_ag)
    bulletin = bdd.prepare("""
        INSERT INTO ag_bulletins(bulletin_id,scrutin_id,choix_id)
        SELECT ?,s.id,c.id FROM scrutins s
        JOIN choix c ON c.scrutin_id=s.id AND c.id=?
        WHERE s.id=? AND s.assemblee_id=? AND changes()=1
    """).bind(secrets.token_hex(24), choix_id, id_sujet, id_ag)
    resultats = await bdd.batch([emargement, bulletin])
    if int(resultats[0].meta.changes) < 1:
        scrutin = _objet(await bdd.prepare(
            "SELECT id,assemblee_id,titre,description,debut_utc,fin_utc,ferme_manuellement FROM scrutins WHERE id=? AND assemblee_id=?"
        ).bind(id_sujet,id_ag).first())
        if scrutin is None:
            raise HTTPException(404,detail="Sujet introuvable")
        deja_vote = await bdd.prepare(
            "SELECT 1 FROM ag_emargements WHERE code_id=? AND scrutin_id=?"
        ).bind(code_id,id_sujet).first()
        if deja_vote is not None:
            return _lien(f"/ag/{id_ag}?already=1")
        if _scrutin(scrutin)["phase"] != "open":
            return _lien(f"/ag/{id_ag}?unavailable=1")
        return _lien(f"/ag/{id_ag}?already=1")
    return _lien(f"/ag/{id_ag}?voted=1")


@app.get("/admin/login")
async def page_connexion(requete: Request):
    compte = await _compte(requete)
    if compte:
        return _lien("/admin")
    return _rendu(requete, "login.html")


@app.post("/admin/login")
async def connexion(requete: Request):
    secret = _secret(requete)
    formulaire = await requete.form()
    _csrf_valide(requete, secret, formulaire)
    identifiant = str(formulaire.get("username", "")).strip()
    mot_de_passe = str(formulaire.get("password", ""))
    if len(identifiant) > 64 or len(mot_de_passe) > 512:
        raise HTTPException(400, detail="Données incorrectes")
    bdd = _bdd(requete)
    portees = _portees(requete, identifiant, secret)
    if await _limite(bdd, portees):
        return _rendu(requete, "login.html", statut=429,
                      error="Trop de tentatives. Réessayez dans 15 minutes.")
    compte = _objet(await bdd.prepare(
        "SELECT id, identifiant, mot_de_passe_hash, role, auth_version "
        "FROM administrateurs WHERE lower(identifiant)=lower(?)"
    ).bind(identifiant).first())
    valide = False
    empreinte_verifiee = compte["mot_de_passe_hash"] if compte else (
        "pbkdf2_sha256$100000$" + "00" * 16 + "$" + "00" * 32)
    valide = await _verifie_mdp(mot_de_passe or "\x00", empreinte_verifiee)
    valide = bool(compte and valide)
    if not valide:
        await _echec(bdd, portees)
        return _rendu(requete, "login.html", statut=401,
                      error="Identifiant ou mot de passe incorrect.")
    if _iterations_mdp(compte["mot_de_passe_hash"]) < ITERATIONS_COURANTES:
        nouvelle_empreinte = await _hash_mdp(mot_de_passe)
        await bdd.prepare(
            "UPDATE administrateurs SET mot_de_passe_hash=? WHERE id=? AND mot_de_passe_hash=?"
        ).bind(nouvelle_empreinte, int(compte["id"]), compte["mot_de_passe_hash"]).run()
    # Supprimer seulement les échecs de cet identifiant ; une IP à attaques
    # multiples reste temporairement limitée par son compteur.
    reponse = _lien("/admin")
    reponse.set_cookie(SESSION, _creer_session(secret, compte),
                       max_age=DUREE_SESSION, httponly=True,
                       secure=True, samesite="lax", path="/")
    csrf = _jeton_csrf(secret, compte)
    reponse.set_cookie(CSRF, csrf, max_age=DUREE_SESSION, httponly=True,
                       secure=True, samesite="lax", path="/")
    return reponse


@app.post("/admin/logout")
async def deconnexion(requete: Request):
    form = await requete.form()
    _csrf_valide(requete, _secret(requete), form)
    compte = await _compte(requete)
    if compte:
        await _bdd(requete).prepare(
            "UPDATE administrateurs SET auth_version=auth_version+1 WHERE id=?"
        ).bind(int(compte["id"])).run()
    reponse = _lien("/")
    reponse.delete_cookie(SESSION, path="/", secure=True, httponly=True, samesite="lax")
    reponse.delete_cookie(CSRF, path="/", secure=True, httponly=True, samesite="lax")
    return reponse


@app.get("/admin")
async def tableau_bord(requete: Request):
    compte, refus = await _auth(requete)
    if refus:
        return refus
    lignes = await _bdd(requete).prepare("""
        SELECT a.id,a.titre,a.description,
          (SELECT count(*) FROM scrutins s WHERE s.assemblee_id=a.id) AS total_sujets,
          (SELECT count(*) FROM ag_codes c WHERE c.assemblee_id=a.id) AS total_codes
        FROM assemblees a ORDER BY a.cree_le DESC,a.id DESC
    """).all()
    return _rendu(requete, "dashboard.html", compte=compte,
                  ags=[_ag(x) for x in _lignes(lignes)],
                  deleted_ag=requete.query_params.get("deleted_ag") == "1",
                  deleted=requete.query_params.get("deleted") == "1")


@app.get("/admin/ags/new")
async def page_creation_ag(requete: Request):
    compte, refus = await _auth(requete)
    if refus:
        return refus
    return _rendu(requete, "ag_new.html", compte=compte)


@app.post("/admin/ags/new")
async def creer_ag(requete: Request):
    compte, refus = await _auth(requete)
    if refus:
        return refus
    form = await requete.form()
    _csrf_valide(requete, _secret(requete), form)
    titre = str(form.get("title", "")).strip()
    description = str(form.get("description", "")).strip()
    if not (3 <= len(titre) <= 140 and len(description) <= 600):
        return _rendu(requete, "ag_new.html", compte=compte, statut=400,
                      titre=titre, description=description,
                      error="Titre ou description invalide.")
    bdd=_bdd(requete)
    for _ in range(5):
        id_ag = secrets.randbelow(2**52 - 2**40) + 2**40
        operations=await bdd.batch([
            bdd.prepare("INSERT OR IGNORE INTO assemblees (id,titre,description,cree_par) VALUES (?,?,?,?)").bind(id_ag,titre,description,int(compte["id"])),
            bdd.prepare("INSERT INTO journal_admin(admin_id,action,cible_type,cible_id) SELECT ?,'create_ag','ag',? WHERE changes()=1").bind(int(compte["id"]),str(id_ag)),
        ])
        if int(operations[0].meta.changes)==1:
            return _lien(f"/admin/ags/{id_ag}?created=1")
    raise HTTPException(503,detail="Cr?ation de l'AG indisponible")


@app.get("/admin/ags/{id_ag}")
async def gerer_ag(requete: Request, id_ag: Annotated[int, PathParam(ge=1, le=9_007_199_254_740_991)]):
    compte, refus = await _auth(requete)
    if refus:
        return refus
    ag = await _ag_detail(requete, id_ag)
    _autoriser_gestion(compte, ag.get("created_by"))
    lignes = await _bdd(requete).prepare("""
        SELECT s.id,s.assemblee_id,s.titre,s.description,s.debut_utc,s.fin_utc,s.ferme_manuellement,s.cree_par
        FROM scrutins s WHERE s.assemblee_id=? ORDER BY s.cree_le DESC,s.id DESC
    """).bind(id_ag).all()
    sujets = [_scrutin(l) for l in _lignes(lignes)]
    nombres = _objet(await _bdd(requete).prepare(
        "SELECT count(*) AS total FROM ag_codes WHERE assemblee_id=?"
    ).bind(id_ag).first())
    codes = _lignes(await _bdd(requete).prepare(
        "SELECT id,cree_le,expire_le,revoque_le FROM ag_codes WHERE assemblee_id=? ORDER BY cree_le DESC"
    ).bind(id_ag).all())
    return _rendu(requete, "ag_manage.html", compte=compte, ag=ag, polls=sujets,
                  total_codes=int(nombres["total"]), codes=codes,
                  created=requete.query_params.get("created") == "1",
                  code_revoked=requete.query_params.get("code_revoked") == "1")


@app.post("/admin/ags/{id_ag}/codes")
async def generer_code_ag(requete: Request, id_ag: Annotated[int, PathParam(ge=1, le=9_007_199_254_740_991)]):
    compte, refus = await _auth(requete)
    if refus:
        return refus
    form = await requete.form()
    _csrf_valide(requete, _secret(requete), form)
    ag = await _ag_detail(requete, id_ag)
    _autoriser_gestion(compte, ag.get("created_by"))
    secret = _secret(requete)
    bdd = _bdd(requete)
    for _ in range(5):
        code = f"{secrets.randbelow(10**12):012d}"
        empreinte = _empreinte_code_ag(_secret_codes(requete), id_ag, code)
        id_code = secrets.randbelow(2**52 - 2**40) + 2**40
        jeton = secrets.token_hex(24)
        nonce = secrets.token_urlsafe(24)
        expiration = int(time.time()) + 90 * 24 * 60 * 60
        operations = await bdd.batch([
            bdd.prepare("""INSERT OR IGNORE INTO ag_codes
                (id,assemblee_id,empreinte_code,jeton_acces,expire_le,revelation_hash)
                VALUES (?,?,?,?,?,?)""").bind(id_code,id_ag,empreinte,jeton,expiration,
                    _signature(secret,("code-reveal:"+nonce).encode())),
            bdd.prepare("""INSERT INTO journal_admin(admin_id,action,cible_type,cible_id)
                SELECT ?, 'create_code', 'ag_code', ? WHERE changes()=1""").bind(
                    int(compte["id"]), str(id_code)),
        ])
        if int(operations[0].meta.changes) != 1:
            continue
        payload={"a":id_ag,"c":code,"i":id_code,"e":int(time.time())+300,"n":nonce}
        enc=base64.urlsafe_b64encode(json.dumps(payload,separators=(",",":")).encode()).rstrip(b"=").decode()
        value=enc+"."+_signature(secret,b"reveal:"+enc.encode())
        response=_lien(f"/admin/ags/{id_ag}/codes/reveal")
        response.set_cookie(COOKIE_CODE_REVEAL,value,max_age=300,secure=True,httponly=True,samesite="strict",path="/")
        return response
    raise HTTPException(503, detail="G?n?ration de code indisponible")


@app.get("/admin/ags/{id_ag}/codes/reveal")
async def reveler_code_ag(requete: Request, id_ag: Annotated[int, PathParam(ge=1, le=9_007_199_254_740_991)]):
    compte, refus = await _auth(requete)
    if refus:
        return refus
    secret=_secret(requete)
    cookie=requete.cookies.get(COOKIE_CODE_REVEAL,"")
    try:
        enc,signature=cookie.rsplit(".",1)
        if not hmac.compare_digest(signature.encode(),_signature(secret,b"reveal:"+enc.encode()).encode()):
            raise ValueError
        payload=json.loads(base64.urlsafe_b64decode(enc+"="*(-len(enc)%4)))
        if payload["a"] != id_ag or payload["e"] < int(time.time()) or not re.fullmatch(r"[0-9]{12}",payload["c"]):
            raise ValueError
        nonce_hash=_signature(secret,("code-reveal:"+payload["n"]).encode())
        code_row=await _bdd(requete).prepare(
            "SELECT id FROM ag_codes WHERE id=? AND assemblee_id=? AND revelation_hash=?"
        ).bind(payload["i"],id_ag,nonce_hash).first()
        if code_row is None:
            raise ValueError
    except (ValueError,KeyError,TypeError,UnicodeError,AttributeError):
        raise HTTPException(404,detail="Code indisponible") from None
    response=_rendu(requete,"ag_code_generated.html",compte=compte,
                    ag=await _ag_detail(requete,id_ag),code=payload["c"])
    consumed=await _bdd(requete).prepare(
        "UPDATE ag_codes SET revelation_hash=NULL WHERE id=? AND assemblee_id=? AND revelation_hash=?"
    ).bind(payload["i"],id_ag,nonce_hash).run()
    if int(consumed.meta.changes)!=1:
        raise HTTPException(404,detail="Code indisponible")
    response.delete_cookie(COOKIE_CODE_REVEAL,path="/",secure=True,httponly=True,samesite="strict")
    return response


@app.post("/admin/ags/{id_ag}/codes/{id_code}/revoke")
async def revoquer_code_ag(requete: Request, id_ag: Annotated[int, PathParam(ge=1, le=9_007_199_254_740_991)], id_code: Annotated[int, PathParam(ge=1, le=9_007_199_254_740_991)]):
    compte, refus = await _auth(requete)
    if refus:
        return refus
    form=await requete.form()
    _csrf_valide(requete,_secret(requete),form)
    ag=await _ag_detail(requete,id_ag)
    _autoriser_gestion(compte,ag.get("created_by"))
    bdd=_bdd(requete)
    resultats=await bdd.batch([
        bdd.prepare("UPDATE ag_codes SET revoque_le=unixepoch('now') WHERE id=? AND assemblee_id=? AND revoque_le IS NULL").bind(id_code,id_ag),
        bdd.prepare("INSERT INTO journal_admin(admin_id,action,cible_type,cible_id) SELECT ?,'revoke_code','ag_code',? WHERE changes()=1").bind(int(compte["id"]),str(id_code)),
    ])
    if int(resultats[0].meta.changes)!=1:
        raise HTTPException(404,detail="Code introuvable ou d?j? r?voqu?")
    return _lien(f"/admin/ags/{id_ag}?code_revoked=1")


@app.post("/admin/ags/{id_ag}/delete")
async def supprimer_ag(requete: Request, id_ag: Annotated[int, PathParam(ge=1, le=9_007_199_254_740_991)]):
    compte, refus = await _auth(requete)
    if refus:
        return refus
    ag = await _ag_detail(requete, id_ag)
    _autoriser_gestion(compte, ag.get("created_by"))
    form = await requete.form()
    _csrf_valide(requete, _secret(requete), form)
    if not hmac.compare_digest(str(form.get("confirmation_titre", "")).encode(), ag["title"].encode()):
        raise HTTPException(400, detail="Titre de confirmation incorrect")
    bdd=_bdd(requete)
    resultats=await bdd.batch([
        bdd.prepare("DELETE FROM ag_bulletins WHERE scrutin_id IN (SELECT id FROM scrutins WHERE assemblee_id=?)").bind(id_ag),
        bdd.prepare("DELETE FROM ag_emargements WHERE assemblee_id=?").bind(id_ag),
        bdd.prepare("DELETE FROM votes WHERE scrutin_id IN (SELECT id FROM scrutins WHERE assemblee_id=?)").bind(id_ag),
        bdd.prepare("DELETE FROM codes_vote WHERE scrutin_id IN (SELECT id FROM scrutins WHERE assemblee_id=?)").bind(id_ag),
        bdd.prepare("DELETE FROM choix WHERE scrutin_id IN (SELECT id FROM scrutins WHERE assemblee_id=?)").bind(id_ag),
        bdd.prepare("DELETE FROM scrutins WHERE assemblee_id=?").bind(id_ag),
        bdd.prepare("DELETE FROM ag_codes WHERE assemblee_id=?").bind(id_ag),
        bdd.prepare("DELETE FROM assemblees WHERE id=?").bind(id_ag),
        bdd.prepare("INSERT INTO journal_admin(admin_id,action,cible_type,cible_id) VALUES (?,'delete_ag','ag',?)").bind(int(compte["id"]),str(id_ag)),
    ])
    if int(resultats[7].meta.changes) != 1:
        raise HTTPException(409,detail="AG introuvable ou modifi?e")
    return _lien("/admin?deleted_ag=1")


@app.get("/admin/polls/new")
async def page_creation(requete: Request):
    compte, refus = await _auth(requete)
    if refus:
        return refus
    try:
        id_ag = _entier_formulaire(requete.query_params.get("ag_id"), "AG")
    except ValueError:
        return _lien("/admin")
    ag = await _ag_detail(requete, id_ag)
    _autoriser_gestion(compte, ag.get("created_by"))
    return _rendu(requete, "new_poll.html", compte=compte, ag=ag)


@app.post("/admin/polls/new")
async def creer_scrutin(requete: Request):
    compte, refus = await _auth(requete)
    if refus:
        return refus
    form = await requete.form()
    _csrf_valide(requete, _secret(requete), form)
    try:
        id_ag = _entier_formulaire(form.get("ag_id"), "AG")
    except ValueError:
        raise HTTPException(400, detail="AG invalide") from None
    ag = await _ag_detail(requete, id_ag)
    _autoriser_gestion(compte, ag.get("created_by"))
    titre = str(form.get("title", "")).strip()
    description = str(form.get("description", "")).strip()
    propositions = [p.strip() for p in str(form.get("options", "")).splitlines() if p.strip()]
    horaires = _horaires(form)
    if not (3 <= len(titre) <= 140 and len(description) <= 600
            and 2 <= len(propositions) <= 10
            and all(len(p) <= 140 for p in propositions)
            and len({p.casefold() for p in propositions}) == len(propositions)
            and horaires):
        return _rendu(requete, "new_poll.html", compte=compte, ag=ag, statut=400,
                      title_value=titre, description_value=description,
                      options_value="\n".join(propositions),
                      starts_value=str(form.get("starts_at", "") or ""),
                      ends_value=str(form.get("ends_at", "") or ""),
                      error="Vérifiez le titre, les réponses et les dates (fin future après début).")
    debut, fin = horaires
    bdd = _bdd(requete)
    for _ in range(5):
        id_scrutin = secrets.randbelow(2**52 - 2**40) + 2**40
        statements = [bdd.prepare("""INSERT OR IGNORE INTO scrutins
            (id,assemblee_id,titre,description,debut_utc,fin_utc,cree_par)
            VALUES (?,?,?,?,?,?,?)""").bind(id_scrutin,id_ag,titre,description,debut,fin,int(compte["id"]))]
        for position, libelle in enumerate(propositions):
            statements.append(bdd.prepare("""INSERT INTO choix(scrutin_id,intitule,position)
                SELECT ?,?,? WHERE changes()=1""").bind(id_scrutin,libelle,position))
        statements.append(bdd.prepare("""INSERT INTO journal_admin(admin_id,action,cible_type,cible_id)
            SELECT ?,'create_poll','poll',? WHERE changes()=1""").bind(int(compte["id"]),str(id_scrutin)))
        resultats=await bdd.batch(statements)
        if int(resultats[0].meta.changes)==1:
            return _lien(f"/admin/polls/{id_scrutin}?created=1")
    raise HTTPException(503,detail="Cr?ation du scrutin indisponible")


async def _detail_scrutin(requete, id_sujet):
    ligne = _objet(await _bdd(requete).prepare(
        "SELECT id,assemblee_id,cree_par,titre,description,debut_utc,fin_utc,ferme_manuellement FROM scrutins WHERE id=?"
    ).bind(id_sujet).first())
    if ligne is None:
        raise HTTPException(404, detail="Scrutin introuvable")
    return _scrutin(ligne)


@app.get("/admin/polls/{id_sujet}")
async def detail_scrutin(requete: Request, id_sujet: Annotated[int, PathParam(ge=1, le=9_007_199_254_740_991)]):
    compte, refus = await _auth(requete)
    if refus:
        return refus
    scrutin = await _detail_scrutin(requete, id_sujet)
    _autoriser_gestion(compte, scrutin.get("created_by"))
    resultat = await _bdd(requete).prepare(
        "SELECT id,intitule,position FROM choix WHERE scrutin_id=? ORDER BY position"
    ).bind(id_sujet).all()
    options = _lignes(resultat)
    resultats = None
    if scrutin["phase"] == "ended":
        resultats = _lignes(await _bdd(requete).prepare("""
            SELECT c.intitule,
              ((SELECT count(*) FROM votes v WHERE v.choix_id=c.id AND v.scrutin_id=?)
              +(SELECT count(*) FROM ag_bulletins v WHERE v.choix_id=c.id AND v.scrutin_id=?)) AS total
            FROM choix c WHERE c.scrutin_id=? ORDER BY c.position
        """).bind(id_sujet,id_sujet,id_sujet).all())
    return _rendu(requete, "poll_manage.html", compte=compte, poll=scrutin,
                  ag=await _ag_detail(requete, scrutin["ag_id"]), options=options,
                  resultats=resultats, phase=scrutin["phase"],
                  created=requete.query_params.get("created") == "1",
                  schedule_saved=requete.query_params.get("schedule_saved") == "1",
                  closed=requete.query_params.get("closed") == "1")


@app.post("/admin/polls/{id_sujet}/schedule")
async def changer_dates(requete: Request, id_sujet: Annotated[int, PathParam(ge=1, le=9_007_199_254_740_991)]):
    compte, refus = await _auth(requete)
    if refus:
        return refus
    form = await requete.form()
    _csrf_valide(requete, _secret(requete), form)
    horaires = _horaires(form)
    if not horaires:
        raise HTTPException(400, detail="Dates invalides")
    poll = await _detail_scrutin(requete, id_sujet)
    _autoriser_gestion(compte, poll.get("created_by"))
    if poll["phase"] in ("open", "ended"):
        raise HTTPException(409, detail="Le calendrier ne peut plus ?tre modifi?")
    debut, fin = horaires
    bdd = _bdd(requete)
    resultats = await bdd.batch([
        bdd.prepare("""UPDATE scrutins SET debut_utc=?,fin_utc=? WHERE id=? AND ferme_manuellement=0
            AND (unixepoch(debut_utc)>unixepoch('now') OR unixepoch(debut_utc) IS NULL)
            AND unixepoch(fin_utc)>unixepoch('now')
            AND NOT EXISTS (SELECT 1 FROM ag_emargements WHERE scrutin_id=scrutins.id)""").bind(debut,fin,id_sujet),
        bdd.prepare("""INSERT INTO journal_admin(admin_id,action,cible_type,cible_id)
            SELECT ?,'schedule_poll','poll',? WHERE changes()=1""").bind(int(compte["id"]),str(id_sujet)),
    ])
    if int(resultats[0].meta.changes) != 1:
        raise HTTPException(409, detail="Scrutin d?marr? ou d?j? vot?")
    return _lien(f"/admin/polls/{id_sujet}?schedule_saved=1")


@app.post("/admin/polls/{id_sujet}/close")
async def fermer_scrutin(requete: Request, id_sujet: Annotated[int, PathParam(ge=1, le=9_007_199_254_740_991)]):
    compte, refus = await _auth(requete)
    if refus:
        return refus
    form = await requete.form()
    _csrf_valide(requete, _secret(requete), form)
    scrutin = await _detail_scrutin(requete, id_sujet)
    _autoriser_gestion(compte, scrutin.get("created_by"))
    if scrutin["phase"] == "invalid":
        raise HTTPException(409, detail="Dates du scrutin invalides")
    bdd = _bdd(requete)
    resultats = await bdd.batch([
        bdd.prepare("""UPDATE scrutins SET ferme_manuellement=1,ferme_par=?,
            ferme_le=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=? AND ferme_manuellement=0""").bind(int(compte["id"]),id_sujet),
        bdd.prepare("""INSERT INTO journal_admin(admin_id,action,cible_type,cible_id)
            SELECT ?,'close_poll','poll',? WHERE changes()=1""").bind(int(compte["id"]),str(id_sujet)),
    ])
    if int(resultats[0].meta.changes) != 1:
        raise HTTPException(404, detail="Scrutin introuvable ou d?j? cl?tur?")
    return _lien(f"/admin/polls/{id_sujet}?closed=1")


@app.post("/admin/polls/{id_sujet}/delete")
async def supprimer_scrutin(requete: Request, id_sujet: Annotated[int, PathParam(ge=1, le=9_007_199_254_740_991)]):
    compte, refus = await _auth(requete)
    if refus:
        return refus
    form = await requete.form()
    _csrf_valide(requete, _secret(requete), form)
    scrutin = await _detail_scrutin(requete, id_sujet)
    _autoriser_gestion(compte, scrutin.get("created_by"))
    confirmation = str(form.get("confirmation_titre", ""))
    if not hmac.compare_digest(confirmation.encode(), scrutin["title"].encode()):
        raise HTTPException(400, detail="Titre de confirmation incorrect")
    bdd = _bdd(requete)
    resultats = await bdd.batch([
        bdd.prepare("DELETE FROM ag_bulletins WHERE scrutin_id=?").bind(id_sujet),
        bdd.prepare("DELETE FROM ag_emargements WHERE scrutin_id=?").bind(id_sujet),
        bdd.prepare("DELETE FROM votes WHERE scrutin_id=?").bind(id_sujet),
        bdd.prepare("DELETE FROM codes_vote WHERE scrutin_id=?").bind(id_sujet),
        bdd.prepare("DELETE FROM choix WHERE scrutin_id=?").bind(id_sujet),
        bdd.prepare("DELETE FROM scrutins WHERE id=?").bind(id_sujet),
        bdd.prepare("INSERT INTO journal_admin(admin_id,action,cible_type,cible_id) VALUES (?,'delete_poll','poll',?)").bind(int(compte["id"]),str(id_sujet)),
    ])
    if int(resultats[5].meta.changes) != 1:
        raise HTTPException(409, detail="Scrutin introuvable ou modifi?")
    return _lien("/admin?deleted=1")


@app.get("/admin/users")
async def utilisateurs(requete: Request):
    compte, refus = await _auth(requete, principal=True)
    if refus:
        return refus
    resultat = await _bdd(requete).prepare(
        "SELECT id, identifiant AS username, "
        "CASE WHEN role='principal' THEN 'owner' ELSE 'admin' END AS role "
        "FROM administrateurs ORDER BY id"
    ).all()
    return _rendu(requete, "admin_users.html", compte=compte, users=_lignes(resultat),
                  created=requete.query_params.get("created") == "1",
                  removed=requete.query_params.get("removed") == "1",
                  changed=requete.query_params.get("changed") == "1")


@app.post("/admin/users/create")
async def creer_compte(requete: Request):
    compte, refus = await _auth(requete, principal=True)
    if refus:
        return refus
    form = await requete.form()
    _csrf_valide(requete, _secret(requete), form)
    utilisateur = str(form.get("username", "")).strip().lower()
    mdp = str(form.get("password", ""))
    if not re.fullmatch(r"[a-z0-9_-]{3,32}", utilisateur) or not MOT_DE_PASSE_MIN <= len(mdp) <= 256:
        raise HTTPException(400, detail="Identifiant ou mot de passe invalide")
    # Un doublon n'entraîne pas de calcul PBKDF2 inutile.
    doublon = await _bdd(requete).prepare(
        "SELECT 1 FROM administrateurs WHERE lower(identifiant)=?"
    ).bind(utilisateur).first()
    if doublon is not None:
        raise HTTPException(409, detail="Identifiant déjà utilisé")
    empreinte = await _hash_mdp(mdp)
    try:
        await _bdd(requete).batch([
            _bdd(requete).prepare("""INSERT INTO administrateurs
                (identifiant,mot_de_passe_hash,role) VALUES (?,?, 'admin')""").bind(utilisateur,empreinte),
            _bdd(requete).prepare("INSERT INTO journal_admin(admin_id,action,cible_type,cible_id) VALUES (?,'create_admin','admin',?)").bind(int(compte["id"]),utilisateur),
        ])
    except Exception:
        raise HTTPException(409, detail="Impossible de créer ce compte") from None
    return _lien("/admin/users?created=1")


@app.post("/admin/users/{id_administrateur}/password")
async def changer_mdp(requete: Request, id_administrateur: Annotated[int, PathParam(ge=1, le=9_007_199_254_740_991)]):
    compte, refus = await _auth(requete, principal=True)
    if refus:
        return refus
    form = await requete.form()
    _csrf_valide(requete, _secret(requete), form)
    mdp = str(form.get("password", ""))
    if not MOT_DE_PASSE_MIN <= len(mdp) <= 256:
        raise HTTPException(400, detail="Mot de passe invalide")
    cible = _objet(await _bdd(requete).prepare(
        "SELECT id,role,mot_de_passe_hash FROM administrateurs WHERE id=?"
    ).bind(id_administrateur).first())
    if cible is None:
        raise HTTPException(404, detail="Compte introuvable")
    mon_compte = int(compte["id"]) == id_administrateur
    if cible["role"] == "principal" and not mon_compte:
        raise HTTPException(403, detail="Un autre compte principal ne peut pas ?tre r?initialis?")
    if mon_compte:
        courant = str(form.get("current_password", ""))
        if not await _verifie_mdp(courant, cible["mot_de_passe_hash"]):
            raise HTTPException(403, detail="Mot de passe actuel incorrect")
    empreinte = await _hash_mdp(mdp)
    bdd = _bdd(requete)
    resultats = await bdd.batch([
        bdd.prepare("UPDATE administrateurs SET mot_de_passe_hash=?,auth_version=auth_version+1 WHERE id=?").bind(empreinte,id_administrateur),
        bdd.prepare("INSERT INTO journal_admin(admin_id,action,cible_type,cible_id) VALUES (?,'change_password','admin',?)").bind(int(compte["id"]),str(id_administrateur)),
    ])
    if int(resultats[0].meta.changes) != 1:
        raise HTTPException(404, detail="Compte introuvable")
    if mon_compte:
        response = _lien("/admin/login")
        response.delete_cookie(SESSION,path="/",secure=True,httponly=True,samesite="lax")
        response.delete_cookie(CSRF,path="/",secure=True,httponly=True,samesite="lax")
        return response
    return _lien("/admin/users?changed=1")


@app.post("/admin/users/{id_administrateur}/delete")
async def supprimer_compte(requete: Request, id_administrateur: Annotated[int, PathParam(ge=1, le=9_007_199_254_740_991)]):
    compte, refus = await _auth(requete, principal=True)
    if refus:
        return refus
    form = await requete.form()
    _csrf_valide(requete, _secret(requete), form)
    if int(compte["id"]) == id_administrateur:
        raise HTTPException(400, detail="Impossible de supprimer son propre compte")
    ligne = _objet(await _bdd(requete).prepare(
        "SELECT identifiant,role FROM administrateurs WHERE id=?"
    ).bind(id_administrateur).first())
    if not ligne:
        raise HTTPException(404, detail="Compte introuvable")
    if ligne["role"] == "principal":
        raise HTTPException(403, detail="Impossible de supprimer le compte principal")
    confirmation = str(form.get("confirmation_identifiant", ""))
    if not hmac.compare_digest(confirmation.encode(), str(ligne["identifiant"]).encode()):
        raise HTTPException(400, detail="Identifiant de confirmation incorrect")
    bdd=_bdd(requete)
    resultats=await bdd.batch([
        bdd.prepare("DELETE FROM administrateurs WHERE id=? AND role='admin' AND identifiant=?").bind(id_administrateur,ligne["identifiant"]),
        bdd.prepare("INSERT INTO journal_admin(admin_id,action,cible_type,cible_id) SELECT ?,'delete_admin','admin',? WHERE changes()=1").bind(int(compte["id"]),str(id_administrateur)),
    ])
    if int(resultats[0].meta.changes) != 1:
        raise HTTPException(409, detail="Compte introuvable ou modifi?")
    return _lien("/admin/users?removed=1")


@app.get("/admin/")
async def admin_slash():
    return _lien("/admin")


@app.get("/admin/{chemin:path}")
async def administration_introuvable():
    raise HTTPException(404, detail="Introuvable")


@app.api_route("/access", methods=["GET", "POST"])
@app.api_route("/vote", methods=["GET", "POST"])
@app.api_route("/polls/{id_sujet}/access", methods=["GET", "POST"])
async def ancienne_route_introuvable():
    raise HTTPException(404, detail="Introuvable")


Default = asgi.entrypoint(app)
