"""AGémocratie / Cloudflare Workers.

Application locale inchangée. Administration D1 (connexion, comptes,
création/calendrier/clôture/suppression de scrutins). Le vote demeure
volontairement désactivé jusqu'à la migration atomique des codes.

Secrets requis dans Cloudflare Worker (pas dans Git) : APP_SECRET_KEY.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape
from workers import asgi

DOSSIER = Path(__file__).resolve().parent
PARIS = ZoneInfo("Europe/Paris")
SESSION = "__Host-ag_session"
CSRF = "__Host-ag_csrf"
DUREE_SESSION = 4 * 60 * 60
DUREE_LIMITE = 15 * 60
ITERATIONS_MIN = 150_000
ITERATIONS_MAX = 1_000_000

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
app = FastAPI(title="AGémocratie Cloudflare", docs_url=None,
              redoc_url=None, openapi_url=None)


@app.middleware("http")
async def securite(requete: Request, suivant):
    reponse = await suivant(requete)
    reponse.headers["X-Content-Type-Options"] = "nosniff"
    reponse.headers["X-Frame-Options"] = "DENY"
    reponse.headers["Referrer-Policy"] = "no-referrer"
    reponse.headers["Cache-Control"] = "no-store"
    reponse.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'none'; style-src 'self'; "
        "img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    )
    reponse.headers["Strict-Transport-Security"] = "max-age=31536000"
    return reponse


def _bdd(requete):
    environnement = requete.scope.get("env")
    if environnement is None or not hasattr(environnement, "DB"):
        raise HTTPException(503, detail="Binding Cloudflare DB indisponible")
    return environnement.DB


def _secret(requete):
    environnement = requete.scope.get("env")
    cle = getattr(environnement, "APP_SECRET_KEY", "") if environnement else ""
    if not isinstance(cle, str):
        cle = str(cle)
    if len(cle) < 32:
        raise HTTPException(503, detail="Le secret APP_SECRET_KEY n'est pas configuré")
    return cle.encode("utf-8")


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


def _jeton_csrf(secret):
    alea = secrets.token_urlsafe(24)
    return f"{alea}.{_signature(secret, ('csrf:' + alea).encode())}"


def _csrf_valide(requete, secret, formulaire):
    origine = requete.headers.get("origin")
    # Contrôle Origin systématique si le navigateur l'envoie.
    if origine:
        url_origine = urlparse(origine)
        if (url_origine.scheme != "https"
                or url_origine.netloc.lower() != requete.url.netloc.lower()):
            raise HTTPException(403, detail="Origine du formulaire invalide")
    cookie = requete.cookies.get(CSRF, "")
    jeton = str(formulaire.get("csrf_token", ""))
    if not cookie or not jeton or not hmac.compare_digest(cookie, jeton):
        raise HTTPException(403, detail="Formulaire expiré ou invalide")
    try:
        alea, signature = cookie.rsplit(".", 1)
    except ValueError:
        raise HTTPException(403, detail="Formulaire invalide") from None
    if not alea or not hmac.compare_digest(signature, _signature(secret, ('csrf:' + alea).encode())):
        raise HTTPException(403, detail="Formulaire invalide")


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
        if not hmac.compare_digest(sig, _signature(secret, b"session:" + enc.encode())):
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


def _rendu(requete, nom, *, compte=None, statut=200, **contexte):
    secret = _secret(requete)
    token = requete.cookies.get(CSRF, "")
    valide = False
    if token and len(token) < 256:
        try:
            alea, signature = token.rsplit(".", 1)
            valide = bool(alea) and hmac.compare_digest(
                signature, _signature(secret, ("csrf:" + alea).encode()))
        except ValueError:
            pass
    if not valide:
        token = _jeton_csrf(secret)
    html = modeles.get_template(nom).render(
        csrf_token=token, is_admin=compte is not None,
        is_owner=bool(compte and compte["role"] == "principal"),
        admin_username=compte["identifiant"] if compte else None,
        request=requete, **contexte,
    )
    reponse = HTMLResponse(html, status_code=statut)
    if not valide:
        reponse.set_cookie(CSRF, token, max_age=DUREE_SESSION,
                           secure=True, httponly=True, samesite="lax", path="/")
    return reponse


def _scrutin(ligne):
    debut, fin = _utc(ligne.get("debut_utc")), _utc(ligne.get("fin_utc"))
    now = datetime.now(timezone.utc)
    if not debut or not fin or int(ligne.get("ferme_manuellement") or 0) or fin <= now:
        phase = "ended"
    elif now < debut:
        phase = "upcoming"
    else:
        phase = "open"
    return {
        "id": int(ligne["id"]), "title": str(ligne["titre"]),
        "description": str(ligne.get("description") or ""),
        "starts_at": int(debut.timestamp()) if debut else None,
        "ends_at": int(fin.timestamp()) if fin else None,
        "phase": phase,
    }


def _horaires(formulaire):
    try:
        a = datetime.strptime(str(formulaire.get("starts_at", "")).strip(), "%Y-%m-%dT%H:%M")
        b = datetime.strptime(str(formulaire.get("ends_at", "")).strip(), "%Y-%m-%dT%H:%M")
        def date(val):
            aware = val.replace(tzinfo=PARIS)
            utc = aware.astimezone(timezone.utc)
            if utc.astimezone(PARIS).replace(tzinfo=None) != val:
                raise ValueError("heure locale inexistante")
            return utc
        debut, fin = date(a), date(b)
        if debut >= fin or fin <= datetime.now(timezone.utc):
            return None
        def iso(x):
            return x.isoformat(timespec="seconds").replace("+00:00", "Z")
        return iso(debut), iso(fin)
    except (ValueError, TypeError, OverflowError):
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
                                       "PBKDF2", False, ["deriveBits"])
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
                                       "PBKDF2", False, ["deriveBits"])
    options = to_js({"name": "PBKDF2", "hash": "SHA-256",
                     "salt": to_js(sel), "iterations": 390_000},
                     dict_converter=Object.fromEntries)
    bits = await crypto.subtle.deriveBits(options, cle, 256)
    empreinte = bytes(Uint8Array.new(bits).to_py())
    return f"pbkdf2_sha256$390000${sel.hex()}${empreinte.hex()}"


def _portees(requete, identifiant, secret):
    ip = requete.headers.get("cf-connecting-ip") or (
        requete.client.host if requete.client else "unknown")
    return [
        _signature(secret, f"ip:{ip}".encode()),
        _signature(secret, f"user:{identifiant.casefold()}".encode()),
    ]


async def _limite(bdd, portees):
    now = int(time.time())
    for portee in portees:
        ligne = _objet(await bdd.prepare(
            "SELECT debut_fenetre, echecs FROM limites_connexion WHERE empreinte=?"
        ).bind(portee).first())
        if ligne and now - int(ligne["debut_fenetre"]) < DUREE_LIMITE and int(ligne["echecs"]) >= 6:
            return True
    return False


async def _echec(bdd, portees):
    now = int(time.time())
    statement = """INSERT INTO limites_connexion (empreinte, debut_fenetre, echecs)
                   VALUES (?, ?, 1)
                   ON CONFLICT(empreinte) DO UPDATE SET
                   echecs=CASE WHEN excluded.debut_fenetre-limites_connexion.debut_fenetre>=900
                          THEN 1 ELSE limites_connexion.echecs+1 END,
                   debut_fenetre=CASE WHEN excluded.debut_fenetre-limites_connexion.debut_fenetre>=900
                          THEN excluded.debut_fenetre ELSE limites_connexion.debut_fenetre END"""
    await bdd.batch([bdd.prepare(statement).bind(p, now) for p in portees])


@app.get("/health")
async def etat(requete: Request):
    await _bdd(requete).prepare("SELECT 1").run()
    return {"status": "ok"}


@app.get("/api/test-db")
async def tester_bdd(requete: Request):
    valeur = await _bdd(requete).prepare("SELECT 1 AS ok").first("ok")
    return {"d1": "connectee" if valeur == 1 else "indisponible"}


@app.get("/")
async def accueil(requete: Request):
    compte = await _compte(requete)
    resultat = await _bdd(requete).prepare(
        "SELECT id,titre,description,debut_utc,fin_utc,ferme_manuellement "
        "FROM scrutins ORDER BY cree_le DESC,id DESC"
    ).all()
    sujets = [_scrutin(l) for l in _lignes(resultat)]
    ordre = {"open": 0, "upcoming": 1, "ended": 2}
    sujets.sort(key=lambda s: (ordre[s["phase"]], -s["id"]))
    return _rendu(requete, "home.html", compte=compte, polls=sujets, success=False)


@app.get("/polls/{id_sujet}")
async def apercu_sujet(requete: Request, id_sujet: int):
    compte = await _compte(requete)
    ligne = _objet(await _bdd(requete).prepare(
        "SELECT id,titre,description,debut_utc,fin_utc,ferme_manuellement "
        "FROM scrutins WHERE id=?"
    ).bind(id_sujet).first())
    if not ligne:
        raise HTTPException(404, detail="Sujet introuvable")
    sujet = _scrutin(ligne)
    return _rendu(requete, "poll_preview.html", compte=compte,
                  poll=sujet, phase=sujet["phase"])


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
    identifiant = str(formulaire.get("username", "admin")).strip()
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
    if compte and mot_de_passe:
        valide = await _verifie_mdp(mot_de_passe, compte["mot_de_passe_hash"])
    if not valide:
        await _echec(bdd, portees)
        return _rendu(requete, "login.html", statut=401,
                      error="Identifiant ou mot de passe incorrect.")
    # Supprimer seulement les échecs de cet identifiant ; une IP à attaques
    # multiples reste temporairement limitée par son compteur.
    await bdd.prepare("DELETE FROM limites_connexion WHERE empreinte=?").bind(portees[1]).run()
    reponse = _lien("/admin")
    reponse.set_cookie(SESSION, _creer_session(secret, compte),
                       max_age=DUREE_SESSION, httponly=True,
                       secure=True, samesite="lax", path="/")
    return reponse


@app.post("/admin/logout")
async def deconnexion(requete: Request):
    form = await requete.form()
    _csrf_valide(requete, _secret(requete), form)
    reponse = _lien("/")
    reponse.delete_cookie(SESSION, path="/", secure=True, httponly=True, samesite="lax")
    return reponse


@app.get("/admin")
async def tableau_bord(requete: Request):
    compte, refus = await _auth(requete)
    if refus:
        return refus
    resultat = await _bdd(requete).prepare("""
        SELECT s.id,s.titre,s.description,s.debut_utc,s.fin_utc,s.ferme_manuellement,
          (SELECT count(*) FROM codes_vote c WHERE c.scrutin_id=s.id) AS total_codes,
          (SELECT count(*) FROM votes v WHERE v.scrutin_id=s.id) AS total_votes
        FROM scrutins s ORDER BY s.cree_le DESC, s.id DESC
    """).all()
    sujets = []
    for ligne in _lignes(resultat):
        sujet = _scrutin(ligne)
        sujet["total_codes"] = int(ligne["total_codes"])
        # Ne JAMAIS envoyer les décomptes de votes en cours au navigateur.
        sujet["total_votes"] = int(ligne["total_votes"]) if sujet["phase"] == "ended" else None
        sujets.append(sujet)
    return _rendu(requete, "dashboard.html", compte=compte, polls=sujets)


@app.get("/admin/polls/new")
async def page_creation(requete: Request):
    compte, refus = await _auth(requete)
    if refus:
        return refus
    return _rendu(requete, "new_poll.html", compte=compte)


@app.post("/admin/polls/new")
async def creer_scrutin(requete: Request):
    compte, refus = await _auth(requete)
    if refus:
        return refus
    form = await requete.form()
    _csrf_valide(requete, _secret(requete), form)
    titre = str(form.get("title", "")).strip()
    description = str(form.get("description", "")).strip()
    propositions = [p.strip() for p in str(form.get("options", "")).splitlines() if p.strip()]
    horaires = _horaires(form)
    if not (3 <= len(titre) <= 140 and len(description) <= 600
            and 2 <= len(propositions) <= 10
            and all(len(p) <= 140 for p in propositions)
            and len({p.casefold() for p in propositions}) == len(propositions)
            and horaires):
        return _rendu(requete, "new_poll.html", compte=compte, statut=400,
                      title_value=titre, description_value=description,
                      options_value="\n".join(propositions),
                      starts_value=form.get("starts_at", ""),
                      ends_value=form.get("ends_at", ""),
                      error="Vérifiez le titre, les réponses et les dates (fin future après début).")
    debut, fin = horaires
    # ID 52-bit aléatoire: partageable et représentable exactement par JS/D1.
    # Réutilisé dans batch() pour que scrutin + choix soient atomiques.
    id_scrutin = secrets.randbelow(2**52 - 2**40) + 2**40
    bdd = _bdd(requete)
    statements = [bdd.prepare("""INSERT INTO scrutins
        (id, titre, description, debut_utc, fin_utc, cree_par)
        VALUES (?, ?, ?, ?, ?, ?)""").bind(id_scrutin, titre, description,
                                               debut, fin, int(compte["id"]))]
    for position, libelle in enumerate(propositions):
        statements.append(bdd.prepare(
            "INSERT INTO choix (scrutin_id,intitule,position) VALUES (?,?,?)"
        ).bind(id_scrutin, libelle, position))
    await bdd.batch(statements)
    return _lien(f"/admin/polls/{id_scrutin}?created=1")


async def _detail_scrutin(requete, id_sujet):
    ligne = _objet(await _bdd(requete).prepare(
        "SELECT id,titre,description,debut_utc,fin_utc,ferme_manuellement FROM scrutins WHERE id=?"
    ).bind(id_sujet).first())
    if ligne is None:
        raise HTTPException(404, detail="Scrutin introuvable")
    return _scrutin(ligne)


@app.get("/admin/polls/{id_sujet}")
async def detail_scrutin(requete: Request, id_sujet: int):
    compte, refus = await _auth(requete)
    if refus:
        return refus
    scrutin = await _detail_scrutin(requete, id_sujet)
    resultat = await _bdd(requete).prepare(
        "SELECT id,intitule,position FROM choix WHERE scrutin_id=? ORDER BY position"
    ).bind(id_sujet).all()
    return _rendu(requete, "poll_manage.html", compte=compte, poll=scrutin,
                  options=_lignes(resultat), phase=scrutin["phase"],
                  created=requete.query_params.get("created") == "1",
                  schedule_saved=requete.query_params.get("schedule_saved") == "1",
                  closed=requete.query_params.get("closed") == "1")


@app.post("/admin/polls/{id_sujet}/schedule")
async def changer_dates(requete: Request, id_sujet: int):
    compte, refus = await _auth(requete)
    if refus:
        return refus
    form = await requete.form()
    _csrf_valide(requete, _secret(requete), form)
    horaires = _horaires(form)
    if not horaires:
        raise HTTPException(400, detail="Dates invalides")
    poll = await _detail_scrutin(requete, id_sujet)
    if poll["phase"] == "ended":
        raise HTTPException(409, detail="Scrutin terminé")
    debut, fin = horaires
    result = await _bdd(requete).prepare("""UPDATE scrutins SET debut_utc=?, fin_utc=?
        WHERE id=? AND ferme_manuellement=0 AND fin_utc>strftime('%Y-%m-%dT%H:%M:%fZ','now')""").bind(
        debut, fin, id_sujet).run()
    if int(result.meta.changes) != 1:
        raise HTTPException(409, detail="Scrutin terminé ou modifié")
    return _lien(f"/admin/polls/{id_sujet}?schedule_saved=1")


@app.post("/admin/polls/{id_sujet}/close")
async def fermer_scrutin(requete: Request, id_sujet: int):
    compte, refus = await _auth(requete)
    if refus:
        return refus
    form = await requete.form()
    _csrf_valide(requete, _secret(requete), form)
    resultat = await _bdd(requete).prepare(
        "UPDATE scrutins SET ferme_manuellement=1 WHERE id=?"
    ).bind(id_sujet).run()
    if int(resultat.meta.changes) != 1:
        raise HTTPException(404, detail="Scrutin introuvable")
    return _lien(f"/admin/polls/{id_sujet}?closed=1")


@app.post("/admin/polls/{id_sujet}/delete")
async def supprimer_scrutin(requete: Request, id_sujet: int):
    compte, refus = await _auth(requete)
    if refus:
        return refus
    form = await requete.form()
    _csrf_valide(requete, _secret(requete), form)
    scrutin = await _detail_scrutin(requete, id_sujet)
    confirme = str(form.get("confirmation_titre", ""))
    if not hmac.compare_digest(confirme.encode(), scrutin["title"].encode()):
        raise HTTPException(400, detail="Titre de confirmation incorrect")
    # ON DELETE CASCADE géré par les clés étrangères du schéma D1.
    result = await _bdd(requete).prepare("DELETE FROM scrutins WHERE id=? AND titre=?").bind(
        id_sujet, scrutin["title"]).run()
    if int(result.meta.changes) != 1:
        raise HTTPException(409, detail="Scrutin introuvable ou modifié")
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
    if not re.fullmatch(r"[a-z0-9_-]{3,32}", utilisateur) or not 12 <= len(mdp) <= 256:
        raise HTTPException(400, detail="Identifiant ou mot de passe invalide")
    # Un doublon n'entraîne pas de calcul PBKDF2 inutile.
    doublon = await _bdd(requete).prepare(
        "SELECT 1 FROM administrateurs WHERE lower(identifiant)=?"
    ).bind(utilisateur).first()
    if doublon is not None:
        raise HTTPException(409, detail="Identifiant déjà utilisé")
    empreinte = await _hash_mdp(mdp)
    try:
        await _bdd(requete).prepare("""INSERT INTO administrateurs
            (identifiant,mot_de_passe_hash,role) VALUES (?,?, 'admin')""").bind(
                utilisateur, empreinte).run()
    except Exception:
        raise HTTPException(409, detail="Impossible de créer ce compte") from None
    return _lien("/admin/users?created=1")


@app.post("/admin/users/{id_administrateur}/password")
async def changer_mdp(requete: Request, id_administrateur: int):
    compte, refus = await _auth(requete, principal=True)
    if refus:
        return refus
    form = await requete.form()
    _csrf_valide(requete, _secret(requete), form)
    mdp = str(form.get("password", ""))
    if not 12 <= len(mdp) <= 256:
        raise HTTPException(400, detail="Mot de passe invalide")
    if await _bdd(requete).prepare(
        "SELECT id FROM administrateurs WHERE id=?"
    ).bind(id_administrateur).first() is None:
        raise HTTPException(404, detail="Compte introuvable")
    empreinte = await _hash_mdp(mdp)
    resultat = await _bdd(requete).prepare("""UPDATE administrateurs
        SET mot_de_passe_hash=?, auth_version=auth_version+1 WHERE id=?""").bind(
        empreinte, id_administrateur).run()
    if int(resultat.meta.changes) != 1:
        raise HTTPException(404, detail="Compte introuvable")
    if int(compte["id"]) == id_administrateur:
        reponse = _lien("/admin/login")
        reponse.delete_cookie(SESSION, path="/", secure=True, httponly=True, samesite="lax")
        return reponse
    return _lien("/admin/users?changed=1")


@app.post("/admin/users/{id_administrateur}/delete")
async def supprimer_compte(requete: Request, id_administrateur: int):
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
    if not hmac.compare_digest(confirmation, str(ligne["identifiant"])):
        raise HTTPException(400, detail="Identifiant de confirmation incorrect")
    resultat = await _bdd(requete).prepare(
        "DELETE FROM administrateurs WHERE id=? AND role='admin' AND identifiant=?"
    ).bind(id_administrateur, ligne["identifiant"]).run()
    if int(resultat.meta.changes) != 1:
        raise HTTPException(409, detail="Compte introuvable ou modifié")
    return _lien("/admin/users?removed=1")


@app.api_route("/admin/{chemin:path}", methods=["GET", "POST"])
@app.api_route("/access", methods=["GET", "POST"])
@app.api_route("/vote", methods=["GET", "POST"])
@app.api_route("/polls/{id_sujet}/access", methods=["GET", "POST"])
async def pas_encore_disponible(requete: Request, chemin: str = "", id_sujet: int = 0):
    compte = await _compte(requete)
    return _rendu(requete, "non_disponible.html", compte=compte, statut=503)


Default = asgi.entrypoint(app)
