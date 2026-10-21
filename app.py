"""Site de vote avec codes numériques à usage unique (FastAPI + SQLite).

MVP pour des consultations privées ; pas destiné à un scrutin officiel.
"""
from __future__ import annotations

import csv
import hashlib
import hmac
import io
import os
import secrets
import sqlite3
import time
from datetime import datetime
from zoneinfo import ZoneInfo
from contextlib import contextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

DOSSIER_PROJET = Path(__file__).resolve().parent
load_dotenv(DOSSIER_PROJET / ".env")

CLE_SECRETE_APPLICATION = os.environ.get("APP_SECRET_KEY", "")
MOT_DE_PASSE_ADMIN = os.environ.get("ADMIN_PASSWORD", "")
if len(CLE_SECRETE_APPLICATION) < 32 or "REMPLACER" in CLE_SECRETE_APPLICATION.upper():
    raise RuntimeError("Définissez APP_SECRET_KEY (au moins 32 caractères) dans .env")
if len(MOT_DE_PASSE_ADMIN) < 12 or "REMPLACER" in MOT_DE_PASSE_ADMIN.upper():
    raise RuntimeError("Définissez ADMIN_PASSWORD (au moins 12 caractères) dans .env")

CHEMIN_BASE_DONNEES = Path(os.environ.get("DATABASE_PATH", DOSSIER_PROJET / "instance" / "votes.sqlite3"))
CHEMIN_BASE_DONNEES.parent.mkdir(parents=True, exist_ok=True)
COOKIE_SECURISE = os.environ.get("COOKIE_SECURE", "0") == "1"

app = FastAPI(title="Vote par code", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(
    SessionMiddleware,
    secret_key=CLE_SECRETE_APPLICATION,
    session_cookie="vote_session",
    max_age=60 * 60 * 4,
    same_site="lax",
    https_only=COOKIE_SECURISE,
)
app.mount("/static", StaticFiles(directory=DOSSIER_PROJET / "static"), name="static")
modeles = Jinja2Templates(directory=DOSSIER_PROJET / "templates")


@contextmanager
def connect_db():
    connexion = sqlite3.connect(CHEMIN_BASE_DONNEES, timeout=10, isolation_level=None)
    connexion.row_factory = sqlite3.Row
    connexion.execute("PRAGMA foreign_keys = ON")
    try:
        yield connexion
    finally:
        connexion.close()


def init_db():
    with connect_db() as bdd:
        bdd.execute("PRAGMA journal_mode = WAL")
        bdd.executescript(
            """
            CREATE TABLE IF NOT EXISTS polls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                is_open INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS poll_options (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                poll_id INTEGER NOT NULL REFERENCES polls(id),
                label TEXT NOT NULL,
                position INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS access_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                poll_id INTEGER NOT NULL REFERENCES polls(id),
                code_hash TEXT NOT NULL UNIQUE,
                used_at INTEGER,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS codes_by_poll ON access_codes(poll_id);
            CREATE TABLE IF NOT EXISTS ballots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                poll_id INTEGER NOT NULL REFERENCES polls(id),
                option_id INTEGER NOT NULL REFERENCES poll_options(id),
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ballots_by_option ON ballots(option_id);
            CREATE TABLE IF NOT EXISTS rate_limits (
                scope TEXT PRIMARY KEY,
                window_start INTEGER NOT NULL,
                failures INTEGER NOT NULL
            );
            """
        )
        colonnes = {ligne["name"] for ligne in bdd.execute("PRAGMA table_info(polls)")}
        if "starts_at" not in colonnes:
            bdd.execute("ALTER TABLE polls ADD COLUMN starts_at INTEGER")
        if "ends_at" not in colonnes:
            bdd.execute("ALTER TABLE polls ADD COLUMN ends_at INTEGER")


init_db()


ITERATIONS_HACHAGE = 390_000


def password_hash(mot_de_passe: str) -> str:
    sel = secrets.token_bytes(16)
    empreinte = hashlib.pbkdf2_hmac("sha256", mot_de_passe.encode("utf-8"), sel, ITERATIONS_HACHAGE)
    return f"pbkdf2_sha256${ITERATIONS_HACHAGE}${sel.hex()}${empreinte.hex()}"


def password_verify(mot_de_passe: str, empreinte_stockee: str) -> bool:
    try:
        algorithme, iterations, sel, empreinte_attendue = empreinte_stockee.split("$")
        if algorithme != "pbkdf2_sha256" or not (150_000 <= int(iterations) <= 1_000_000):
            return False
        empreinte_obtenue = hashlib.pbkdf2_hmac("sha256", mot_de_passe.encode("utf-8"), bytes.fromhex(sel), int(iterations))
        return hmac.compare_digest(empreinte_obtenue, bytes.fromhex(empreinte_attendue))
    except (TypeError, ValueError):
        return False


def init_admin_accounts():
    with connect_db() as bdd:
        bdd.execute("BEGIN IMMEDIATE")
        try:
            bdd.execute("""CREATE TABLE IF NOT EXISTS admin_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('owner','admin')),
                auth_version INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL
            )""")
            if bdd.execute("SELECT COUNT(*) FROM admin_users").fetchone()[0] == 0:
                bdd.execute("INSERT INTO admin_users(username,password_hash,role,created_at) VALUES (?,?,?,?)",
                           ("admin", password_hash(MOT_DE_PASSE_ADMIN), "owner", int(time.time())))
            bdd.execute("COMMIT")
        except Exception:
            if bdd.in_transaction:
                bdd.execute("ROLLBACK")
            raise


init_admin_accounts()


def admin_account(requete: Request):
    id_administrateur = requete.session.get("admin_user_id")
    version = requete.session.get("admin_auth_version")
    if not isinstance(id_administrateur, int) or not isinstance(version, int):
        return None
    with connect_db() as bdd:
        administrateur = bdd.execute(
            "SELECT id,username,role,auth_version FROM admin_users WHERE id=?", (id_administrateur,)
        ).fetchone()
    if administrateur is None or administrateur["auth_version"] != version:
        return None
    return dict(administrateur)


def require_owner(requete: Request):
    if acces_refuse := require_admin(requete):
        return acces_refuse
    if admin_account(requete)["role"] != "owner":
        raise HTTPException(status_code=403, detail="Réservé à l'administrateur principal")
    return None


PARIS = ZoneInfo("Europe/Paris")


def read_local_date(valeur: str) -> int | None:
    """Convertit le formulaire HTML datetime-local (heure de Paris) en secondes UTC."""
    try:
        date_sans_fuseau = datetime.strptime(valeur.strip(), "%Y-%m-%dT%H:%M")
        date_avec_fuseau = date_sans_fuseau.replace(tzinfo=PARIS)
        horodatage = int(date_avec_fuseau.timestamp())
        if datetime.fromtimestamp(horodatage, PARIS).replace(tzinfo=None) != date_sans_fuseau:
            return None
        return horodatage
    except (ValueError, TypeError, OverflowError):
        return None


def local_date(valeur):
    if valeur is None:
        return "Non définie"
    return datetime.fromtimestamp(valeur, PARIS).strftime("%d/%m/%Y à %H:%M")


def local_input(valeur):
    if valeur is None:
        return ""
    return datetime.fromtimestamp(valeur, PARIS).strftime("%Y-%m-%dT%H:%M")


modeles.env.filters["local_date"] = local_date
modeles.env.filters["local_input"] = local_input


def poll_phase(sujet, instant: int | None = None) -> str:
    """À venir, ouvert ou terminé (y compris fermeture manuelle)."""
    if instant is None:
        instant = int(time.time())
    if not sujet["is_open"]:
        return "ended"
    if sujet["ends_at"] is not None and instant >= sujet["ends_at"]:
        return "ended"
    if sujet["starts_at"] is not None and instant < sujet["starts_at"]:
        return "upcoming"
    return "open"


def schedule_from_form(formulaire):
    debut = read_local_date(str(formulaire.get("starts_at", "")))
    fin = read_local_date(str(formulaire.get("ends_at", "")))
    if debut is None or fin is None or debut >= fin or fin <= int(time.time()):
        return None
    return debut, fin


def render(requete: Request, modele: str, status_code=200, **contexte):
    jeton = requete.session.get("csrf_token")
    if not jeton:
        jeton = secrets.token_urlsafe(32)
        requete.session["csrf_token"] = jeton
    administrateur = admin_account(requete)
    return modeles.TemplateResponse(
        requete, modele,
        {"csrf_token": jeton, "is_admin": administrateur is not None,
         "is_owner": bool(administrateur and administrateur["role"] == "owner"),
         "admin_username": administrateur["username"] if administrateur else None, **contexte},
        status_code=status_code,
    )


def csrf_check(requete: Request, formulaire):
    empreinte_attendue = requete.session.get("csrf_token", "")
    jeton_recu = str(formulaire.get("csrf_token", ""))
    if not empreinte_attendue or not hmac.compare_digest(empreinte_attendue, jeton_recu):
        raise HTTPException(status_code=403, detail="Formulaire expiré ou invalide")


def require_admin(requete: Request):
    if admin_account(requete) is None:
        return RedirectResponse(url="/admin/login", status_code=303)
    return None


def redirect_to(chemin: str):
    return RedirectResponse(chemin, status_code=303)


def code_digest(code: str) -> str:
    return hmac.new(CLE_SECRETE_APPLICATION.encode(), code.encode(), hashlib.sha256).hexdigest()


def scope_for(requete: Request, categorie: str) -> str:
    adresse_ip = requete.client.host if requete.client else "unknown"
    return hmac.new(CLE_SECRETE_APPLICATION.encode(), f"{categorie}:{adresse_ip}".encode(), hashlib.sha256).hexdigest()


def blocked(bdd: sqlite3.Connection, portee: str, maximum_echecs: int) -> bool:
    ligne = bdd.execute("SELECT window_start, failures FROM rate_limits WHERE scope=?", (portee,)).fetchone()
    return bool(ligne and (int(time.time()) - ligne["window_start"] < 900) and ligne["failures"] >= maximum_echecs)


def failed_attempt(bdd: sqlite3.Connection, portee: str):
    instant = int(time.time())
    bdd.execute(
        """INSERT INTO rate_limits (scope, window_start, failures) VALUES (?, ?, 1)
        ON CONFLICT(scope) DO UPDATE SET
            failures=CASE WHEN excluded.window_start - rate_limits.window_start >= 900
                          THEN 1 ELSE rate_limits.failures + 1 END,
            window_start=CASE WHEN excluded.window_start - rate_limits.window_start >= 900
                              THEN excluded.window_start ELSE rate_limits.window_start END""",
        (portee, instant),
    )


@app.middleware("http")
async def security_headers(requete: Request, appel_suivant):
    reponse_http = await appel_suivant(requete)
    reponse_http.headers["X-Content-Type-Options"] = "nosniff"
    reponse_http.headers["X-Frame-Options"] = "DENY"
    reponse_http.headers["Referrer-Policy"] = "no-referrer"
    reponse_http.headers["Cache-Control"] = "no-store"
    reponse_http.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'none'; style-src 'self'; img-src 'self'; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    )
    if COOKIE_SECURISE and requete.url.scheme == "https":
        reponse_http.headers["Strict-Transport-Security"] = "max-age=31536000"
    return reponse_http


@app.get("/health")
async def health():
    """Réponse minimale de disponibilité pour la supervision de l'hébergeur."""
    try:
        with connect_db() as bdd:
            bdd.execute("SELECT 1").fetchone()
    except sqlite3.Error:
        raise HTTPException(status_code=503, detail="Base de données indisponible")
    return {"status": "ok"}


@app.get("/")
async def home(requete: Request):
    with connect_db() as bdd:
        lignes = bdd.execute(
            "SELECT id,title,description,is_open,starts_at,ends_at "
            "FROM polls ORDER BY id DESC"
        ).fetchall()
    sujets = [{**dict(ligne), "phase": poll_phase(ligne)} for ligne in lignes]
    ordre = {"open": 0, "upcoming": 1, "ended": 2}
    sujets.sort(key=lambda sujet: (ordre[sujet["phase"]], -sujet["id"]))
    return render(requete, "home.html", polls=sujets,
                  success=requete.query_params.get("done") == "1")


@app.get("/polls/{id_sujet}")
async def public_poll(requete: Request, id_sujet: int):
    with connect_db() as bdd:
        sujet = bdd.execute(
            "SELECT id,title,description,is_open,starts_at,ends_at "
            "FROM polls WHERE id=?", (id_sujet,)
        ).fetchone()
    if sujet is None:
        raise HTTPException(status_code=404, detail="Sujet introuvable")
    return render(requete, "poll_access.html", poll=sujet, phase=poll_phase(sujet))


@app.post("/polls/{id_sujet}/access")
async def access_selected_poll(requete: Request, id_sujet: int):
    formulaire = await requete.form()
    csrf_check(requete, formulaire)
    code = str(formulaire.get("code", "")).strip()
    portee = scope_for(requete, "voter")
    with connect_db() as bdd:
        sujet = bdd.execute(
            "SELECT id,title,description,is_open,starts_at,ends_at "
            "FROM polls WHERE id=?", (id_sujet,)
        ).fetchone()
        if sujet is None:
            raise HTTPException(status_code=404, detail="Sujet introuvable")
        etat = poll_phase(sujet)
        if etat != "open":
            return render(requete, "poll_access.html", status_code=409,
                          poll=sujet, phase=etat,
                          error="Ce sujet n'est pas ouvert au vote.")
        if blocked(bdd, portee, 10):
            return render(requete, "poll_access.html", status_code=429,
                          poll=sujet, phase=etat,
                          error="Trop de tentatives. Réessayez dans 15 minutes.")
        ligne = None
        if len(code) == 10 and code.isascii() and code.isdigit():
            ligne = bdd.execute(
                "SELECT id FROM access_codes "
                "WHERE poll_id=? AND code_hash=? AND used_at IS NULL",
                (id_sujet, code_digest(code)),
            ).fetchone()
        if ligne is None:
            failed_attempt(bdd, portee)
            return render(requete, "poll_access.html", status_code=400,
                          poll=sujet, phase=etat,
                          error="Code invalide, déjà utilisé ou destiné à un autre sujet.")
        bdd.execute("DELETE FROM rate_limits WHERE scope=?", (portee,))
    requete.session.pop("voter_code_id", None)
    requete.session["voter_code_id"] = ligne["id"]
    return redirect_to("/vote")


@app.post("/access")
async def access_vote(requete: Request):
    formulaire = await requete.form()
    csrf_check(requete, formulaire)
    code = str(formulaire.get("code", "")).strip()
    portee = scope_for(requete, "voter")
    with connect_db() as bdd:
        if blocked(bdd, portee, 10):
            return render(requete, "home.html", status_code=429,
                          error="Trop de tentatives. Réessayez dans 15 minutes.", success=False)
        ligne = None
        if len(code) == 10 and code.isascii() and code.isdigit():
            ligne = bdd.execute(
                """SELECT c.id, p.is_open, p.starts_at, p.ends_at FROM access_codes c
                   JOIN polls p ON p.id=c.poll_id
                   WHERE c.code_hash=? AND c.used_at IS NULL""",
                (code_digest(code),),
            ).fetchone()
        if ligne is None or poll_phase(ligne) != "open":
            failed_attempt(bdd, portee)
            return render(requete, "home.html", status_code=400,
                          error="Code invalide, déjà utilisé ou vote indisponible à cette heure.", success=False)
        bdd.execute("DELETE FROM rate_limits WHERE scope=?", (portee,))
    requete.session.pop("voter_code_id", None)
    requete.session["voter_code_id"] = ligne["id"]
    return redirect_to("/vote")


def get_active_poll(bdd, id_code):
    ligne = bdd.execute(
        """SELECT p.id, p.title, p.description, p.is_open, p.starts_at, p.ends_at
           FROM access_codes c JOIN polls p ON p.id=c.poll_id
           WHERE c.id=? AND c.used_at IS NULL""",
        (id_code,),
    ).fetchone()
    return ligne if ligne is not None and poll_phase(ligne) == "open" else None


@app.get("/vote")
async def voting_page(requete: Request):
    id_code = requete.session.get("voter_code_id")
    if not id_code:
        return redirect_to("/")
    with connect_db() as bdd:
        sujet = get_active_poll(bdd, id_code)
        if not sujet:
            requete.session.pop("voter_code_id", None)
            return redirect_to("/")
        propositions = bdd.execute("SELECT id,label FROM poll_options WHERE poll_id=? ORDER BY position", (sujet["id"],)).fetchall()
    return render(requete, "vote.html", poll=sujet, options=propositions)


@app.post("/vote")
async def submit_vote(requete: Request):
    formulaire = await requete.form()
    csrf_check(requete, formulaire)
    id_code = requete.session.get("voter_code_id")
    if not id_code:
        return redirect_to("/")
    try:
        id_proposition = int(formulaire.get("option_id", ""))
    except (TypeError, ValueError):
        id_proposition = -1

    with connect_db() as bdd:
        bdd.execute("BEGIN IMMEDIATE")
        try:
            sujet = get_active_poll(bdd, id_code)
            if sujet is None:
                bdd.execute("ROLLBACK")
                requete.session.pop("voter_code_id", None)
                return redirect_to("/")
            proposition = bdd.execute(
                "SELECT id FROM poll_options WHERE id=? AND poll_id=?", (id_proposition, sujet["id"])
            ).fetchone()
            if not proposition:
                propositions = bdd.execute("SELECT id,label FROM poll_options WHERE poll_id=? ORDER BY position", (sujet["id"],)).fetchall()
                bdd.execute("ROLLBACK")
                return render(requete, "vote.html", status_code=400, poll=sujet, options=propositions,
                              error="Sélectionnez une proposition avant de valider.")
            instant = int(time.time())
            mise_a_jour = bdd.execute(
                "UPDATE access_codes SET used_at=? WHERE id=? AND used_at IS NULL", (instant, id_code)
            )
            if mise_a_jour.rowcount != 1:
                bdd.execute("ROLLBACK")
                requete.session.pop("voter_code_id", None)
                return redirect_to("/")
            bdd.execute("INSERT INTO ballots (poll_id,option_id,created_at) VALUES (?,?,?)",
                       (sujet["id"], id_proposition, instant))
            bdd.execute("COMMIT")
        except Exception:
            if bdd.in_transaction:
                bdd.execute("ROLLBACK")
            raise
    requete.session.pop("voter_code_id", None)
    return redirect_to("/?done=1")


@app.get("/admin/login")
async def admin_login_page(requete: Request):
    if admin_account(requete):
        return redirect_to("/admin")
    return render(requete, "login.html")


@app.post("/admin/login")
async def admin_login(requete: Request):
    formulaire = await requete.form()
    csrf_check(requete, formulaire)
    identifiant = str(formulaire.get("username", "admin")).strip()
    mot_de_passe = str(formulaire.get("password", ""))
    portee = scope_for(requete, "admin")
    with connect_db() as bdd:
        if blocked(bdd, portee, 6):
            return render(requete, "login.html", status_code=429,
                          error="Trop de tentatives. Réessayez dans 15 minutes.")
        compte = bdd.execute(
            "SELECT id,password_hash,auth_version FROM admin_users WHERE username=?", (identifiant,)
        ).fetchone()
        if not compte or not password_verify(mot_de_passe, compte["password_hash"]):
            failed_attempt(bdd, portee)
            return render(requete, "login.html", status_code=401,
                          error="Identifiant ou mot de passe incorrect.")
        bdd.execute("DELETE FROM rate_limits WHERE scope=?", (portee,))
    requete.session.clear()
    requete.session["admin_user_id"] = compte["id"]
    requete.session["admin_auth_version"] = compte["auth_version"]
    return redirect_to("/admin")


@app.post("/admin/logout")
async def admin_logout(requete: Request):
    formulaire = await requete.form()
    csrf_check(requete, formulaire)
    requete.session.clear()
    return redirect_to("/")


@app.get("/admin")
async def admin_dashboard(requete: Request):
    if acces_refuse := require_admin(requete):
        return acces_refuse
    with connect_db() as bdd:
        lignes = bdd.execute(
            """SELECT p.*,
               (SELECT COUNT(*) FROM access_codes c WHERE c.poll_id=p.id) AS total_codes,
               (SELECT COUNT(*) FROM ballots b WHERE b.poll_id=p.id) AS total_votes
               FROM polls p ORDER BY p.id DESC"""
        ).fetchall()
    sujets = [{**dict(ligne), "phase": poll_phase(ligne)} for ligne in lignes]
    return render(requete, "dashboard.html", polls=sujets)


@app.get("/admin/polls/new")
async def create_poll_page(requete: Request):
    if acces_refuse := require_admin(requete):
        return acces_refuse
    return render(requete, "new_poll.html")


@app.post("/admin/polls/new")
async def create_poll(requete: Request):
    if acces_refuse := require_admin(requete):
        return acces_refuse
    formulaire = await requete.form()
    csrf_check(requete, formulaire)
    titre = str(formulaire.get("title", "")).strip()
    description = str(formulaire.get("description", "")).strip()
    propositions = [proposition.strip() for proposition in str(formulaire.get("options", "")).splitlines() if proposition.strip()]
    horaires = schedule_from_form(formulaire)
    if not (3 <= len(titre) <= 140 and len(description) <= 600
            and 2 <= len(propositions) <= 10 and all(len(proposition) <= 140 for proposition in propositions)
            and len(set(proposition.casefold() for proposition in propositions)) == len(propositions)
            and horaires is not None):
        return render(requete, "new_poll.html", status_code=400,
                      title_value=titre, description_value=description,
                      options_value="\n".join(propositions),
                      starts_value=str(formulaire.get("starts_at", "")),
                      ends_value=str(formulaire.get("ends_at", "")),
                      error="Vérifiez le titre, 2 à 10 réponses distinctes et les heures (fin future après début).")
    debut, fin = horaires
    with connect_db() as bdd:
        bdd.execute("BEGIN IMMEDIATE")
        try:
            id_sujet = bdd.execute(
                "INSERT INTO polls (title,description,created_at,starts_at,ends_at) VALUES (?,?,?,?,?)",
                (titre, description, int(time.time()), debut, fin),
            ).lastrowid
            for indice, libelle in enumerate(propositions):
                bdd.execute("INSERT INTO poll_options(poll_id,label,position) VALUES (?,?,?)",
                           (id_sujet, libelle, indice))
            bdd.execute("COMMIT")
        except Exception:
            bdd.execute("ROLLBACK")
            raise
    return redirect_to(f"/admin/polls/{id_sujet}?created=1")


def poll_details_data(bdd, id_sujet):
    sujet = bdd.execute("SELECT * FROM polls WHERE id=?", (id_sujet,)).fetchone()
    if sujet is None:
        raise HTTPException(status_code=404, detail="Vote introuvable")
    statistiques = bdd.execute(
        """SELECT COUNT(*) AS total_codes,
           COALESCE(SUM(CASE WHEN used_at IS NOT NULL THEN 1 ELSE 0 END),0) AS used_codes
           FROM access_codes WHERE poll_id=?""", (id_sujet,)
    ).fetchone()
    lignes = bdd.execute(
        """SELECT o.id,o.label,COUNT(b.id) AS votes
           FROM poll_options o LEFT JOIN ballots b ON b.option_id=o.id
           WHERE o.poll_id=? GROUP BY o.id ORDER BY o.position""", (id_sujet,)
    ).fetchall()
    total_votes_enregistres = sum(ligne["votes"] for ligne in lignes)
    resultats = [{"label": ligne["label"], "votes": ligne["votes"],
                "percent": round(100 * ligne["votes"] / total_votes_enregistres, 1) if total_votes_enregistres else 0}
               for ligne in lignes]
    return sujet, statistiques, resultats, total_votes_enregistres


@app.get("/admin/polls/{id_sujet}")
async def admin_poll_detail(requete: Request, id_sujet: int):
    if acces_refuse := require_admin(requete):
        return acces_refuse
    with connect_db() as bdd:
        sujet, statistiques, resultats, total_votes_enregistres = poll_details_data(bdd, id_sujet)
    etat = poll_phase(sujet)
    message_temporaire = requete.session.get("new_code")
    code_genere = None
    if isinstance(message_temporaire, dict) and message_temporaire.get("poll_id") == id_sujet:
        code_genere = message_temporaire.get("code")
        requete.session.pop("new_code", None)
    return render(requete, "poll_detail.html", poll=sujet, stats=statistiques,
                  phase=etat, show_results=(etat == "ended"),
                  results=resultats if etat == "ended" else [],
                  total_votes=total_votes_enregistres if etat == "ended" else None,
                  generated_code=code_genere,
                  created=requete.query_params.get("created") == "1",
                  closed=requete.query_params.get("closed") == "1",
                  schedule_saved=requete.query_params.get("schedule_saved") == "1")


@app.post("/admin/polls/{id_sujet}/codes")
async def generate_codes(requete: Request, id_sujet: int):
    if acces_refuse := require_admin(requete):
        return acces_refuse
    formulaire = await requete.form()
    csrf_check(requete, formulaire)
    with connect_db() as bdd:
        bdd.execute("BEGIN IMMEDIATE")
        try:
            sujet = bdd.execute("SELECT * FROM polls WHERE id=?", (id_sujet,)).fetchone()
            if sujet is None:
                raise HTTPException(status_code=404, detail="Vote introuvable")
            if poll_phase(sujet) == "ended":
                raise HTTPException(status_code=409, detail="Vote terminé")
            while True:
                code = str(secrets.randbelow(9_000_000_000) + 1_000_000_000)
                try:
                    bdd.execute("INSERT INTO access_codes (poll_id,code_hash,created_at) VALUES (?,?,?)",
                               (id_sujet, code_digest(code), int(time.time())))
                    break
                except sqlite3.IntegrityError:
                    continue
            bdd.execute("COMMIT")
        except Exception:
            if bdd.in_transaction:
                bdd.execute("ROLLBACK")
            raise
    requete.session["new_code"] = {"poll_id": id_sujet, "code": code}
    return redirect_to(f"/admin/polls/{id_sujet}")


@app.post("/admin/polls/{id_sujet}/schedule")
async def update_poll_schedule(requete: Request, id_sujet: int):
    if acces_refuse := require_admin(requete):
        return acces_refuse
    formulaire = await requete.form()
    csrf_check(requete, formulaire)
    horaires = schedule_from_form(formulaire)
    if horaires is None:
        raise HTTPException(status_code=400, detail="Heures invalides : la fin doit être future et après le début")
    with connect_db() as bdd:
        bdd.execute("BEGIN IMMEDIATE")
        try:
            sujet = bdd.execute("SELECT * FROM polls WHERE id=?", (id_sujet,)).fetchone()
            if sujet is None:
                raise HTTPException(status_code=404, detail="Vote introuvable")
            if poll_phase(sujet) == "ended":
                raise HTTPException(status_code=409, detail="Impossible de changer les dates d'un vote terminé")
            bdd.execute("UPDATE polls SET starts_at=?, ends_at=? WHERE id=?",
                       (horaires[0], horaires[1], id_sujet))
            bdd.execute("COMMIT")
        except Exception:
            if bdd.in_transaction:
                bdd.execute("ROLLBACK")
            raise
    return redirect_to(f"/admin/polls/{id_sujet}?schedule_saved=1")



@app.post("/admin/polls/{id_sujet}/delete")
async def delete_poll(requete: Request, id_sujet: int):
    if acces_refuse := require_admin(requete):
        return acces_refuse
    formulaire = await requete.form()
    csrf_check(requete, formulaire)
    confirmation = str(formulaire.get("confirmation_titre", ""))
    with connect_db() as bdd:
        bdd.execute("BEGIN IMMEDIATE")
        try:
            sujet = bdd.execute("SELECT title FROM polls WHERE id=?", (id_sujet,)).fetchone()
            if sujet is None:
                raise HTTPException(status_code=404, detail="Sujet introuvable")
            if not hmac.compare_digest(confirmation.encode("utf-8"), sujet["title"].encode("utf-8")):
                raise HTTPException(status_code=400, detail="Titre de confirmation incorrect")
            bdd.execute("DELETE FROM ballots WHERE poll_id=?", (id_sujet,))
            bdd.execute("DELETE FROM access_codes WHERE poll_id=?", (id_sujet,))
            bdd.execute("DELETE FROM poll_options WHERE poll_id=?", (id_sujet,))
            bdd.execute("DELETE FROM polls WHERE id=?", (id_sujet,))
            bdd.execute("COMMIT")
        except Exception:
            if bdd.in_transaction:
                bdd.execute("ROLLBACK")
            raise
    requete.session.pop("new_code", None)
    return redirect_to("/admin?deleted=1")


@app.post("/admin/polls/{id_sujet}/close")
async def close_poll(requete: Request, id_sujet: int):
    if acces_refuse := require_admin(requete):
        return acces_refuse
    formulaire = await requete.form()
    csrf_check(requete, formulaire)
    with connect_db() as bdd:
        resultat = bdd.execute("UPDATE polls SET is_open=0 WHERE id=?", (id_sujet,))
        if resultat.rowcount == 0:
            raise HTTPException(status_code=404, detail="Vote introuvable")
    return redirect_to(f"/admin/polls/{id_sujet}?closed=1")


@app.get("/admin/users")
async def admin_users_page(requete: Request):
    if acces_refuse := require_owner(requete):
        return acces_refuse
    with connect_db() as bdd:
        administrateurs = [dict(ligne) for ligne in bdd.execute(
            "SELECT id,username,role,created_at FROM admin_users ORDER BY id"
        )]
    return render(requete, "admin_users.html", users=administrateurs,
                  created=requete.query_params.get("created") == "1",
                  removed=requete.query_params.get("removed") == "1",
                  changed=requete.query_params.get("changed") == "1")


@app.post("/admin/users/create")
async def create_admin_user(requete: Request):
    if acces_refuse := require_owner(requete):
        return acces_refuse
    formulaire = await requete.form()
    csrf_check(requete, formulaire)
    identifiant = str(formulaire.get("username", "")).strip()
    mot_de_passe = str(formulaire.get("password", ""))
    import re
    identifiant_valide = re.fullmatch(r"[A-Za-z0-9_-]{3,32}", identifiant) is not None
    mot_de_passe_valide = 12 <= len(mot_de_passe) <= 256
    if not identifiant_valide or not mot_de_passe_valide:
        raise HTTPException(status_code=400, detail="Identifiant (3 à 32 caractères simples) et mot de passe (12 caractères minimum) requis")
    with connect_db() as bdd:
        try:
            bdd.execute(
                "INSERT INTO admin_users(username,password_hash,role,created_at) VALUES (?,?,?,?)",
                (identifiant, password_hash(mot_de_passe), "admin", int(time.time())),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="Cet identifiant existe déjà")
    return redirect_to("/admin/users?created=1")


@app.post("/admin/users/{id_administrateur}/password")
async def reset_admin_password(requete: Request, id_administrateur: int):
    if acces_refuse := require_owner(requete):
        return acces_refuse
    formulaire = await requete.form()
    csrf_check(requete, formulaire)
    nouveau_mot_de_passe = str(formulaire.get("password", ""))
    if not 12 <= len(nouveau_mot_de_passe) <= 256:
        raise HTTPException(status_code=400, detail="Le mot de passe doit contenir entre 12 et 256 caractères")
    with connect_db() as bdd:
        resultat = bdd.execute(
            "UPDATE admin_users SET password_hash=?, auth_version=auth_version+1 WHERE id=?",
            (password_hash(nouveau_mot_de_passe), id_administrateur),
        )
        if resultat.rowcount == 0:
            raise HTTPException(status_code=404, detail="Compte introuvable")
    if admin_account(requete) is None:
        requete.session.clear()
        return redirect_to("/admin/login")
    return redirect_to("/admin/users?changed=1")


@app.post("/admin/users/{id_administrateur}/delete")
async def remove_admin_user(requete: Request, id_administrateur: int):
    if acces_refuse := require_owner(requete):
        return acces_refuse
    formulaire = await requete.form()
    csrf_check(requete, formulaire)
    if id_administrateur == admin_account(requete)["id"]:
        raise HTTPException(status_code=400, detail="Impossible de supprimer son propre compte")
    with connect_db() as bdd:
        bdd.execute("BEGIN IMMEDIATE")
        try:
            ligne = bdd.execute("SELECT username,role FROM admin_users WHERE id=?", (id_administrateur,)).fetchone()
            if ligne is None:
                raise HTTPException(status_code=404, detail="Compte introuvable")
            if ligne["role"] == "owner":
                raise HTTPException(status_code=403, detail="Impossible de supprimer le compte principal")
            confirmation_identifiant = str(formulaire.get("confirmation_identifiant", ""))
            if not hmac.compare_digest(confirmation_identifiant, ligne["username"]):
                raise HTTPException(status_code=400, detail="Identifiant de confirmation incorrect")
            bdd.execute("DELETE FROM admin_users WHERE id=?", (id_administrateur,))
            bdd.execute("COMMIT")
        except Exception:
            if bdd.in_transaction:
                bdd.execute("ROLLBACK")
            raise
    return redirect_to("/admin/users?removed=1")
