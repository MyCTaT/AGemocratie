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
            CREATE TABLE IF NOT EXISTS assemblies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL
            );
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
            CREATE TABLE IF NOT EXISTS assembly_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assembly_id INTEGER NOT NULL REFERENCES assemblies(id),
                code_hash TEXT NOT NULL UNIQUE,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS codes_by_assembly ON assembly_codes(assembly_id);
            -- Un code a voté sur tel sujet ; sans horodatage ni ordre d'insertion,
            -- pour ne pas pouvoir rapprocher un code de son bulletin.
            CREATE TABLE IF NOT EXISTS code_uses (
                code_id INTEGER NOT NULL REFERENCES assembly_codes(id),
                poll_id INTEGER NOT NULL REFERENCES polls(id),
                PRIMARY KEY (code_id, poll_id)
            ) WITHOUT ROWID;
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
        if "assembly_id" not in colonnes:
            bdd.execute("ALTER TABLE polls ADD COLUMN assembly_id INTEGER REFERENCES assemblies(id)")
        bdd.execute("CREATE INDEX IF NOT EXISTS polls_by_assembly ON polls(assembly_id)")
    migrate_to_assemblies()


def migrate_to_assemblies():
    """Reprend les données de l'ancienne version (un code par sujet) sans rien perdre.

    Chaque ancien sujet devient une AG contenant ce seul sujet ; ses codes, déjà
    distribués, restent valables. Une copie de la base est faite avant la migration.
    """
    with connect_db() as bdd:
        ancienne_table = bdd.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='access_codes'"
        ).fetchone() is not None
        sujets_orphelins = bdd.execute("SELECT COUNT(*) FROM polls WHERE assembly_id IS NULL").fetchone()[0]
        if not ancienne_table and sujets_orphelins == 0:
            return
        sauvegarde_base(bdd, "avant-migration-ag")
        bdd.execute("BEGIN IMMEDIATE")
        try:
            for sujet in bdd.execute(
                "SELECT id,title,description,created_at FROM polls WHERE assembly_id IS NULL"
            ).fetchall():
                id_assemblee = bdd.execute(
                    "INSERT INTO assemblies (title,description,created_at) VALUES (?,?,?)",
                    (sujet["title"], sujet["description"], sujet["created_at"]),
                ).lastrowid
                bdd.execute("UPDATE polls SET assembly_id=? WHERE id=?", (id_assemblee, sujet["id"]))
            if ancienne_table:
                bdd.execute(
                    """INSERT INTO assembly_codes (id,assembly_id,code_hash,created_at)
                       SELECT c.id, p.assembly_id, c.code_hash, c.created_at
                       FROM access_codes c JOIN polls p ON p.id=c.poll_id"""
                )
                bdd.execute(
                    "INSERT INTO code_uses (code_id,poll_id) "
                    "SELECT id, poll_id FROM access_codes WHERE used_at IS NOT NULL"
                )
                bdd.execute("DROP TABLE access_codes")
            bdd.execute("COMMIT")
        except Exception:
            if bdd.in_transaction:
                bdd.execute("ROLLBACK")
            raise


def sauvegarde_base(bdd: sqlite3.Connection, motif: str) -> Path:
    """Copie cohérente de la base, à côté du fichier d'origine."""
    horodatage = datetime.now(ZoneInfo("Europe/Paris")).strftime("%Y%m%d-%H%M%S")
    chemin = CHEMIN_BASE_DONNEES.with_name(f"{CHEMIN_BASE_DONNEES.stem}.{motif}.{horodatage}.bak")
    copie = sqlite3.connect(chemin)
    try:
        bdd.backup(copie)
    finally:
        copie.close()
    return chemin


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


def assembly_phase(sujets) -> str:
    """En cours si au moins un sujet est ouvert, à venir s'il en reste un à ouvrir."""
    phases = {poll_phase(sujet) for sujet in sujets}
    if "open" in phases:
        return "open"
    if "upcoming" in phases or not phases:
        return "upcoming"
    return "ended"


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
        assemblees = [dict(ligne) for ligne in bdd.execute(
            "SELECT id,title,description FROM assemblies ORDER BY id DESC"
        )]
        sujets = bdd.execute(
            "SELECT id,assembly_id,is_open,starts_at,ends_at FROM polls"
        ).fetchall()
    for assemblee in assemblees:
        siens = [sujet for sujet in sujets if sujet["assembly_id"] == assemblee["id"]]
        debuts = [sujet["starts_at"] for sujet in siens if sujet["starts_at"] is not None]
        fins = [sujet["ends_at"] for sujet in siens if sujet["ends_at"] is not None]
        assemblee.update(phase=assembly_phase(siens), total_polls=len(siens),
                         starts_at=min(debuts, default=None), ends_at=max(fins, default=None))
    ordre = {"open": 0, "upcoming": 1, "ended": 2}
    assemblees.sort(key=lambda assemblee: (ordre[assemblee["phase"]], -assemblee["id"]))
    return render(requete, "home.html", assemblies=assemblees)


def assembly_page_data(bdd, id_assemblee):
    assemblee = bdd.execute(
        "SELECT id,title,description FROM assemblies WHERE id=?", (id_assemblee,)
    ).fetchone()
    if assemblee is None:
        raise HTTPException(status_code=404, detail="AG introuvable")
    sujets = bdd.execute(
        "SELECT id,title,description,is_open,starts_at,ends_at FROM polls "
        "WHERE assembly_id=? ORDER BY starts_at, id", (id_assemblee,)
    ).fetchall()
    return assemblee, sujets


def voter_code(bdd, requete: Request):
    """Code saisi par le votant dans cette session, s'il existe encore."""
    id_code = requete.session.get("voter_code_id")
    if not isinstance(id_code, int):
        return None
    return bdd.execute("SELECT id,assembly_id FROM assembly_codes WHERE id=?", (id_code,)).fetchone()


def render_assembly(requete: Request, bdd, id_assemblee, status_code=200, **contexte):
    assemblee, sujets = assembly_page_data(bdd, id_assemblee)
    code = voter_code(bdd, requete)
    deja_votes = set()
    if code is not None and code["assembly_id"] == id_assemblee:
        deja_votes = {ligne["poll_id"] for ligne in bdd.execute(
            "SELECT poll_id FROM code_uses WHERE code_id=?", (code["id"],))}
    else:
        code = None
    liste = [{**dict(sujet), "phase": poll_phase(sujet), "voted": sujet["id"] in deja_votes}
             for sujet in sujets]
    return render(requete, "assembly.html", status_code=status_code, assembly=assemblee,
                  polls=liste, phase=assembly_phase(sujets), has_code=code is not None,
                  success=requete.query_params.get("done") == "1", **contexte)


@app.get("/ag/{id_assemblee}")
async def public_assembly(requete: Request, id_assemblee: int):
    with connect_db() as bdd:
        return render_assembly(requete, bdd, id_assemblee)


@app.get("/polls/{id_sujet}")
async def public_poll(id_sujet: int):
    """Anciens liens par sujet : renvoie vers l'AG correspondante."""
    with connect_db() as bdd:
        sujet = bdd.execute("SELECT assembly_id FROM polls WHERE id=?", (id_sujet,)).fetchone()
    if sujet is None:
        raise HTTPException(status_code=404, detail="Sujet introuvable")
    return redirect_to(f"/ag/{sujet['assembly_id']}")


@app.post("/ag/{id_assemblee}/access")
async def access_assembly(requete: Request, id_assemblee: int):
    formulaire = await requete.form()
    csrf_check(requete, formulaire)
    code = str(formulaire.get("code", "")).strip()
    portee = scope_for(requete, "voter")
    with connect_db() as bdd:
        _, sujets = assembly_page_data(bdd, id_assemblee)
        if assembly_phase(sujets) != "open":
            return render_assembly(requete, bdd, id_assemblee, status_code=409,
                                   error="Aucun vote n'est ouvert dans cette AG.")
        if blocked(bdd, portee, 10):
            return render_assembly(requete, bdd, id_assemblee, status_code=429,
                                   error="Trop de tentatives. Réessayez dans 15 minutes.")
        ligne = None
        if len(code) == 10 and code.isascii() and code.isdigit():
            ligne = bdd.execute(
                "SELECT id FROM assembly_codes WHERE assembly_id=? AND code_hash=?",
                (id_assemblee, code_digest(code)),
            ).fetchone()
        if ligne is None:
            failed_attempt(bdd, portee)
            return render_assembly(requete, bdd, id_assemblee, status_code=400,
                                   error="Code invalide ou destiné à une autre AG.")
        bdd.execute("DELETE FROM rate_limits WHERE scope=?", (portee,))
    requete.session["voter_code_id"] = ligne["id"]
    return redirect_to(f"/ag/{id_assemblee}")


@app.post("/ag/leave")
async def leave_assembly(requete: Request):
    formulaire = await requete.form()
    csrf_check(requete, formulaire)
    requete.session.pop("voter_code_id", None)
    return redirect_to("/")


def votable_poll(bdd, code, id_sujet):
    """Le sujet si ce code peut encore y voter maintenant, sinon None."""
    if code is None:
        return None
    sujet = bdd.execute(
        "SELECT id,title,description,is_open,starts_at,ends_at,assembly_id FROM polls "
        "WHERE id=? AND assembly_id=?", (id_sujet, code["assembly_id"]),
    ).fetchone()
    if sujet is None or poll_phase(sujet) != "open":
        return None
    if bdd.execute("SELECT 1 FROM code_uses WHERE code_id=? AND poll_id=?",
                   (code["id"], id_sujet)).fetchone():
        return None
    return sujet


def back_to_assembly(code):
    return redirect_to(f"/ag/{code['assembly_id']}" if code is not None else "/")


@app.get("/vote/{id_sujet}")
async def voting_page(requete: Request, id_sujet: int):
    with connect_db() as bdd:
        code = voter_code(bdd, requete)
        sujet = votable_poll(bdd, code, id_sujet)
        if sujet is None:
            return back_to_assembly(code)
        propositions = bdd.execute("SELECT id,label FROM poll_options WHERE poll_id=? ORDER BY position", (sujet["id"],)).fetchall()
    return render(requete, "vote.html", poll=sujet, options=propositions)


@app.post("/vote/{id_sujet}")
async def submit_vote(requete: Request, id_sujet: int):
    formulaire = await requete.form()
    csrf_check(requete, formulaire)
    try:
        id_proposition = int(formulaire.get("option_id", ""))
    except (TypeError, ValueError):
        id_proposition = -1

    with connect_db() as bdd:
        bdd.execute("BEGIN IMMEDIATE")
        try:
            code = voter_code(bdd, requete)
            sujet = votable_poll(bdd, code, id_sujet)
            if sujet is None:
                bdd.execute("ROLLBACK")
                return back_to_assembly(code)
            proposition = bdd.execute(
                "SELECT id FROM poll_options WHERE id=? AND poll_id=?", (id_proposition, sujet["id"])
            ).fetchone()
            if not proposition:
                propositions = bdd.execute("SELECT id,label FROM poll_options WHERE poll_id=? ORDER BY position", (sujet["id"],)).fetchall()
                bdd.execute("ROLLBACK")
                return render(requete, "vote.html", status_code=400, poll=sujet, options=propositions,
                              error="Sélectionnez une proposition avant de valider.")
            bdd.execute("INSERT INTO code_uses (code_id,poll_id) VALUES (?,?)", (code["id"], sujet["id"]))
            bdd.execute("INSERT INTO ballots (poll_id,option_id,created_at) VALUES (?,?,?)",
                       (sujet["id"], id_proposition, int(time.time())))
            bdd.execute("COMMIT")
        except Exception:
            if bdd.in_transaction:
                bdd.execute("ROLLBACK")
            raise
    return redirect_to(f"/ag/{code['assembly_id']}?done=1")


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
        assemblees = [dict(ligne) for ligne in bdd.execute(
            """SELECT a.*,
               (SELECT COUNT(*) FROM assembly_codes c WHERE c.assembly_id=a.id) AS total_codes
               FROM assemblies a ORDER BY a.id DESC"""
        )]
        sujets = bdd.execute("SELECT assembly_id,is_open,starts_at,ends_at FROM polls").fetchall()
    for assemblee in assemblees:
        siens = [sujet for sujet in sujets if sujet["assembly_id"] == assemblee["id"]]
        assemblee.update(phase=assembly_phase(siens), total_polls=len(siens))
    return render(requete, "dashboard.html", assemblies=assemblees)


def assembly_form_valid(titre: str, description: str) -> bool:
    return 3 <= len(titre) <= 140 and len(description) <= 600


@app.get("/admin/ag/new")
async def create_assembly_page(requete: Request):
    if acces_refuse := require_admin(requete):
        return acces_refuse
    return render(requete, "new_assembly.html")


@app.post("/admin/ag/new")
async def create_assembly(requete: Request):
    if acces_refuse := require_admin(requete):
        return acces_refuse
    formulaire = await requete.form()
    csrf_check(requete, formulaire)
    titre = str(formulaire.get("title", "")).strip()
    description = str(formulaire.get("description", "")).strip()
    if not assembly_form_valid(titre, description):
        return render(requete, "new_assembly.html", status_code=400,
                      title_value=titre, description_value=description,
                      error="Le titre doit faire entre 3 et 140 caractères, la description 600 au plus.")
    with connect_db() as bdd:
        id_assemblee = bdd.execute(
            "INSERT INTO assemblies (title,description,created_at) VALUES (?,?,?)",
            (titre, description, int(time.time())),
        ).lastrowid
    return redirect_to(f"/admin/ag/{id_assemblee}?created=1")


def admin_assembly_or_404(bdd, id_assemblee):
    assemblee = bdd.execute("SELECT * FROM assemblies WHERE id=?", (id_assemblee,)).fetchone()
    if assemblee is None:
        raise HTTPException(status_code=404, detail="AG introuvable")
    return assemblee


@app.get("/admin/ag/{id_assemblee}")
async def admin_assembly_detail(requete: Request, id_assemblee: int):
    if acces_refuse := require_admin(requete):
        return acces_refuse
    with connect_db() as bdd:
        assemblee = admin_assembly_or_404(bdd, id_assemblee)
        total_codes = bdd.execute(
            "SELECT COUNT(*) FROM assembly_codes WHERE assembly_id=?", (id_assemblee,)
        ).fetchone()[0]
        lignes = bdd.execute(
            """SELECT p.*, (SELECT COUNT(*) FROM ballots b WHERE b.poll_id=p.id) AS total_votes
               FROM polls p WHERE p.assembly_id=? ORDER BY p.starts_at, p.id""", (id_assemblee,)
        ).fetchall()
    sujets = [{**dict(ligne), "phase": poll_phase(ligne)} for ligne in lignes]
    message_temporaire = requete.session.get("new_code")
    code_genere = None
    if isinstance(message_temporaire, dict) and message_temporaire.get("assembly_id") == id_assemblee:
        code_genere = message_temporaire.get("code")
        requete.session.pop("new_code", None)
    return render(requete, "assembly_detail.html", assembly=assemblee, polls=sujets,
                  phase=assembly_phase(lignes), total_codes=total_codes,
                  generated_code=code_genere,
                  created=requete.query_params.get("created") == "1",
                  deleted=requete.query_params.get("deleted") == "1")


@app.post("/admin/ag/{id_assemblee}/codes")
async def generate_codes(requete: Request, id_assemblee: int):
    if acces_refuse := require_admin(requete):
        return acces_refuse
    formulaire = await requete.form()
    csrf_check(requete, formulaire)
    with connect_db() as bdd:
        bdd.execute("BEGIN IMMEDIATE")
        try:
            admin_assembly_or_404(bdd, id_assemblee)
            sujets = bdd.execute(
                "SELECT is_open,starts_at,ends_at FROM polls WHERE assembly_id=?", (id_assemblee,)
            ).fetchall()
            if assembly_phase(sujets) == "ended":
                raise HTTPException(status_code=409, detail="Tous les votes de cette AG sont terminés")
            while True:
                code = str(secrets.randbelow(9_000_000_000) + 1_000_000_000)
                try:
                    bdd.execute("INSERT INTO assembly_codes (assembly_id,code_hash,created_at) VALUES (?,?,?)",
                               (id_assemblee, code_digest(code), int(time.time())))
                    break
                except sqlite3.IntegrityError:
                    continue
            bdd.execute("COMMIT")
        except Exception:
            if bdd.in_transaction:
                bdd.execute("ROLLBACK")
            raise
    requete.session["new_code"] = {"assembly_id": id_assemblee, "code": code}
    return redirect_to(f"/admin/ag/{id_assemblee}")


@app.post("/admin/ag/{id_assemblee}/delete")
async def delete_assembly(requete: Request, id_assemblee: int):
    if acces_refuse := require_admin(requete):
        return acces_refuse
    formulaire = await requete.form()
    csrf_check(requete, formulaire)
    confirmation = str(formulaire.get("confirmation_titre", ""))
    with connect_db() as bdd:
        bdd.execute("BEGIN IMMEDIATE")
        try:
            assemblee = admin_assembly_or_404(bdd, id_assemblee)
            if not hmac.compare_digest(confirmation.encode("utf-8"), assemblee["title"].encode("utf-8")):
                raise HTTPException(status_code=400, detail="Titre de confirmation incorrect")
            sujets_de_l_ag = "SELECT id FROM polls WHERE assembly_id=?"
            bdd.execute(f"DELETE FROM ballots WHERE poll_id IN ({sujets_de_l_ag})", (id_assemblee,))
            bdd.execute(f"DELETE FROM code_uses WHERE poll_id IN ({sujets_de_l_ag})", (id_assemblee,))
            bdd.execute(f"DELETE FROM poll_options WHERE poll_id IN ({sujets_de_l_ag})", (id_assemblee,))
            bdd.execute("DELETE FROM polls WHERE assembly_id=?", (id_assemblee,))
            bdd.execute("DELETE FROM assembly_codes WHERE assembly_id=?", (id_assemblee,))
            bdd.execute("DELETE FROM assemblies WHERE id=?", (id_assemblee,))
            bdd.execute("COMMIT")
        except Exception:
            if bdd.in_transaction:
                bdd.execute("ROLLBACK")
            raise
    requete.session.pop("new_code", None)
    return redirect_to("/admin?deleted=1")


@app.get("/admin/ag/{id_assemblee}/polls/new")
async def create_poll_page(requete: Request, id_assemblee: int):
    if acces_refuse := require_admin(requete):
        return acces_refuse
    with connect_db() as bdd:
        assemblee = admin_assembly_or_404(bdd, id_assemblee)
    return render(requete, "new_poll.html", assembly=assemblee)


@app.post("/admin/ag/{id_assemblee}/polls/new")
async def create_poll(requete: Request, id_assemblee: int):
    if acces_refuse := require_admin(requete):
        return acces_refuse
    formulaire = await requete.form()
    csrf_check(requete, formulaire)
    titre = str(formulaire.get("title", "")).strip()
    description = str(formulaire.get("description", "")).strip()
    propositions = [proposition.strip() for proposition in str(formulaire.get("options", "")).splitlines() if proposition.strip()]
    horaires = schedule_from_form(formulaire)
    with connect_db() as bdd:
        assemblee = admin_assembly_or_404(bdd, id_assemblee)
    if not (assembly_form_valid(titre, description)
            and 2 <= len(propositions) <= 10 and all(len(proposition) <= 140 for proposition in propositions)
            and len(set(proposition.casefold() for proposition in propositions)) == len(propositions)
            and horaires is not None):
        return render(requete, "new_poll.html", status_code=400, assembly=assemblee,
                      title_value=titre, description_value=description,
                      options_value="\n".join(propositions),
                      starts_value=str(formulaire.get("starts_at", "")),
                      ends_value=str(formulaire.get("ends_at", "")),
                      error="Vérifiez le titre, 2 à 10 réponses distinctes et les heures (fin future après début).")
    debut, fin = horaires
    with connect_db() as bdd:
        bdd.execute("BEGIN IMMEDIATE")
        try:
            admin_assembly_or_404(bdd, id_assemblee)
            id_sujet = bdd.execute(
                "INSERT INTO polls (title,description,created_at,starts_at,ends_at,assembly_id) VALUES (?,?,?,?,?,?)",
                (titre, description, int(time.time()), debut, fin, id_assemblee),
            ).lastrowid
            for indice, libelle in enumerate(propositions):
                bdd.execute("INSERT INTO poll_options(poll_id,label,position) VALUES (?,?,?)",
                           (id_sujet, libelle, indice))
            bdd.execute("COMMIT")
        except Exception:
            if bdd.in_transaction:
                bdd.execute("ROLLBACK")
            raise
    return redirect_to(f"/admin/polls/{id_sujet}?created=1")


def poll_details_data(bdd, id_sujet):
    sujet = bdd.execute("SELECT * FROM polls WHERE id=?", (id_sujet,)).fetchone()
    if sujet is None:
        raise HTTPException(status_code=404, detail="Vote introuvable")
    assemblee = bdd.execute("SELECT id,title FROM assemblies WHERE id=?", (sujet["assembly_id"],)).fetchone()
    total_codes = bdd.execute(
        "SELECT COUNT(*) FROM assembly_codes WHERE assembly_id=?", (sujet["assembly_id"],)
    ).fetchone()[0]
    lignes = bdd.execute(
        """SELECT o.id,o.label,COUNT(b.id) AS votes
           FROM poll_options o LEFT JOIN ballots b ON b.option_id=o.id
           WHERE o.poll_id=? GROUP BY o.id ORDER BY o.position""", (id_sujet,)
    ).fetchall()
    total_votes_enregistres = sum(ligne["votes"] for ligne in lignes)
    resultats = [{"label": ligne["label"], "votes": ligne["votes"],
                "percent": round(100 * ligne["votes"] / total_votes_enregistres, 1) if total_votes_enregistres else 0}
               for ligne in lignes]
    return sujet, assemblee, total_codes, resultats, total_votes_enregistres


@app.get("/admin/polls/{id_sujet}")
async def admin_poll_detail(requete: Request, id_sujet: int):
    if acces_refuse := require_admin(requete):
        return acces_refuse
    with connect_db() as bdd:
        sujet, assemblee, total_codes, resultats, total_votes_enregistres = poll_details_data(bdd, id_sujet)
    etat = poll_phase(sujet)
    return render(requete, "poll_detail.html", poll=sujet, assembly=assemblee,
                  total_codes=total_codes,
                  phase=etat, show_results=(etat == "ended"),
                  results=resultats if etat == "ended" else [],
                  total_votes=total_votes_enregistres if etat == "ended" else None,
                  created=requete.query_params.get("created") == "1",
                  closed=requete.query_params.get("closed") == "1",
                  schedule_saved=requete.query_params.get("schedule_saved") == "1")


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
            sujet = bdd.execute("SELECT title,assembly_id FROM polls WHERE id=?", (id_sujet,)).fetchone()
            if sujet is None:
                raise HTTPException(status_code=404, detail="Sujet introuvable")
            if not hmac.compare_digest(confirmation.encode("utf-8"), sujet["title"].encode("utf-8")):
                raise HTTPException(status_code=400, detail="Titre de confirmation incorrect")
            bdd.execute("DELETE FROM ballots WHERE poll_id=?", (id_sujet,))
            bdd.execute("DELETE FROM code_uses WHERE poll_id=?", (id_sujet,))
            bdd.execute("DELETE FROM poll_options WHERE poll_id=?", (id_sujet,))
            bdd.execute("DELETE FROM polls WHERE id=?", (id_sujet,))
            bdd.execute("COMMIT")
        except Exception:
            if bdd.in_transaction:
                bdd.execute("ROLLBACK")
            raise
    return redirect_to(f"/admin/ag/{sujet['assembly_id']}?deleted=1")


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
