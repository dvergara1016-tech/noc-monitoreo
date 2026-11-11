import os
import re
import time
import html
from urllib.parse import urlparse
import threading
import requests
from datetime import datetime, timezone, timedelta
from collections import deque
from concurrent.futures import ThreadPoolExecutor
import sqlite3
import secrets
import hmac
import hashlib
import json as _json
from functools import wraps
from flask import Flask, jsonify, Response, request, session, redirect, g
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

GRAFANA_URL = os.environ.get("GRAFANA_URL", "http://grafana_server:3000")
TOKEN = os.environ.get("GRAFANA_TOKEN", "")
HEADERS = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

# API de Zabbix (para leer los problemas/alertas). El token va en .env
ZABBIX_API_URL = os.environ.get("ZABBIX_API_URL", "http://TU-ZABBIX/api_jsonrpc.php")
ZABBIX_API_TOKEN = os.environ.get("ZABBIX_API_TOKEN", "")
HORAS_EVENTOS = 24          # historial de eventos de Zabbix que se muestra
# Telegram (token y chat id van en .env, nunca en el código)
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
TELEGRAM_NIVELES = {"crit", "warn", "ok"}   # quita "ok" para no recibir SSH exitosos ni recuperaciones
TELEGRAM_CADA_SEG = 30                      # cada cuánto revisa si hay eventos nuevos
TELEGRAM_MAX_POR_CICLO = 8                  # notificaciones por revisión; si hay más, se envía un resumen
TELEGRAM_INCLUIR_EVENTOS_NOC = False        # True = también los eventos propios del NOC (suelen repetir a Zabbix)
NOC_NOMBRE = os.environ.get("NOC_NOMBRE", "NOC")   # aparece en el encabezado: NOTIFICACIÓN NOC // <nombre>
ZONA_HORARIA_UTC = -5                       # Colombia
MINUTOS_ALERTA_LOG = 30     # alertas tipo log (SSH) se consideran activas este tiempo
SEVERIDAD_MINIMA_ALERTA = 2 # 2=Warning, 3=Average, 4=High, 5=Disaster (las de nivel 0-1 no son alertas)

# ================= CONFIGURACIÓN =================
ZABBIX_DS_UID = os.environ.get("ZABBIX_DS_UID") or "eg221t88guq68f"   # UID de la fuente de datos Zabbix en Grafana
GRUPO = "/.*/"
HORAS_HISTORIAL = 1
SEGUNDOS_CACHE = 10
MAX_EVENTOS = 200

# Cada dispositivo muestra su panel de puertos y sus gráficas.
#  - filtro_puertos: regex de las interfaces que se dibujan como puertos
#  - con_puertos: False si el equipo no tiene interfaces en Zabbix
#  - graficas: cuáles gráficas aplican ("traf", "lat", "cpu")
#  - cpu / lat: item a graficar (None si no existe)
#  - badge: texto corto de la tarjeta lateral
LAT = "/ICMP response time/"
TODAS = ["traf", "lat", "cpu"]

# Interfaces físicas del FortiGate. Se aceptan por nombre (lista blanca) para dejar fuera las virtuales
# (ssl.root, naf.*, l2t.*, vsys_*, tunnel, VLAN con punto como wan1.100...).
# Cubre: port1.., x1.. y sfp1.. (fibra), wan1.., lan, dmz, ha, mgmt, internal1.., a/b.
# Si tu modelo usa otros nombres, defínelo en el environment:  NOC_FG_FILTRO=<regex>
_FG_BASE = os.environ.get("NOC_FG_FILTRO") or (
    r"^(?![^(]*\.)(?:(?:port|x|fiber|fibra|wan|lan|internal)\d|sfp|dmz|ha\d*|mgmt\d*|wan|lan|internal|[ab](?:\(|$))")
# Puertos que no usas y quieres ocultar (evita que un wan2 sin cable salga como proveedor caído):
#   NOC_PUERTOS_OCULTOS=wan2,ha1,ha2,dmz
_ocultos = [re.escape(x.strip()) for x in os.environ.get("NOC_PUERTOS_OCULTOS", "").split(",") if x.strip()]
FG_FILTRO = "(?i)" + ((r"^(?!(?:%s)(?:\(|$))(?:%s)" % ("|".join(_ocultos), _FG_BASE)) if _ocultos else _FG_BASE)   # sin distinguir mayúsculas
# Interfaces que se pintan como fibra (SFP/SFP+): por nombre o por el alias que les pusiste en el FortiGate
FIBRA_RE = re.compile(r"sfp|fibra|fiber|^x\d|^ten|^te\d", re.I)

DISPOSITIVOS = [
    {"id": "fgdata", "host": "FG-DATA", "titulo": "FortiGate",
     "subtitulo": "FG-DATA // Firewall", "badge": "FW",
     "panel": "Panel frontal · estado de puertos",
     "filtro_puertos": FG_FILTRO, "graficas": TODAS,
     "cpu": "FortiGate: CPU utilization", "lat": LAT},

    # Windows by Zabbix agent (sin ICMP)
    {"id": "dataserver", "host": "DATASERVER", "titulo": "Servidor de datos",
     "subtitulo": "DATASERVER // Windows Server", "badge": "SRV",
     "panel": "Interfaces de red · estado",
     "filtro_puertos": r"^(?!.*(Loopback|Pseudo|isatap|Teredo|WAN Miniport|Virtual|Bluetooth|Filter|QoS|Kernel Debug)).*",
     "graficas": ["traf", "cpu"],
     "cpu": "/CPU utilization/", "lat": None},

    # Linux by Zabbix agent
    {"id": "glpisrv", "host": "GLPI-SRV", "titulo": "Servidor GLPI",
     "subtitulo": "GLPI-SRV // Linux (GLPI)", "badge": "SRV",
     "panel": "Interfaces de red · estado",
     "filtro_puertos": r"^(eth|ens|enp|eno)", "graficas": TODAS,
     "cpu": "Linux: CPU utilization", "lat": LAT},

    # Windows by Zabbix agent (sin ICMP)
    {"id": "dshost", "host": "SRV-DSHOST", "titulo": "Servidor DS-Host",
     "subtitulo": "SRV-DSHOST // Windows Server", "badge": "SRV",
     "panel": "Interfaces de red · estado",
     "filtro_puertos": r"^(?!.*(Loopback|Pseudo|isatap|Teredo|WAN Miniport|Virtual|Bluetooth|Filter|QoS|Kernel Debug)).*",
     "graficas": ["traf", "cpu"],
     "cpu": "/CPU utilization/", "lat": None},

    # Servidor Zabbix - Linux by Zabbix agent (sin ICMP)
    {"id": "zabbixsrv", "host": "Zabbix server", "titulo": "Zabbix server",
     "subtitulo": "Zabbix server // Linux (Monitoreo)", "badge": "SRV",
     "panel": "Interfaces de red · estado",
     "filtro_puertos": r"^(eth|ens|enp|eno)", "graficas": ["traf", "cpu"],
     "cpu": "Linux: CPU utilization", "lat": None},

    # Servidor de inventario (Snipe-IT) - Linux by Zabbix agent
    {"id": "snipe", "host": "snipe", "titulo": "Servidor Inventario",
     "subtitulo": "snipe // Linux (Inventario)", "badge": "SRV",
     "panel": "Interfaces de red · estado",
     "filtro_puertos": r"^(eth|ens|enp|eno)", "graficas": TODAS,
     "cpu": "Linux: CPU utilization", "lat": LAT},
]


def _std(host, cpu=None, mem=None, perdida=False):
    """Tarjetas estándar de un equipo con ICMP: ping y latencia, más lo que aplique."""
    m = [
        {"host": host, "label": "Ping", "item": "/ICMP ping/", "tipo": "estado"},
        {"host": host, "label": "Latencia", "item": LAT,
         "unidad": " ms", "mult": 1000, "warn": 50, "crit": 100},
    ]
    if perdida:
        m.append({"host": host, "label": "Pérdida", "item": "/ICMP loss/",
                  "unidad": "%", "warn": 1, "crit": 10})
    if cpu:
        m.append({"host": host, "label": "CPU", "item": cpu,
                  "unidad": "%", "warn": 70, "crit": 90})
    if mem:
        m.append({"host": host, "label": "Memoria", "item": mem,
                  "unidad": "%", "warn": 80, "crit": 95})
    return m


METRICAS = (
    _std("FG-DATA", "FortiGate: CPU utilization", "FortiGate: Used memory")
    + [
        # DATASERVER: Windows by Zabbix agent (no tiene ICMP)
        {"host": "DATASERVER", "label": "Agente", "item": "/agent ping/", "tipo": "estado"},
        {"host": "DATASERVER", "label": "CPU", "item": "/CPU utilization/",
         "unidad": "%", "warn": 70, "crit": 90},
        {"host": "DATASERVER", "label": "Memoria", "item": "/Memory utilization/",
         "unidad": "%", "warn": 80, "crit": 95},
    ]
    + _std("GLPI-SRV", "Linux: CPU utilization", "Linux: Memory utilization")
    + [
        # SRV-DSHOST: Windows by Zabbix agent (no tiene ICMP)
        {"host": "SRV-DSHOST", "label": "Agente", "item": "/agent ping/", "tipo": "estado"},
        {"host": "SRV-DSHOST", "label": "CPU", "item": "/CPU utilization/",
         "unidad": "%", "warn": 70, "crit": 90},
        {"host": "SRV-DSHOST", "label": "Memoria", "item": "/Memory utilization/",
         "unidad": "%", "warn": 80, "crit": 95},
        # Zabbix server: Linux by Zabbix agent
        {"host": "Zabbix server", "label": "CPU",
         "item": "Linux: CPU utilization", "unidad": "%", "warn": 70, "crit": 90},
        {"host": "Zabbix server", "label": "Memoria",
         "item": "Linux: Memory utilization", "unidad": "%", "warn": 80, "crit": 95},
    ]
    + _std("snipe", "Linux: CPU utilization", "Linux: Memory utilization")
)
# =================================================

_cache = {"t": 0, "datos": None}
_lock = threading.Lock()
_prev = {}
_vistos_up = set()
EVENTOS = deque(maxlen=MAX_EVENTOS)
_seq = [0]


# ======================= AUTENTICACIÓN, USUARIOS Y ROLES =======================
DB_PATH = os.environ.get("NOC_DB", "/data/noc.db")
CORS_ORIGEN = os.environ.get("NOC_CORS_ORIGEN", "*")   # origen permitido para apps con token
SESION_HORAS = 8          # la sesión se cierra a las 8 h
MAX_FALLOS = 5            # intentos fallidos antes de bloquear el usuario
BLOQUEO_SEG = 300         # 5 minutos de bloqueo
CLAVE_MIN = 10            # largo mínimo de contraseña

PERMISOS = {
    "ver": "Ver el panel NOC (equipos, alertas y eventos)",
    "exportar": "Exportar el registro de eventos en JSON",
    "diagnostico": "Páginas de diagnóstico y prueba de Telegram",
    "usuarios": "Administrar usuarios, roles y auditoría",
}
ROLES_INICIALES = [
    ("Administrador", ["ver", "exportar", "diagnostico", "usuarios"], 1),
    ("Operador", ["ver", "exportar", "diagnostico"], 0),
    ("Solo lectura", ["ver"], 0),
]
RE_USUARIO = re.compile(r"^[A-Za-z0-9._-]{3,32}$")
HASH_FALSO = generate_password_hash("clave-falsa-para-igualar-tiempos")
_fallos = {}   # usuario -> [intentos, bloqueado_hasta]

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,           # el NOC corre en HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(hours=SESION_HORAS),
)


def db():
    carpeta = os.path.dirname(DB_PATH)
    if carpeta:
        os.makedirs(carpeta, exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con


def consulta(sql, p=(), uno=False):
    con = db()
    try:
        cur = con.execute(sql, p)
        return cur.fetchone() if uno else cur.fetchall()
    finally:
        con.close()


def ejecutar(sql, p=()):
    con = db()
    try:
        cur = con.execute(sql, p)
        con.commit()
        return cur.lastrowid
    finally:
        con.close()


def iniciar_auth():
    con = db()
    try:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY, nombre TEXT UNIQUE NOT NULL COLLATE NOCASE,
            permisos TEXT NOT NULL, sistema INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY, usuario TEXT UNIQUE NOT NULL COLLATE NOCASE,
            nombre TEXT, clave TEXT NOT NULL,
            rol_id INTEGER NOT NULL REFERENCES roles(id),
            activo INTEGER NOT NULL DEFAULT 1, sv INTEGER NOT NULL DEFAULT 1,
            creado INTEGER, ultimo_acceso INTEGER);
        CREATE TABLE IF NOT EXISTS ajustes (clave TEXT PRIMARY KEY, valor TEXT);
        CREATE TABLE IF NOT EXISTS auditoria (
            id INTEGER PRIMARY KEY, ts INTEGER, usuario TEXT, accion TEXT,
            detalle TEXT, ip TEXT);
        CREATE TABLE IF NOT EXISTS tokens (
            id INTEGER PRIMARY KEY, nombre TEXT NOT NULL, hash TEXT UNIQUE NOT NULL,
            prefijo TEXT, usuario_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
            creado INTEGER, ultimo_uso INTEGER);
        """)
        # Limpieza: la versión con asistente de IA guardó un permiso "asistente" en los roles; ya no existe
        for rid, perms in con.execute("SELECT id, permisos FROM roles").fetchall():
            lista = [p for p in (perms or "").split(",") if p]
            limpia = [p for p in lista if p != "asistente"]
            if limpia != lista:
                con.execute("UPDATE roles SET permisos=? WHERE id=?", (",".join(limpia), rid))
        con.commit()
        if con.execute("SELECT COUNT(*) FROM roles").fetchone()[0] == 0:
            for nombre, perms, sistema in ROLES_INICIALES:
                con.execute("INSERT INTO roles (nombre, permisos, sistema) VALUES (?,?,?)",
                            (nombre, ",".join(perms), sistema))
        fila = con.execute("SELECT valor FROM ajustes WHERE clave='secret_key'").fetchone()
        if not fila:
            con.execute("INSERT INTO ajustes VALUES ('secret_key', ?)", (secrets.token_hex(32),))
        con.commit()
        # Administrador inicial opcional por variable de entorno
        clave_ini = os.environ.get("NOC_ADMIN_PASSWORD", "")
        if clave_ini and con.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0] == 0:
            rol = con.execute("SELECT id FROM roles WHERE nombre='Administrador'").fetchone()[0]
            con.execute("INSERT INTO usuarios (usuario, nombre, clave, rol_id, creado) VALUES (?,?,?,?,?)",
                        (os.environ.get("NOC_ADMIN_USER", "admin"), "Administrador",
                         generate_password_hash(clave_ini), rol, int(time.time())))
            con.commit()
        app.secret_key = os.environ.get("SECRET_KEY") or \
            con.execute("SELECT valor FROM ajustes WHERE clave='secret_key'").fetchone()[0]
    finally:
        con.close()


def auditar(accion, detalle="", usuario=None):
    try:
        if usuario is None:
            usuario = g.usuario["usuario"] if getattr(g, "usuario", None) else "-"
        ip = request.remote_addr if request else "-"
        ejecutar("INSERT INTO auditoria (ts, usuario, accion, detalle, ip) VALUES (?,?,?,?,?)",
                 (int(time.time()), usuario, accion, detalle[:300], ip))
    except Exception:
        pass


def sin_usuarios():
    return consulta("SELECT COUNT(*) AS n FROM usuarios", uno=True)["n"] == 0


def usuario_actual():
    uid = session.get("uid")
    if not uid:
        return None
    fila = consulta("""SELECT u.*, r.nombre AS rol, r.permisos AS permisos
                       FROM usuarios u JOIN roles r ON r.id = u.rol_id WHERE u.id=?""",
                    (uid,), uno=True)
    if not fila or not fila["activo"] or fila["sv"] != session.get("sv"):
        session.clear()
        return None
    d = dict(fila)
    d["permisos"] = set(p for p in fila["permisos"].split(",") if p)
    return d


def hash_token(t):
    return hashlib.sha256(t.encode()).hexdigest()


def usuario_por_token(token):
    fila = consulta("""SELECT u.*, r.nombre AS rol, r.permisos AS permisos, t.id AS token_id
                       FROM tokens t JOIN usuarios u ON u.id = t.usuario_id
                       JOIN roles r ON r.id = u.rol_id
                       WHERE t.hash=? AND u.activo=1""", (hash_token(token),), uno=True)
    if not fila:
        return None
    ejecutar("UPDATE tokens SET ultimo_uso=? WHERE id=?", (int(time.time()), fila["token_id"]))
    d = dict(fila)
    d["permisos"] = set(p for p in fila["permisos"].split(",") if p)
    return d


def asegurar_csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


def otros_admins(excluir_uid=None, excluir_rol=None):
    """Cuántos usuarios activos con permiso 'usuarios' quedarían, sin contar a uno."""
    sql = """SELECT COUNT(*) AS n FROM usuarios u JOIN roles r ON r.id=u.rol_id
             WHERE u.activo=1 AND (',' || r.permisos || ',') LIKE '%,usuarios,%'"""
    p = []
    if excluir_uid is not None:
        sql += " AND u.id != ?"
        p.append(excluir_uid)
    if excluir_rol is not None:
        sql += " AND u.rol_id != ?"
        p.append(excluir_rol)
    return consulta(sql, p, uno=True)["n"]


def validar_clave(c):
    if len(c) < CLAVE_MIN:
        return f"La contraseña debe tener al menos {CLAVE_MIN} caracteres."
    if len(c) > 128:
        return "La contraseña es demasiado larga."
    if c.isdigit():
        return "La contraseña no puede ser solo números."
    return ""


def bloqueo_restante(usuario):
    est = _fallos.get(usuario.lower())
    if est and est[1] > time.time():
        return int(est[1] - time.time())
    return 0


def registrar_fallo(usuario):
    est = _fallos.setdefault(usuario.lower(), [0, 0])
    est[0] += 1
    if est[0] >= MAX_FALLOS:
        est[0], est[1] = 0, time.time() + BLOQUEO_SEG


def requiere(permiso):
    def deco(f):
        @wraps(f)
        def envoltura(*a, **k):
            if permiso not in g.usuario["permisos"]:
                if request.path.startswith("/api/"):
                    return jsonify({"error": "Tu rol no tiene permiso para esto"}), 403
                return pagina("Sin permiso",
                              "<div class='caja'><h1>SIN PERMISO</h1>"
                              "<p>Tu rol no permite ver esta sección.</p>"
                              "<p><a href='/'>Volver</a></p></div>"), 403
            return f(*a, **k)
        return envoltura
    return deco


@app.before_request
def guardia():
    ep = request.endpoint
    if ep == "static":
        return
    if request.method == "OPTIONS" and request.path == "/api/data":
        return Response(status=204)          # preflight CORS (las cabeceras las pone cabeceras())
    cabecera = request.headers.get("Authorization", "")
    if cabecera.startswith("Bearer "):
        # Token de API: solo sirve para LEER /api/data
        if request.path != "/api/data" or request.method != "GET":
            return jsonify({"error": "El token de API solo permite leer /api/data"}), 403
        u = None if sin_usuarios() else usuario_por_token(cabecera[7:].strip())
        if not u:
            return jsonify({"error": "Token inválido o revocado"}), 401
        g.usuario = u
        return None
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        token = request.headers.get("X-CSRF") or request.form.get("csrf") or ""
        if not session.get("csrf") or not hmac.compare_digest(token, session["csrf"]):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Sesión inválida. Recarga la página."}), 400
            return "Solicitud inválida. Vuelve atrás, recarga la página e inténtalo de nuevo.", 400
    if sin_usuarios():
        return None if ep == "setup" else redirect("/setup")
    if ep in ("login", "setup", "logout"):
        return None
    g.usuario = usuario_actual()
    if not g.usuario:
        if request.path.startswith("/api/"):
            return jsonify({"error": "No autenticado"}), 401
        return redirect("/login")
    return None


@app.after_request
def cabeceras(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    if request.path.startswith("/api/") or request.path in ("/", "/login", "/admin", "/cuenta"):
        resp.headers["Cache-Control"] = "no-store"
    if request.path == "/api/data" and request.headers.get("Origin"):
        # Sin cookies: solo responde datos si la petición trae un token Bearer válido
        resp.headers["Access-Control-Allow-Origin"] = CORS_ORIGEN
        resp.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        resp.headers["Access-Control-Allow-Private-Network"] = "true"
        resp.headers["Access-Control-Max-Age"] = "600"
        resp.headers["Vary"] = "Origin"
    return resp


# ---------------- Páginas de apoyo ----------------
ESTILO_BASE = """
:root{--bg:#12143a;--bgimg:radial-gradient(900px 620px at 8% -8%,rgba(124,108,240,.55),transparent 62%),radial-gradient(900px 700px at 100% 105%,rgba(47,91,234,.50),transparent 60%),radial-gradient(560px 460px at 70% 20%,rgba(143,160,255,.26),transparent 70%),radial-gradient(520px 420px at 28% 76%,rgba(99,179,237,.22),transparent 70%);
--card:linear-gradient(150deg,rgba(255,255,255,.13),rgba(255,255,255,.05));--chip:rgba(255,255,255,.10);--border:rgba(255,255,255,.16);--border2:rgba(255,255,255,.28);
--text:#f1f3ff;--muted:#a3abd6;--accent:#9fb8ff;--ok:#34d399;--warn:#fbbf24;--bad:#fb7185}
[data-theme="light"]{--bg:#cdd6f4;--bgimg:radial-gradient(820px 600px at 6% -6%,rgba(167,139,250,.55),transparent 62%),radial-gradient(900px 700px at 100% 104%,rgba(96,165,250,.55),transparent 60%),radial-gradient(600px 460px at 62% 12%,rgba(255,255,255,.55),transparent 70%),linear-gradient(160deg,#dfe5fb,#c6d0f3 55%,#b9c6ef);--card:linear-gradient(150deg,rgba(255,255,255,.68),rgba(255,255,255,.38));--chip:rgba(255,255,255,.64);--border:rgba(255,255,255,.78);--border2:rgba(120,135,200,.38);
--text:#141a3a;--muted:#59628c;--accent:#2f4fe0;--ok:#15803d;--warn:#b45309;--bad:#dc2626}
*{box-sizing:border-box}
body{margin:0;background-color:var(--bg);background-image:var(--bgimg);background-attachment:fixed;min-height:100vh;color:var(--text);font-family:"Segoe UI",system-ui,-apple-system,Roboto,Arial,sans-serif;font-size:14px}
a{color:var(--accent)}
h1{color:var(--accent);font-size:18px;letter-spacing:2px;margin:0 0 14px}
h2{color:var(--accent);font-size:13px;letter-spacing:1px;margin:0 0 10px}
.caja{max-width:420px;margin:8vh auto;background:var(--card);border:1px solid var(--border);border-radius:28px;padding:28px;box-shadow:0 14px 40px rgba(0,0,30,.5)}
.ancho{max-width:1100px;margin:24px auto;padding:0 16px}
.card{background:var(--card);border:1px solid var(--border);border-radius:26px;padding:20px;margin-bottom:16px;box-shadow:0 10px 30px rgba(0,0,30,.35)}
label{display:block;color:var(--muted);font-size:11px;letter-spacing:1px;margin:12px 0 4px}
input[type=text],input[type=password],select{width:100%;background:var(--chip);color:var(--text);
border:1px solid var(--border2);border-radius:12px;padding:9px 12px;font-family:inherit;font-size:14px}
input:focus,select:focus,button:focus-visible{outline:2px solid var(--accent)}
button,.btn{background:var(--chip);color:var(--text);border:1px solid var(--border2);border-radius:999px;
padding:7px 16px;cursor:pointer;font-family:inherit;font-size:13px;text-decoration:none;display:inline-block}
button.pri{background:linear-gradient(135deg,#2f5bea,#5b7cf6);border-color:transparent;color:#fff;box-shadow:0 8px 18px rgba(47,91,234,.30)}
button.mal{border-color:var(--bad);color:var(--bad)}
button.full{width:100%;margin-top:18px;padding:10px}
.err{color:var(--bad);font-size:13px;margin-top:10px;min-height:1em}
.okm{color:var(--ok);font-size:13px;margin-top:10px}
.muted{color:var(--muted);font-size:12px}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--border);font-size:13px;vertical-align:top}
th{color:var(--muted);font-size:11px;letter-spacing:1px;font-weight:normal}
.tabs{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap}
.tabs button.on{background:linear-gradient(135deg,#2f5bea,#5b7cf6);border-color:transparent;color:#fff}
.tag{display:inline-block;font-size:11px;border:1px solid var(--border2);border-radius:3px;padding:0 5px;margin:1px 3px 1px 0;color:var(--accent)}
.off{color:var(--bad)}
.top{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:16px}
dialog{background:var(--card);color:var(--text);border:1px solid var(--border2);border-radius:24px;padding:22px;width:min(440px,92vw)}
dialog::backdrop{background:rgba(2,6,20,.45);backdrop-filter:blur(5px)}
.caja,.card,dialog{-webkit-backdrop-filter:blur(22px) saturate(160%);backdrop-filter:blur(22px) saturate(160%);box-shadow:0 14px 40px rgba(0,0,30,.5),0 1px 0 rgba(255,255,255,.12) inset}
[data-theme="light"] .caja,[data-theme="light"] .card,[data-theme="light"] dialog{box-shadow:0 18px 40px rgba(70,80,160,.20),0 1px 0 rgba(255,255,255,.9) inset}
@media (prefers-reduced-transparency:reduce){:root:not([data-theme="light"]){--card:linear-gradient(165deg,rgba(11,27,77,.94),rgba(6,15,51,.97))}.caja,.card,dialog{-webkit-backdrop-filter:none;backdrop-filter:none}}
.chk{display:flex;gap:8px;align-items:flex-start;margin:8px 0;color:var(--text);font-size:13px}
.chk input{margin-top:3px}
.fila{display:flex;gap:8px;justify-content:flex-end;margin-top:16px}
"""

TEMA_JS = """
try{var t=localStorage.getItem('tema-noc');if(t)document.documentElement.setAttribute('data-theme',t);}catch(e){}
"""


def pagina(titulo, cuerpo, js="", css=""):
    return ("<!DOCTYPE html><html data-theme=\"light\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            f"<title>{html.escape(titulo)} · NOC</title><style>{ESTILO_BASE}{css}</style></head>"
            f"<body>{cuerpo}<script>{TEMA_JS}{js}</script></body></html>")


LOGIN_CSS = """
html,body{height:100%}
body{overflow-x:hidden}
.lg-fondo{position:fixed;inset:0;overflow:hidden;pointer-events:none;z-index:0}
.lg-fondo .orb,.lg-escena .orb{position:absolute;transform:translate3d(calc(var(--mx,0)*var(--d)*1px),calc(var(--my,0)*var(--d)*1px),0);transition:transform .6s cubic-bezier(.2,.7,.2,1)}
.orb i{display:block;width:100%;height:100%;border-radius:50%;
 background:radial-gradient(circle at 30% 26%,rgba(255,255,255,.62),rgba(255,255,255,0) 34%),
 radial-gradient(circle at 50% 50%,var(--o1),var(--o2) 68%,var(--o3));
 box-shadow:inset -10px -14px 30px rgba(0,10,50,.35),inset 8px 10px 22px rgba(255,255,255,.18),0 30px 70px var(--og);
 animation:lg-flota var(--t) ease-in-out infinite alternate;animation-delay:var(--dl,0s)}
.o-az{--o1:#8fd3ff;--o2:#0b3be6;--o3:#0b1b4d;--og:rgba(11,59,230,.45)}
.o-vi{--o1:#8aa9ff;--o2:#2151ed;--o3:#0b1b4d;--og:rgba(33,81,237,.45)}
.o-ci{--o1:#d4efff;--o2:#4cb8f5;--o3:#0b3be6;--og:rgba(76,184,245,.40)}
@keyframes lg-flota{0%{transform:translate3d(0,0,0) scale(1)}50%{transform:translate3d(10px,-22px,0) scale(1.03)}100%{transform:translate3d(-12px,14px,0) scale(.98)}}
.lg-fondo .f1{width:clamp(180px,26vw,380px);aspect-ratio:1;left:6%;top:10%;--d:-26;--t:11s}
.lg-fondo .f2{width:clamp(140px,19vw,280px);aspect-ratio:1;right:7%;bottom:9%;--d:30;--t:13s;--dl:-4s}
.lg-fondo .f3{width:clamp(70px,9vw,130px);aspect-ratio:1;right:18%;top:12%;--d:-44;--t:9s;--dl:-2s}
.lg-fondo .f4{width:clamp(60px,7vw,100px);aspect-ratio:1;left:14%;bottom:12%;--d:40;--t:10s;--dl:-6s}
.lg-pagina{position:relative;z-index:1;min-height:100vh;display:grid;place-items:center;padding:28px 16px}
.lg-escena{position:relative;width:min(400px,100%);perspective:1100px}
.lg-escena .e1{width:150px;height:150px;left:-62px;top:-46px;--d:-18;--t:8s;z-index:0}
.lg-escena .e2{width:190px;height:190px;right:-84px;bottom:-70px;--d:22;--t:10s;--dl:-3s;z-index:0}
.lg-escena .e3{width:64px;height:64px;right:30px;top:-30px;--d:-34;--t:7s;--dl:-1s;z-index:0}
.lg-card{position:relative;z-index:1;border-radius:26px;padding:34px 32px 26px;border:1px solid rgba(255,255,255,.20);
 background:linear-gradient(150deg,rgba(255,255,255,.13),rgba(60,100,230,.14) 38%,rgba(6,15,51,.38));
 -webkit-backdrop-filter:blur(22px) saturate(170%);backdrop-filter:blur(22px) saturate(170%);
 box-shadow:0 24px 70px rgba(0,0,30,.55),0 1px 0 rgba(255,255,255,.28) inset;
 transform:rotateY(calc(var(--mx,0)*4deg)) rotateX(calc(var(--my,0)*-3deg));transition:transform .5s cubic-bezier(.2,.7,.2,1);
 animation:lg-entra .8s cubic-bezier(.2,.8,.2,1) both;overflow:hidden}
.lg-card::after{content:"";position:absolute;inset:0;border-radius:inherit;pointer-events:none;
 background:radial-gradient(260px circle at var(--px,50%) var(--py,0%),rgba(255,255,255,.16),transparent 62%);opacity:.9}
@keyframes lg-entra{from{opacity:0;transform:translateY(26px) scale(.96)}to{opacity:1}}
.lg-card.lg-err{animation:lg-entra .8s both,lg-sacude .45s .1s}
@keyframes lg-sacude{20%,60%{translate:-9px 0}40%,80%{translate:9px 0}}
.lg-logo{position:relative;width:78px;height:78px;margin:0 auto 14px;border-radius:50%;display:grid;place-items:center;
 background:linear-gradient(145deg,rgba(255,255,255,.22),rgba(255,255,255,.05));border:1px solid rgba(255,255,255,.28);color:var(--accent)}
.lg-logo::before{content:"";position:absolute;inset:-7px;border-radius:50%;border:1px solid var(--accent);opacity:.0;animation:lg-pulso 3.4s ease-out infinite}
@keyframes lg-pulso{0%{transform:scale(.88);opacity:.55}100%{transform:scale(1.28);opacity:0}}
.lg-logo svg{width:38px;height:38px}
.lg-logo .lnk{stroke-dasharray:60;stroke-dashoffset:60;animation:lg-traza 1.4s .5s ease forwards}
@keyframes lg-traza{to{stroke-dashoffset:0}}
.lg-card h1{text-align:center;color:var(--text);font-size:19px;letter-spacing:.3px;font-weight:600;margin:0 0 4px}
.lg-sub{text-align:center;color:var(--muted);font-size:13px;margin:0 0 22px}
.lg-campo{position:relative;margin:0 0 18px}
.lg-campo>svg.ic{position:absolute;left:2px;top:17px;width:18px;height:18px;color:var(--muted);transition:color .25s}
.lg-campo input{width:100%;background:transparent;border:0;border-bottom:1px solid rgba(255,255,255,.28);border-radius:0;
 color:var(--text);font-size:15px;padding:20px 38px 7px 30px;outline:0;transition:border-color .25s}
.lg-campo label{position:absolute;left:30px;top:15px;margin:0;color:var(--muted);font-size:14px;letter-spacing:0;pointer-events:none;
 transform-origin:left top;transition:transform .22s ease,color .22s ease}
.lg-campo input:focus~label,.lg-campo input:not(:placeholder-shown)~label,.lg-campo input:-webkit-autofill~label{transform:translateY(-14px) scale(.78);color:var(--accent)}
.lg-campo input:-webkit-autofill{-webkit-text-fill-color:var(--text);transition:background-color 9999s}
.lg-campo:focus-within>svg.ic{color:var(--accent)}
.lg-campo .barra{position:absolute;left:0;right:0;bottom:0;height:2px;background:linear-gradient(90deg,#0b3be6,#8fd3ff);transform:scaleX(0);transform-origin:left;transition:transform .35s ease}
.lg-campo:focus-within .barra{transform:scaleX(1)}
.lg-ojo{position:absolute;right:0;top:11px;width:30px;height:30px;padding:0;border:0;background:transparent;color:var(--muted);border-radius:8px;display:grid;place-items:center;cursor:pointer}
.lg-ojo:hover{color:var(--accent)}
.lg-ojo svg{width:18px;height:18px}
.lg-ojo .ocu{display:none}.lg-ojo[aria-pressed=true] .ver{display:none}.lg-ojo[aria-pressed=true] .ocu{display:block}
.lg-aviso{font-size:12px;color:var(--warn);min-height:16px;margin:-8px 0 6px;opacity:0;transition:opacity .2s}
.lg-aviso.v{opacity:1}
.lg-btn{position:relative;overflow:hidden;width:100%;padding:13px 14px;border:0;border-radius:14px;font-size:15px;font-weight:600;color:#fff;cursor:pointer;
 background:linear-gradient(100deg,#0b3be6,#2151ed 55%,#5283fc);box-shadow:0 10px 28px rgba(11,59,230,.42);transition:transform .2s,box-shadow .2s,filter .2s}
.lg-btn::before{content:"";position:absolute;top:0;bottom:0;left:-60%;width:40%;transform:skewX(-20deg);background:linear-gradient(90deg,transparent,rgba(255,255,255,.35),transparent);transition:left .6s ease}
.lg-btn:hover{transform:translateY(-1px);box-shadow:0 14px 34px rgba(11,59,230,.55)}
.lg-btn:hover::before{left:120%}
.lg-btn:active{transform:translateY(1px)}
.lg-btn:focus-visible,.lg-ojo:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.lg-btn .sp{display:none;width:17px;height:17px;border-radius:50%;border:2px solid rgba(255,255,255,.4);border-top-color:#fff;animation:lg-gira .7s linear infinite;vertical-align:-3px;margin-right:8px}
.lg-btn.carga{pointer-events:none;filter:saturate(.8)}
.lg-btn.carga .sp{display:inline-block}
@keyframes lg-gira{to{transform:rotate(360deg)}}
.lg-msg{min-height:20px;margin-top:14px;text-align:center;font-size:13px;color:var(--bad)}
.lg-pie{margin-top:8px;text-align:center;font-size:11px;color:var(--muted)}
[data-theme="light"] .lg-card{background:linear-gradient(150deg,rgba(255,255,255,.82),rgba(238,242,251,.60));border-color:#fff;box-shadow:0 24px 60px rgba(11,59,230,.16),0 1px 0 #fff inset;-webkit-backdrop-filter:blur(18px);backdrop-filter:blur(18px)}
[data-theme="light"] .lg-campo input{border-bottom-color:#b9c8f0}
[data-theme="light"] .lg-fondo{opacity:.9}
@media (max-width:480px){.lg-card{padding:28px 22px 22px;border-radius:22px}.lg-escena .e1{left:-30px;width:110px;height:110px}.lg-escena .e2{right:-34px;width:130px;height:130px}}
@media (prefers-reduced-motion:reduce){.orb i,.lg-logo::before,.lg-logo .lnk,.lg-card,.lg-card.lg-err{animation:none!important}.lg-logo .lnk{stroke-dashoffset:0}.lg-card,.lg-fondo .orb,.lg-escena .orb{transform:none!important}.lg-btn::before{display:none}}
@media (prefers-reduced-transparency:reduce){.lg-card{-webkit-backdrop-filter:none;backdrop-filter:none;background:linear-gradient(165deg,rgba(11,27,77,.95),rgba(6,15,51,.98))}}
"""

LOGIN_JS = """
(function(){
  var r=document.documentElement,card=document.getElementById('lgCard'),
      reduce=matchMedia('(prefers-reduced-motion:reduce)').matches,
      u=document.getElementById('u'),c=document.getElementById('c'),
      btn=document.getElementById('lgBtn'),ojo=document.getElementById('lgOjo'),
      av=document.getElementById('lgCaps');
  if(!reduce){
    addEventListener('pointermove',function(e){
      r.style.setProperty('--mx',(e.clientX/innerWidth*2-1).toFixed(3));
      r.style.setProperty('--my',(e.clientY/innerHeight*2-1).toFixed(3));
    },{passive:true});
    card.addEventListener('pointermove',function(e){
      var b=card.getBoundingClientRect();
      card.style.setProperty('--px',((e.clientX-b.left)/b.width*100).toFixed(1)+'%');
      card.style.setProperty('--py',((e.clientY-b.top)/b.height*100).toFixed(1)+'%');
    },{passive:true});
  }
  ojo.addEventListener('click',function(){
    var ver=c.type==='password';
    c.type=ver?'text':'password';
    ojo.setAttribute('aria-pressed',ver?'true':'false');
    ojo.setAttribute('aria-label',ver?'Ocultar contraseña':'Mostrar contraseña');
    c.focus();
  });
  function caps(e){
    if(!e.getModifierState)return;
    av.classList.toggle('v',e.getModifierState('CapsLock'));
  }
  c.addEventListener('keydown',caps);c.addEventListener('keyup',caps);
  c.addEventListener('blur',function(){av.classList.remove('v');});
  card.addEventListener('submit',function(){
    btn.classList.add('carga');btn.querySelector('.tx').textContent='Verificando…';
  });
  addEventListener('pageshow',function(){
    btn.classList.remove('carga');btn.querySelector('.tx').textContent='Ingresar';
  });
  if(u.value){c.focus();}
})();
"""


def form_login(error="", csrf="", usuario=""):
    cls = "lg-card lg-err" if error else "lg-card"
    return pagina("Ingresar", f"""
<div class="lg-fondo" aria-hidden="true">
  <div class="orb o-az f1"><i></i></div><div class="orb o-vi f2"><i></i></div>
  <div class="orb o-ci f3"><i></i></div><div class="orb o-vi f4"><i></i></div>
</div>
<main class="lg-pagina">
  <div class="lg-escena">
    <div class="orb o-az e1" aria-hidden="true"><i></i></div>
    <div class="orb o-vi e2" aria-hidden="true"><i></i></div>
    <div class="orb o-ci e3" aria-hidden="true"><i></i></div>
    <form class="{cls}" id="lgCard" method="post" action="/login" autocomplete="on">
      <div class="lg-logo" aria-hidden="true">
        <svg viewBox="0 0 40 40" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
          <path class="lnk" d="M20 12 9 29M20 12l11 17M9 29h22"/>
          <circle cx="20" cy="11" r="4" fill="currentColor" stroke="none"/>
          <circle cx="9" cy="29" r="4" fill="currentColor" stroke="none"/>
          <circle cx="31" cy="29" r="4" fill="currentColor" stroke="none"/>
        </svg>
      </div>
      <h1>Centro de operaciones de red</h1>
      <p class="lg-sub">Ingresa con tu cuenta del NOC</p>
      <input type="hidden" name="csrf" value="{csrf}">
      <div class="lg-campo">
        <svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 21c1-4 4-6 8-6s7 2 8 6"/></svg>
        <input id="u" name="usuario" type="text" placeholder=" " value="{html.escape(usuario)}" autocomplete="username" autocapitalize="none" spellcheck="false" autofocus required>
        <label for="u">Usuario</label><span class="barra"></span>
      </div>
      <div class="lg-campo">
        <svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10" width="16" height="11" rx="2.5"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>
        <input id="c" name="clave" type="password" placeholder=" " autocomplete="current-password" required>
        <label for="c">Contraseña</label>
        <button class="lg-ojo" id="lgOjo" type="button" aria-pressed="false" aria-label="Mostrar contraseña">
          <svg class="ver" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>
          <svg class="ocu" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3l18 18M10.6 5.2A10 10 0 0 1 12 5c6.4 0 10 7 10 7a17 17 0 0 1-3.2 4M6.5 6.6A17 17 0 0 0 2 12s3.6 7 10 7c1.6 0 3-.4 4.3-1M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg>
        </button>
        <span class="barra"></span>
      </div>
      <div class="lg-aviso" id="lgCaps" aria-live="polite">Bloq Mayús está activado</div>
      <button class="lg-btn" id="lgBtn" type="submit"><span class="sp"></span><span class="tx">Ingresar</span></button>
      <div class="lg-msg" role="alert">{html.escape(error)}</div>
      <div class="lg-pie">Acceso restringido. Cada ingreso queda registrado.</div>
    </form>
  </div>
</main>""", js=LOGIN_JS, css=LOGIN_CSS)


def form_setup(error="", csrf="", usuario="", nombre=""):
    return pagina("Configuración inicial", f"""
<form class="caja" method="post" action="/setup" autocomplete="off">
  <h1>CONFIGURACIÓN INICIAL</h1>
  <p class="muted">Aún no hay usuarios. Crea la cuenta del administrador; con ella podrás crear
  los demás usuarios y roles.</p>
  <input type="hidden" name="csrf" value="{csrf}">
  <label>USUARIO</label>
  <input name="usuario" type="text" value="{html.escape(usuario)}" required>
  <label>NOMBRE COMPLETO</label>
  <input name="nombre" type="text" value="{html.escape(nombre)}">
  <label>CONTRASEÑA (mínimo {CLAVE_MIN} caracteres)</label>
  <input name="clave" type="password" autocomplete="new-password" required>
  <label>REPETIR CONTRASEÑA</label>
  <input name="clave2" type="password" autocomplete="new-password" required>
  <button class="pri full" type="submit">Crear administrador</button>
  <div class="err" role="alert">{html.escape(error)}</div>
</form>""")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if usuario_actual():
            return redirect("/")
        return form_login(csrf=asegurar_csrf())
    usuario = (request.form.get("usuario") or "").strip()
    clave = request.form.get("clave") or ""
    espera = bloqueo_restante(usuario)
    if espera:
        auditar("login_bloqueado", usuario, usuario=usuario)
        return form_login(f"Demasiados intentos. Intenta de nuevo en {espera // 60 + 1} min.",
                          asegurar_csrf(), usuario), 429
    fila = consulta("SELECT * FROM usuarios WHERE usuario=?", (usuario,), uno=True)
    if fila and fila["activo"]:
        ok = check_password_hash(fila["clave"], clave)
    else:
        check_password_hash(HASH_FALSO, clave)   # iguala tiempos de respuesta
        ok = False
    if not ok:
        registrar_fallo(usuario)
        auditar("login_fallido", usuario, usuario=usuario)
        return form_login("Usuario o contraseña incorrectos.", asegurar_csrf(), usuario), 401
    _fallos.pop(usuario.lower(), None)
    session.clear()
    session.permanent = True
    session["uid"], session["sv"] = fila["id"], fila["sv"]
    asegurar_csrf()
    ejecutar("UPDATE usuarios SET ultimo_acceso=? WHERE id=?", (int(time.time()), fila["id"]))
    auditar("login", "", usuario=fila["usuario"])
    return redirect("/")


@app.route("/logout", methods=["POST"])
def logout():
    u = usuario_actual()
    if u:
        auditar("logout", "", usuario=u["usuario"])
    session.clear()
    return redirect("/login")


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if not sin_usuarios():
        return redirect("/login")
    if request.method == "GET":
        return form_setup(csrf=asegurar_csrf())
    usuario = (request.form.get("usuario") or "").strip()
    nombre = (request.form.get("nombre") or "").strip()[:60]
    clave, clave2 = request.form.get("clave") or "", request.form.get("clave2") or ""
    error = ""
    if not RE_USUARIO.match(usuario):
        error = "Usuario: 3 a 32 caracteres (letras, números, punto, guion)."
    elif clave != clave2:
        error = "Las contraseñas no coinciden."
    else:
        error = validar_clave(clave)
    if error:
        return form_setup(error, asegurar_csrf(), usuario, nombre), 400
    rol = consulta("SELECT id FROM roles WHERE nombre='Administrador'", uno=True)["id"]
    uid = ejecutar("INSERT INTO usuarios (usuario, nombre, clave, rol_id, creado) VALUES (?,?,?,?,?)",
                   (usuario, nombre or usuario, generate_password_hash(clave), rol, int(time.time())))
    auditar("setup", "Administrador inicial creado", usuario=usuario)
    session.clear()
    session.permanent = True
    session["uid"], session["sv"] = uid, 1
    asegurar_csrf()
    return redirect("/")


# ---------------- Mi cuenta ----------------
@app.route("/cuenta")
def cuenta():
    u = g.usuario
    return pagina("Mi cuenta", f"""
<div class="caja" style="max-width:460px">
  <h1>MI CUENTA</h1>
  <p>Usuario: <b>{html.escape(u['usuario'])}</b><br>Rol: <b>{html.escape(u['rol'])}</b></p>
  <h2>CAMBIAR CONTRASEÑA</h2>
  <label>CONTRASEÑA ACTUAL</label><input id="a" type="password" autocomplete="current-password">
  <label>NUEVA CONTRASEÑA (mínimo {CLAVE_MIN} caracteres)</label><input id="n" type="password" autocomplete="new-password">
  <label>REPETIR NUEVA CONTRASEÑA</label><input id="n2" type="password" autocomplete="new-password">
  <button class="pri full" id="guardar">Guardar</button>
  <div class="err" id="msg" role="alert"></div>
  <p><a href="/">&larr; Volver al NOC</a></p>
</div>""", f"""
const CSRF = {_json.dumps(asegurar_csrf())};
document.getElementById('guardar').addEventListener('click', async () => {{
  const m = document.getElementById('msg'); m.className = 'err'; m.textContent = '';
  const a = document.getElementById('a').value, n = document.getElementById('n').value, n2 = document.getElementById('n2').value;
  if (n !== n2) {{ m.textContent = 'Las contraseñas nuevas no coinciden.'; return; }}
  try {{
    const r = await fetch('/api/cuenta/password', {{method: 'POST',
      headers: {{'Content-Type': 'application/json', 'X-CSRF': CSRF}},
      body: JSON.stringify({{actual: a, nueva: n}})}});
    const j = await r.json().catch(() => ({{}}));
    if (!r.ok) {{ m.textContent = j.error || 'No se pudo cambiar la contraseña.'; return; }}
    m.className = 'okm'; m.textContent = 'Contraseña actualizada. Las demás sesiones se cerraron.';
    ['a', 'n', 'n2'].forEach(i => document.getElementById(i).value = '');
  }} catch (e) {{ m.textContent = 'Error: ' + e.message; }}
}});
""")


@app.route("/api/cuenta/password", methods=["POST"])
def api_cuenta_password():
    d = request.get_json(silent=True) or {}
    u = g.usuario
    fila = consulta("SELECT clave FROM usuarios WHERE id=?", (u["id"],), uno=True)
    if not check_password_hash(fila["clave"], d.get("actual") or ""):
        auditar("clave_cambio_fallido", "contraseña actual incorrecta")
        return jsonify({"error": "La contraseña actual es incorrecta."}), 400
    error = validar_clave(d.get("nueva") or "")
    if error:
        return jsonify({"error": error}), 400
    nuevo_sv = u["sv"] + 1
    ejecutar("UPDATE usuarios SET clave=?, sv=? WHERE id=?",
             (generate_password_hash(d["nueva"]), nuevo_sv, u["id"]))
    session["sv"] = nuevo_sv
    auditar("clave_cambiada", "")
    return jsonify({"ok": True})


# ---------------- API de administración ----------------
def _json_in():
    return request.get_json(silent=True) or {}


@app.route("/api/admin/usuarios", methods=["GET"])
@requiere("usuarios")
def adm_usuarios():
    us = consulta("""SELECT u.id, u.usuario, u.nombre, u.rol_id, r.nombre AS rol, u.activo, u.ultimo_acceso
                     FROM usuarios u JOIN roles r ON r.id=u.rol_id ORDER BY u.usuario""")
    roles = consulta("SELECT id, nombre FROM roles ORDER BY nombre")
    return jsonify({"usuarios": [dict(x) for x in us], "roles": [dict(x) for x in roles],
                    "yo": g.usuario["id"]})


@app.route("/api/admin/usuarios", methods=["POST"])
@requiere("usuarios")
def adm_usuario_crear():
    d = _json_in()
    usuario = (d.get("usuario") or "").strip()
    nombre = (d.get("nombre") or "").strip()[:60]
    clave = d.get("clave") or ""
    if not RE_USUARIO.match(usuario):
        return jsonify({"error": "Usuario: 3 a 32 caracteres (letras, números, punto, guion)."}), 400
    error = validar_clave(clave)
    if error:
        return jsonify({"error": error}), 400
    if not consulta("SELECT 1 FROM roles WHERE id=?", (d.get("rol_id"),), uno=True):
        return jsonify({"error": "Elige un rol válido."}), 400
    if consulta("SELECT 1 FROM usuarios WHERE usuario=?", (usuario,), uno=True):
        return jsonify({"error": "Ya existe un usuario con ese nombre."}), 400
    uid = ejecutar("INSERT INTO usuarios (usuario, nombre, clave, rol_id, activo, creado) VALUES (?,?,?,?,?,?)",
                   (usuario, nombre or usuario, generate_password_hash(clave), d["rol_id"],
                    1 if d.get("activo", True) else 0, int(time.time())))
    auditar("usuario_creado", f"{usuario} (rol {d['rol_id']})")
    return jsonify({"ok": True, "id": uid})


@app.route("/api/admin/usuarios/<int:uid>", methods=["PUT"])
@requiere("usuarios")
def adm_usuario_editar(uid):
    d = _json_in()
    fila = consulta("""SELECT u.*, r.permisos FROM usuarios u JOIN roles r ON r.id=u.rol_id
                       WHERE u.id=?""", (uid,), uno=True)
    if not fila:
        return jsonify({"error": "Usuario no encontrado."}), 404
    era_admin = "usuarios" in fila["permisos"].split(",") and fila["activo"]
    nombre = (d.get("nombre", fila["nombre"]) or "").strip()[:60]
    activo = 1 if d.get("activo", bool(fila["activo"])) else 0
    rol_id = d.get("rol_id", fila["rol_id"])
    rol = consulta("SELECT * FROM roles WHERE id=?", (rol_id,), uno=True)
    if not rol:
        return jsonify({"error": "Elige un rol válido."}), 400
    seguira_admin = "usuarios" in rol["permisos"].split(",") and activo
    if uid == g.usuario["id"] and not activo:
        return jsonify({"error": "No puedes desactivar tu propia cuenta."}), 400
    if era_admin and not seguira_admin and otros_admins(excluir_uid=uid) == 0:
        return jsonify({"error": "Debe quedar al menos un administrador activo."}), 400
    sv = fila["sv"]
    clave_hash = fila["clave"]
    if d.get("clave"):
        error = validar_clave(d["clave"])
        if error:
            return jsonify({"error": error}), 400
        clave_hash = generate_password_hash(d["clave"])
        sv += 1
    if activo != fila["activo"] or rol_id != fila["rol_id"]:
        sv += 1   # cierra sus sesiones abiertas
    ejecutar("UPDATE usuarios SET nombre=?, activo=?, rol_id=?, clave=?, sv=? WHERE id=?",
             (nombre or fila["usuario"], activo, rol_id, clave_hash, sv, uid))
    if uid == g.usuario["id"]:
        session["sv"] = sv
    auditar("usuario_editado", f"{fila['usuario']}: rol={rol['nombre']} activo={activo}"
            + (" clave restablecida" if d.get("clave") else ""))
    return jsonify({"ok": True})


@app.route("/api/admin/usuarios/<int:uid>", methods=["DELETE"])
@requiere("usuarios")
def adm_usuario_borrar(uid):
    fila = consulta("""SELECT u.usuario, u.activo, r.permisos FROM usuarios u
                       JOIN roles r ON r.id=u.rol_id WHERE u.id=?""", (uid,), uno=True)
    if not fila:
        return jsonify({"error": "Usuario no encontrado."}), 404
    if uid == g.usuario["id"]:
        return jsonify({"error": "No puedes eliminar tu propia cuenta."}), 400
    if "usuarios" in fila["permisos"].split(",") and fila["activo"] and otros_admins(excluir_uid=uid) == 0:
        return jsonify({"error": "Debe quedar al menos un administrador activo."}), 400
    ejecutar("DELETE FROM usuarios WHERE id=?", (uid,))
    auditar("usuario_eliminado", fila["usuario"])
    return jsonify({"ok": True})


@app.route("/api/admin/roles", methods=["GET"])
@requiere("usuarios")
def adm_roles():
    rs = consulta("""SELECT r.id, r.nombre, r.permisos, r.sistema,
                     (SELECT COUNT(*) FROM usuarios u WHERE u.rol_id=r.id) AS usuarios
                     FROM roles r ORDER BY r.sistema DESC, r.nombre""")
    return jsonify({"roles": [dict(x, permisos=[p for p in x["permisos"].split(",") if p]) for x in rs],
                    "permisos": PERMISOS})


def _permisos_validos(lista):
    return [p for p in PERMISOS if p in (lista or [])]


@app.route("/api/admin/roles", methods=["POST"])
@requiere("usuarios")
def adm_rol_crear():
    d = _json_in()
    nombre = (d.get("nombre") or "").strip()
    if not (2 <= len(nombre) <= 40):
        return jsonify({"error": "El nombre del rol debe tener entre 2 y 40 caracteres."}), 400
    if consulta("SELECT 1 FROM roles WHERE nombre=?", (nombre,), uno=True):
        return jsonify({"error": "Ya existe un rol con ese nombre."}), 400
    perms = _permisos_validos(d.get("permisos"))
    rid = ejecutar("INSERT INTO roles (nombre, permisos, sistema) VALUES (?,?,0)", (nombre, ",".join(perms)))
    auditar("rol_creado", f"{nombre}: {','.join(perms)}")
    return jsonify({"ok": True, "id": rid})


@app.route("/api/admin/roles/<int:rid>", methods=["PUT"])
@requiere("usuarios")
def adm_rol_editar(rid):
    d = _json_in()
    rol = consulta("SELECT * FROM roles WHERE id=?", (rid,), uno=True)
    if not rol:
        return jsonify({"error": "Rol no encontrado."}), 404
    if rol["sistema"]:
        return jsonify({"error": "El rol Administrador no se puede modificar."}), 400
    nombre = (d.get("nombre") or "").strip()
    if not (2 <= len(nombre) <= 40):
        return jsonify({"error": "El nombre del rol debe tener entre 2 y 40 caracteres."}), 400
    if consulta("SELECT 1 FROM roles WHERE nombre=? AND id!=?", (nombre, rid), uno=True):
        return jsonify({"error": "Ya existe un rol con ese nombre."}), 400
    perms = _permisos_validos(d.get("permisos"))
    if "usuarios" in rol["permisos"].split(",") and "usuarios" not in perms \
            and otros_admins(excluir_rol=rid) == 0:
        return jsonify({"error": "Debe quedar al menos un administrador activo."}), 400
    ejecutar("UPDATE roles SET nombre=?, permisos=? WHERE id=?", (nombre, ",".join(perms), rid))
    auditar("rol_editado", f"{nombre}: {','.join(perms)}")
    return jsonify({"ok": True})


@app.route("/api/admin/roles/<int:rid>", methods=["DELETE"])
@requiere("usuarios")
def adm_rol_borrar(rid):
    rol = consulta("SELECT * FROM roles WHERE id=?", (rid,), uno=True)
    if not rol:
        return jsonify({"error": "Rol no encontrado."}), 404
    if rol["sistema"]:
        return jsonify({"error": "El rol Administrador no se puede eliminar."}), 400
    if consulta("SELECT 1 FROM usuarios WHERE rol_id=?", (rid,), uno=True):
        return jsonify({"error": "Hay usuarios con este rol. Cámbiales el rol primero."}), 400
    ejecutar("DELETE FROM roles WHERE id=?", (rid,))
    auditar("rol_eliminado", rol["nombre"])
    return jsonify({"ok": True})


@app.route("/api/admin/auditoria")
@requiere("usuarios")
def adm_auditoria():
    filas = consulta("SELECT ts, usuario, accion, detalle, ip FROM auditoria ORDER BY id DESC LIMIT 150")
    return jsonify({"registros": [dict(x) for x in filas]})


@app.route("/api/admin/tokens", methods=["GET"])
@requiere("usuarios")
def adm_tokens():
    filas = consulta("""SELECT t.id, t.nombre, t.prefijo, t.creado, t.ultimo_uso,
                        u.usuario, u.activo FROM tokens t JOIN usuarios u ON u.id=t.usuario_id
                        ORDER BY t.id DESC""")
    return jsonify({"tokens": [dict(x) for x in filas]})


@app.route("/api/admin/tokens", methods=["POST"])
@requiere("usuarios")
def adm_token_crear():
    d = _json_in()
    nombre = (d.get("nombre") or "").strip()
    if not (2 <= len(nombre) <= 40):
        return jsonify({"error": "El nombre debe tener entre 2 y 40 caracteres."}), 400
    u = consulta("SELECT id, usuario FROM usuarios WHERE id=? AND activo=1", (d.get("usuario_id"),), uno=True)
    if not u:
        return jsonify({"error": "Elige un usuario activo."}), 400
    token = "noc_" + secrets.token_urlsafe(32)
    ejecutar("INSERT INTO tokens (nombre, hash, prefijo, usuario_id, creado) VALUES (?,?,?,?,?)",
             (nombre, hash_token(token), token[:8], u["id"], int(time.time())))
    auditar("token_creado", f"{nombre} (usuario {u['usuario']})")
    return jsonify({"ok": True, "token": token})   # solo se muestra esta vez


@app.route("/api/admin/tokens/<int:tid>", methods=["DELETE"])
@requiere("usuarios")
def adm_token_borrar(tid):
    fila = consulta("SELECT nombre FROM tokens WHERE id=?", (tid,), uno=True)
    if not fila:
        return jsonify({"error": "Token no encontrado."}), 404
    ejecutar("DELETE FROM tokens WHERE id=?", (tid,))
    auditar("token_revocado", fila["nombre"])
    return jsonify({"ok": True})


ADMIN_HTML = """
<div class="ancho">
  <div class="top">
    <h1 style="margin:0">ADMINISTRACIÓN</h1>
    <a class="btn" href="/">&larr; Volver al NOC</a>
  </div>
  <div class="tabs">
    <button class="on" data-tab="usuarios">Usuarios</button>
    <button data-tab="roles">Roles</button>
    <button data-tab="tokens">Tokens API</button>
    <button data-tab="auditoria">Auditoría</button>
  </div>

  <div class="card" id="tab-usuarios">
    <div class="top"><h2 style="margin:0">USUARIOS</h2><button class="pri" id="nuevo-usuario">+ Nuevo usuario</button></div>
    <div style="overflow-x:auto"><table><thead><tr><th>USUARIO</th><th>NOMBRE</th><th>ROL</th><th>ESTADO</th><th>ÚLTIMO ACCESO</th><th></th></tr></thead>
    <tbody id="lista-usuarios"></tbody></table></div>
  </div>

  <div class="card" id="tab-roles" hidden>
    <div class="top"><h2 style="margin:0">ROLES Y PERMISOS</h2><button class="pri" id="nuevo-rol">+ Nuevo rol</button></div>
    <div style="overflow-x:auto"><table><thead><tr><th>ROL</th><th>PERMISOS</th><th>USUARIOS</th><th></th></tr></thead>
    <tbody id="lista-roles"></tbody></table></div>
    <p class="muted" id="leyenda-permisos"></p>
  </div>

  <div class="card" id="tab-tokens" hidden>
    <div class="top"><h2 style="margin:0">TOKENS DE API (SOLO LECTURA)</h2><button class="pri" id="nuevo-token">+ Nuevo token</button></div>
    <p class="muted">Permiten que una app externa lea <b>/api/data</b> con la cabecera
    <b>Authorization: Bearer ...</b>. Cada token tiene los permisos del rol de su usuario y no sirve para nada más.
    Recomendado: crear un usuario dedicado con rol "Solo lectura".</p>
    <div style="overflow-x:auto"><table><thead><tr><th>NOMBRE</th><th>TOKEN</th><th>USUARIO</th><th>CREADO</th><th>ÚLTIMO USO</th><th></th></tr></thead>
    <tbody id="lista-tokens"></tbody></table></div>
  </div>

  <div class="card" id="tab-auditoria" hidden>
    <h2>ÚLTIMOS 150 REGISTROS</h2>
    <div style="overflow-x:auto"><table><thead><tr><th>FECHA</th><th>USUARIO</th><th>ACCIÓN</th><th>DETALLE</th><th>IP</th></tr></thead>
    <tbody id="lista-auditoria"></tbody></table></div>
  </div>
</div>

<dialog id="dlg-usuario"><form method="dialog" id="f-usuario">
  <h2 id="dlg-u-titulo">USUARIO</h2>
  <label>USUARIO</label><input type="text" id="u-usuario" autocomplete="off">
  <label>NOMBRE COMPLETO</label><input type="text" id="u-nombre" autocomplete="off">
  <label>ROL</label><select id="u-rol"></select>
  <label id="u-clave-lbl">CONTRASEÑA</label><input type="password" id="u-clave" autocomplete="new-password">
  <label class="chk"><input type="checkbox" id="u-activo" checked> Cuenta activa</label>
  <div class="err" id="u-err" role="alert"></div>
  <div class="fila"><button type="button" id="u-cancelar">Cancelar</button><button type="button" class="pri" id="u-guardar">Guardar</button></div>
</form></dialog>

<dialog id="dlg-token"><form method="dialog">
  <h2>NUEVO TOKEN DE API</h2>
  <label>NOMBRE (para qué app es)</label><input type="text" id="t-nombre" autocomplete="off" placeholder="Ej: App AI Studio">
  <label>USUARIO</label><select id="t-usuario"></select>
  <div class="err" id="t-err" role="alert"></div>
  <div class="fila"><button type="button" id="t-cancelar">Cancelar</button><button type="button" class="pri" id="t-crear">Crear token</button></div>
</form></dialog>

<dialog id="dlg-token-ok"><form method="dialog">
  <h2>TOKEN CREADO</h2>
  <p class="off">Cópialo ahora. Por seguridad no se vuelve a mostrar.</p>
  <input type="text" id="t-valor" readonly>
  <div class="fila"><button type="button" id="t-copiar">Copiar</button><button type="button" class="pri" id="t-cerrar">Listo</button></div>
  <div class="okm" id="t-copiado"></div>
</form></dialog>

<dialog id="dlg-rol"><form method="dialog" id="f-rol">
  <h2 id="dlg-r-titulo">ROL</h2>
  <label>NOMBRE DEL ROL</label><input type="text" id="r-nombre" autocomplete="off">
  <label>PERMISOS</label><div id="r-permisos"></div>
  <div class="err" id="r-err" role="alert"></div>
  <div class="fila"><button type="button" id="r-cancelar">Cancelar</button><button type="button" class="pri" id="r-guardar">Guardar</button></div>
</form></dialog>
"""

ADMIN_JS = """
const CSRF = __CSRF__;
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fecha = ts => ts ? new Date(ts * 1000).toLocaleString() : '—';
const $ = id => document.getElementById(id);
let USUARIOS = [], ROLES = [], ROLES_SEL = [], PERMISOS = {}, YO = 0, editU = null, editR = null;

async function api(metodo, url, cuerpo) {
  const r = await fetch(url, {method: metodo,
    headers: {'Content-Type': 'application/json', 'X-CSRF': CSRF},
    body: cuerpo ? JSON.stringify(cuerpo) : undefined});
  if (r.status === 401) { location.href = '/login'; throw new Error('Sesión expirada'); }
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || ('Error ' + r.status));
  return j;
}

document.querySelectorAll('[data-tab]').forEach(b => b.addEventListener('click', () => {
  document.querySelectorAll('[data-tab]').forEach(x => x.classList.toggle('on', x === b));
  ['usuarios', 'roles', 'tokens', 'auditoria'].forEach(t => { $('tab-' + t).hidden = (t !== b.dataset.tab); });
  if (b.dataset.tab === 'auditoria') cargarAuditoria();
  if (b.dataset.tab === 'tokens') cargarTokens();
}));

// ---------- Usuarios ----------
async function cargarUsuarios() {
  const j = await api('GET', '/api/admin/usuarios');
  USUARIOS = j.usuarios; ROLES_SEL = j.roles; YO = j.yo;
  $('lista-usuarios').innerHTML = USUARIOS.map(u =>
    '<tr><td><b>' + esc(u.usuario) + '</b>' + (u.id === YO ? ' <span class="muted">(tú)</span>' : '') + '</td>' +
    '<td>' + esc(u.nombre) + '</td><td><span class="tag">' + esc(u.rol) + '</span></td>' +
    '<td>' + (u.activo ? 'Activo' : '<span class="off">Desactivado</span>') + '</td>' +
    '<td class="muted">' + fecha(u.ultimo_acceso) + '</td>' +
    '<td style="white-space:nowrap"><button data-ed="' + u.id + '">Editar</button> ' +
    (u.id === YO ? '' : '<button class="mal" data-del="' + u.id + '">Eliminar</button>') + '</td></tr>').join('');
}
function abrirUsuario(u) {
  editU = u;
  $('dlg-u-titulo').textContent = u ? 'EDITAR USUARIO' : 'NUEVO USUARIO';
  $('u-usuario').value = u ? u.usuario : ''; $('u-usuario').disabled = !!u;
  $('u-nombre').value = u ? u.nombre : '';
  $('u-rol').innerHTML = ROLES_SEL.map(r => '<option value="' + r.id + '"' + (u && u.rol_id === r.id ? ' selected' : '') + '>' + esc(r.nombre) + '</option>').join('');
  $('u-clave').value = '';
  $('u-clave-lbl').textContent = u ? 'NUEVA CONTRASEÑA (dejar vacío para no cambiarla)' : 'CONTRASEÑA (mínimo 10 caracteres)';
  $('u-activo').checked = u ? !!u.activo : true; $('u-activo').disabled = !!(u && u.id === YO);
  $('u-err').textContent = '';
  $('dlg-usuario').showModal();
}
$('nuevo-usuario').addEventListener('click', () => abrirUsuario(null));
$('u-cancelar').addEventListener('click', () => $('dlg-usuario').close());
$('u-guardar').addEventListener('click', async () => {
  const cuerpo = {nombre: $('u-nombre').value, rol_id: Number($('u-rol').value), activo: $('u-activo').checked};
  if ($('u-clave').value) cuerpo.clave = $('u-clave').value;
  try {
    if (editU) await api('PUT', '/api/admin/usuarios/' + editU.id, cuerpo);
    else { cuerpo.usuario = $('u-usuario').value; await api('POST', '/api/admin/usuarios', cuerpo); }
    $('dlg-usuario').close(); await cargarUsuarios(); await cargarRoles();
  } catch (e) { $('u-err').textContent = e.message; }
});
$('lista-usuarios').addEventListener('click', async ev => {
  const b = ev.target.closest('button'); if (!b) return;
  if (b.dataset.ed) abrirUsuario(USUARIOS.find(u => u.id === Number(b.dataset.ed)));
  if (b.dataset.del) {
    const u = USUARIOS.find(x => x.id === Number(b.dataset.del));
    if (!confirm('¿Eliminar al usuario "' + u.usuario + '"? Esta acción no se puede deshacer.')) return;
    try { await api('DELETE', '/api/admin/usuarios/' + u.id); await cargarUsuarios(); await cargarRoles(); }
    catch (e) { alert(e.message); }
  }
});

// ---------- Roles ----------
async function cargarRoles() {
  const j = await api('GET', '/api/admin/roles');
  ROLES = j.roles; PERMISOS = j.permisos;
  $('lista-roles').innerHTML = ROLES.map(r =>
    '<tr><td><b>' + esc(r.nombre) + '</b>' + (r.sistema ? ' <span class="muted">(sistema)</span>' : '') + '</td>' +
    '<td>' + (r.permisos.map(p => '<span class="tag">' + esc(p) + '</span>').join('') || '<span class="muted">ninguno</span>') + '</td>' +
    '<td>' + r.usuarios + '</td><td style="white-space:nowrap">' +
    (r.sistema ? '<span class="muted">bloqueado</span>' :
      '<button data-ed="' + r.id + '">Editar</button> <button class="mal" data-del="' + r.id + '">Eliminar</button>') + '</td></tr>').join('');
  $('leyenda-permisos').innerHTML = Object.keys(PERMISOS).map(p => '<b>' + esc(p) + '</b>: ' + esc(PERMISOS[p])).join('<br>');
}
function abrirRol(r) {
  editR = r;
  $('dlg-r-titulo').textContent = r ? 'EDITAR ROL' : 'NUEVO ROL';
  $('r-nombre').value = r ? r.nombre : '';
  $('r-permisos').innerHTML = Object.keys(PERMISOS).map(p =>
    '<label class="chk"><input type="checkbox" value="' + esc(p) + '"' + (r && r.permisos.includes(p) ? ' checked' : (!r && p === 'ver' ? ' checked' : '')) + '> <span><b>' + esc(p) + '</b><br><span class="muted">' + esc(PERMISOS[p]) + '</span></span></label>').join('');
  $('r-err').textContent = '';
  $('dlg-rol').showModal();
}
$('nuevo-rol').addEventListener('click', () => abrirRol(null));
$('r-cancelar').addEventListener('click', () => $('dlg-rol').close());
$('r-guardar').addEventListener('click', async () => {
  const cuerpo = {nombre: $('r-nombre').value,
    permisos: Array.from($('r-permisos').querySelectorAll('input:checked')).map(i => i.value)};
  try {
    if (editR) await api('PUT', '/api/admin/roles/' + editR.id, cuerpo);
    else await api('POST', '/api/admin/roles', cuerpo);
    $('dlg-rol').close(); await cargarRoles(); await cargarUsuarios();
  } catch (e) { $('r-err').textContent = e.message; }
});
$('lista-roles').addEventListener('click', async ev => {
  const b = ev.target.closest('button'); if (!b) return;
  if (b.dataset.ed) abrirRol(ROLES.find(r => r.id === Number(b.dataset.ed)));
  if (b.dataset.del) {
    const r = ROLES.find(x => x.id === Number(b.dataset.del));
    if (!confirm('¿Eliminar el rol "' + r.nombre + '"?')) return;
    try { await api('DELETE', '/api/admin/roles/' + r.id); await cargarRoles(); await cargarUsuarios(); }
    catch (e) { alert(e.message); }
  }
});

// ---------- Auditoría ----------
async function cargarAuditoria() {
  const j = await api('GET', '/api/admin/auditoria');
  $('lista-auditoria').innerHTML = j.registros.map(r =>
    '<tr><td class="muted">' + fecha(r.ts) + '</td><td>' + esc(r.usuario) + '</td><td><span class="tag">' + esc(r.accion) +
    '</span></td><td>' + esc(r.detalle) + '</td><td class="muted">' + esc(r.ip) + '</td></tr>').join('');
}

// ---------- Tokens de API ----------
let TOKENS = [];
async function cargarTokens() {
  const j = await api('GET', '/api/admin/tokens');
  TOKENS = j.tokens;
  $('lista-tokens').innerHTML = TOKENS.map(t =>
    '<tr><td><b>' + esc(t.nombre) + '</b></td><td class="muted">' + esc(t.prefijo) + '…</td>' +
    '<td>' + esc(t.usuario) + (t.activo ? '' : ' <span class="off">(desactivado)</span>') + '</td>' +
    '<td class="muted">' + fecha(t.creado) + '</td><td class="muted">' + fecha(t.ultimo_uso) + '</td>' +
    '<td><button class="mal" data-rev="' + t.id + '">Revocar</button></td></tr>').join('') ||
    '<tr><td colspan="6" class="muted">Aún no hay tokens.</td></tr>';
}
$('nuevo-token').addEventListener('click', async () => {
  await cargarUsuarios();
  $('t-usuario').innerHTML = USUARIOS.filter(u => u.activo).map(u => '<option value="' + u.id + '">' + esc(u.usuario) + ' (' + esc(u.rol) + ')</option>').join('');
  $('t-nombre').value = ''; $('t-err').textContent = '';
  $('dlg-token').showModal();
});
$('t-cancelar').addEventListener('click', () => $('dlg-token').close());
$('t-crear').addEventListener('click', async () => {
  try {
    const j = await api('POST', '/api/admin/tokens', {nombre: $('t-nombre').value, usuario_id: Number($('t-usuario').value)});
    $('dlg-token').close();
    $('t-valor').value = j.token; $('t-copiado').textContent = '';
    $('dlg-token-ok').showModal(); $('t-valor').select();
    await cargarTokens();
  } catch (e) { $('t-err').textContent = e.message; }
});
$('t-copiar').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('t-valor').value); $('t-copiado').textContent = 'Copiado.'; }
  catch (e) { $('t-valor').select(); $('t-copiado').textContent = 'Selecciónalo y cópialo con Ctrl+C.'; }
});
$('t-cerrar').addEventListener('click', () => { $('t-valor').value = ''; $('dlg-token-ok').close(); });
$('lista-tokens').addEventListener('click', async ev => {
  const b = ev.target.closest('button'); if (!b || !b.dataset.rev) return;
  const t = TOKENS.find(x => x.id === Number(b.dataset.rev));
  if (!confirm('¿Revocar el token "' + t.nombre + '"? La app que lo use dejará de funcionar.')) return;
  try { await api('DELETE', '/api/admin/tokens/' + t.id); await cargarTokens(); } catch (e) { alert(e.message); }
});

cargarRoles().then(cargarUsuarios).catch(e => alert(e.message));
"""


@app.route("/admin")
@requiere("usuarios")
def admin():
    return pagina("Administración", ADMIN_HTML,
                  ADMIN_JS.replace("__CSRF__", _json.dumps(asegurar_csrf())))


iniciar_auth()
# ===================== FIN AUTENTICACIÓN =====================


def consultar(host, item):
    """Devuelve ([(nombre, tiempos_ms, valores)], error)."""
    cuerpo = {
        "from": f"now-{HORAS_HISTORIAL}h",
        "to": "now",
        "queries": [{
            "refId": "A",
            "datasource": {"type": "alexanderzobnin-zabbix-datasource",
                           "uid": ZABBIX_DS_UID},
            "queryType": "0",
            "group": {"filter": GRUPO},
            "host": {"filter": host},
            "application": {"filter": ""},
            "itemTag": {"filter": ""},
            "item": {"filter": item},
            "options": {"showDisabledItems": False, "skipEmptyValues": False},
            "intervalMs": 60000,
            "maxDataPoints": 120,
        }],
    }
    try:
        r = requests.post(f"{GRAFANA_URL}/api/ds/query",
                          headers=HEADERS, json=cuerpo, timeout=30)
        if r.status_code != 200:
            return [], f"HTTP {r.status_code}"
        frames = r.json()["results"]["A"].get("frames", [])
        salida = []
        for f in frames:
            nombre = f["schema"].get("name") or f["schema"]["fields"][1].get("name", "")
            salida.append((nombre, f["data"]["values"][0], f["data"]["values"][1]))
        return salida, ""
    except Exception as e:
        return [], f"Error: {e}"


def ultimo(valores):
    for v in reversed(valores):
        if v is not None:
            return v
    return None


def serie_simple(frames, mult=1):
    if not frames:
        return {"t": [], "v": []}
    _, t, v = frames[0]
    pares = [(a, round(b * mult, 2)) for a, b in zip(t, v) if b is not None]
    return {"t": [p[0] for p in pares], "v": [p[1] for p in pares]}


def nombre_puerto(nombre_item):
    return re.sub(r"^Interface ", "", nombre_item.rsplit(": ", 1)[0])


def etiqueta(puerto):
    base, alias = partes_nombre(puerto)
    # FortiGate: x1, sfp1, wan1, dmz... se muestran con su nombre (solo el número sería ambiguo)
    if re.match(r"^(x|sfp\+?|wan|lan|dmz|ha|mgmt|internal|fiber|fibra|[ab])\d*$", base, re.I):
        return base[:5]
    for t in (base, alias):
        m = re.search(r"(\d+)$", t)
        if m:
            return m.group(1)
    corto = base if len(base) <= 12 else (alias or base)
    return corto[:5]


def partes_nombre(puerto):
    """'port1(WAN)' -> ('port1', 'WAN'); 'port2' -> ('port2', '')."""
    m = re.match(r"^(.*)\(([^()]*)\)\s*$", puerto)
    if m:
        return m.group(1).strip(), m.group(2).strip()
    return puerto.strip(), ""


def clave_natural(texto):
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", texto)]


def tarjeta(m):
    frames, error = consultar(m["host"], m["item"])
    valor = ultimo(frames[0][2]) if frames else None
    if not frames and not error:
        error = "Sin datos (revisa host e item)"
    if frames and valor is None and not error:
        error = "Sin valores recientes"

    if m.get("tipo") == "estado":
        texto = "N/D" if valor is None else ("UP" if valor >= 1 else "DOWN")
        color = "na" if valor is None else ("ok" if valor >= 1 else "bad")
    else:
        if valor is not None:
            valor = round(valor * m.get("mult", 1), 2)
        texto = "N/D" if valor is None else f"{valor}{m.get('unidad', '')}"
        if valor is None:
            color = "na"
        elif m.get("crit") is not None and valor >= m["crit"]:
            color = "bad"
        elif m.get("warn") is not None and valor >= m["warn"]:
            color = "warn"
        else:
            color = "ok"
    return {"host": m["host"], "label": m["label"], "texto": texto,
            "color": color, "error": error}


def datos_dispositivo(d):
    host = d["host"]
    consultas = {}
    if d.get("con_puertos", True):
        consultas.update({"estado": "/Operational status/",
                          "rx": "/Bits received/", "tx": "/Bits sent/"})
    if d.get("lat"):
        consultas["lat"] = d["lat"]
    if d.get("cpu"):
        consultas["cpu"] = d["cpu"]
    claves = list(consultas)
    with ThreadPoolExecutor(max_workers=5) as pool:
        resultados = list(pool.map(lambda k: consultar(host, consultas[k]), claves))
    res = dict(zip(claves, resultados))
    for k in ("estado", "rx", "tx", "lat", "cpu"):
        res.setdefault(k, ([], ""))

    filtro = re.compile(d.get("filtro_puertos", r".*"))
    puertos = {}
    suma = {"rx": {}, "tx": {}}
    for campo in ("estado", "rx", "tx"):
        for nombre, t, v in res[campo][0]:
            p = nombre_puerto(nombre)
            if not filtro.search(p):
                continue
            puertos.setdefault(p, {})[campo] = ultimo(v)
            if campo in suma:
                for ts, val in zip(t, v):
                    if val is not None:
                        b = int(ts // 60000) * 60000
                        suma[campo][b] = suma[campo].get(b, 0) + val

    def mb(val):
        return None if val is None else round(val / 1e6, 2)

    lista = []
    for p in sorted(puertos, key=clave_natural):
        x = puertos[p]
        est = x.get("estado")
        estado = "na" if est is None else ("up" if est == 1 else ("down" if est == 2 else "otro"))
        base, alias = partes_nombre(p)
        lista.append({"nombre": p, "base": base, "alias": alias,
                      "label": etiqueta(p), "estado": estado,
                      "fibra": bool(FIBRA_RE.search(p)),
                      "rx": mb(x.get("rx")), "tx": mb(x.get("tx"))})

    buckets = sorted(set(suma["rx"]) | set(suma["tx"]))[-120:]
    traf = {"t": buckets,
            "rx": [round(suma["rx"].get(b, 0) / 1e6, 2) for b in buckets],
            "tx": [round(suma["tx"].get(b, 0) / 1e6, 2) for b in buckets]}

    return {
        "id": d["id"], "host": host, "titulo": d["titulo"],
        "subtitulo": d.get("subtitulo", ""),
        "badge": d.get("badge", ""),
        "u": d.get("u"),
        "panel": d.get("panel", "PANEL DE PUERTOS"),
        "con_puertos": d.get("con_puertos", True),
        "graficas": d.get("graficas", TODAS),
        "puertos": lista,
        "series": {"traf": traf,
                   "lat": serie_simple(res["lat"][0], 1000),
                   "cpu": serie_simple(res["cpu"][0])},
    }


# ---------------- Alertas y eventos ----------------
def evento(nivel, host, msg):
    _seq[0] += 1
    EVENTOS.appendleft({"id": f"n{_seq[0]}", "ts": int(time.time() * 1000),
                        "nivel": nivel, "host": host, "msg": msg})


def detectar_eventos(disp, tarjetas):
    """Compara con la lectura anterior y registra los cambios de estado."""
    actual = {}
    for d in disp:
        for p in d["puertos"]:
            actual[("p", d["host"], p["nombre"])] = (p["estado"], p["nombre"], "")
    for t in tarjetas:
        actual[("m", t["host"], t["label"])] = (t["color"], t["label"], t["texto"])

    for k, (nuevo, nombre, texto) in actual.items():
        tipo, host = k[0], k[1]
        viejo = _prev.get(k, nuevo if tipo == "p" else "ok")
        _prev[k] = nuevo
        if tipo == "p" and nuevo == "up":
            _vistos_up.add(k)
        if viejo == nuevo or nuevo == "na":
            continue
        if tipo == "p":
            if nuevo == "down":
                evento("crit", host, f"Puerto {nombre} caído")
            elif nuevo == "up" and viejo == "down":
                evento("ok", host, f"Puerto {nombre} recuperado")
        else:
            if nombre == "Ping" and nuevo == "bad":
                evento("crit", host, "Sin respuesta ICMP (ping DOWN)")
            elif nuevo == "bad":
                evento("crit", host, f"{nombre} crítico: {texto}")
            elif nuevo == "warn":
                evento("warn", host, f"{nombre} en advertencia: {texto}")
            elif nuevo == "ok" and viejo in ("bad", "warn"):
                evento("ok", host, f"{nombre} normalizado: {texto}")


def alertas_activas(disp, tarjetas):
    lista = []
    for t in tarjetas:
        if t["color"] in ("bad", "warn"):
            lista.append({"nivel": "crit" if t["color"] == "bad" else "warn",
                          "host": t["host"],
                          "msg": f"{t['label']}: {t['texto']}"})
    for d in disp:
        for p in d["puertos"]:
            if p["estado"] == "down" and ("p", d["host"], p["nombre"]) in _vistos_up:
                lista.append({"nivel": "crit", "host": d["host"],
                              "msg": f"Puerto {p['nombre']} caído"})
    lista.sort(key=lambda a: 0 if a["nivel"] == "crit" else 1)
    return lista


def zbx(metodo, params):
    r = requests.post(
        ZABBIX_API_URL,
        json={"jsonrpc": "2.0", "method": metodo, "params": params, "id": 1},
        headers={"Content-Type": "application/json-rpc",
                 "Authorization": f"Bearer {ZABBIX_API_TOKEN}"},
        timeout=10)
    j = r.json()
    if "error" in j:
        raise RuntimeError(j["error"].get("data") or j["error"].get("message", "error"))
    return j["result"]


def clasificar(nombre):
    n = nombre.lower()
    if "ssh" in n:
        return "SSH"
    if any(p in n for p in ("icmp", "unavailable", "not available", "no disponible",
                            "apagad", "restarted", "uptime")):
        return "DISPONIBILIDAD"
    if any(p in n for p in ("tráfico", "trafico", "traffic", "bandwidth", "bits")):
        return "TRÁFICO"
    if any(p in n for p in ("interface", "link down", "port", "puerto")):
        return "PUERTO"
    return "ZABBIX"


def eventos_zabbix():
    """Devuelve (eventos, alertas_activas, error) leyendo la API de Zabbix."""
    if not ZABBIX_API_TOKEN:
        return [], [], "Falta ZABBIX_API_TOKEN en .env"
    nivel = {"0": "ok", "1": "ok", "2": "warn", "3": "warn", "4": "crit", "5": "crit"}
    ahora = time.time()
    try:
        # Historial reciente (registro de eventos)
        desde = int(ahora) - HORAS_EVENTOS * 3600
        res = zbx("event.get", {
            "output": ["eventid", "name", "clock", "severity"],
            "selectHosts": ["host"],
            "source": 0, "object": 0, "value": 1,
            "time_from": desde,
            "sortfield": ["clock", "eventid"], "sortorder": "DESC",
            "limit": 150,
        })
        eventos = []
        for ev in res:
            host = ev["hosts"][0]["host"] if ev.get("hosts") else "Zabbix"
            eventos.append({"id": "z" + ev["eventid"], "ts": int(ev["clock"]) * 1000,
                            "nivel": nivel.get(ev["severity"], "warn"),
                            "host": host, "msg": ev["name"],
                            "tipo": clasificar(ev["name"])})

        # Alertas activas = problemas abiertos, sin importar su antigüedad
        probs = zbx("problem.get", {
            "output": ["eventid", "name", "clock", "severity"],
            "source": 0, "object": 0, "suppressed": False,
            "sortfield": ["eventid"], "sortorder": "DESC", "limit": 300,
        })
        hosts_ev = {}
        if probs:
            evs = zbx("event.get", {"output": ["eventid"],
                                    "eventids": [p["eventid"] for p in probs],
                                    "selectHosts": ["host"]})
            hosts_ev = {e["eventid"]: (e["hosts"][0]["host"] if e.get("hosts") else "Zabbix")
                        for e in evs}
    except Exception as e:
        return [], [], f"{e}"

    alertas = []
    for p in probs:
        if int(p["severity"]) < SEVERIDAD_MINIMA_ALERTA:
            continue
        tipo = clasificar(p["name"])
        clock = int(p["clock"])
        # Los avisos de log (SSH) no se cierran solos: solo cuentan un rato
        if tipo == "SSH" and (ahora - clock) > MINUTOS_ALERTA_LOG * 60:
            continue
        alertas.append({"nivel": nivel.get(p["severity"], "warn"),
                        "host": hosts_ev.get(p["eventid"], "Zabbix"),
                        "msg": p["name"], "tipo": tipo})
    return eventos, alertas, ""


def obtener_datos():
    with _lock:
        ahora = time.time()
        if _cache["datos"] is None or ahora - _cache["t"] > SEGUNDOS_CACHE:
            with ThreadPoolExecutor(max_workers=8) as pool:
                f_disp = [pool.submit(datos_dispositivo, d) for d in DISPOSITIVOS]
                tarjetas = list(pool.map(tarjeta, METRICAS))
                disp = [f.result() for f in f_disp]
            detectar_eventos(disp, tarjetas)
            z_ev, z_al, z_err = eventos_zabbix()
            al_todas = alertas_activas(disp, tarjetas) + z_al
            anotar_alertas(al_todas)
            _cache["datos"] = {"dispositivos": disp, "tarjetas": tarjetas,
                               "alertas": al_todas,
                               "zabbix_eventos": z_ev, "zabbix_error": z_err}
            _cache["t"] = ahora
        respuesta = dict(_cache["datos"])
        propios = [dict(e, tipo=e.get("tipo", "NOC")) for e in EVENTOS]
        todos = propios + respuesta.pop("zabbix_eventos")
        todos.sort(key=lambda e: e["ts"], reverse=True)
        respuesta["alertas"].sort(key=lambda a: (a.get("prio", 3), 0 if a["nivel"] == "crit" else 1))
        respuesta["eventos"] = todos[:MAX_EVENTOS]
    return respuesta


@app.route("/api/data")
@requiere("ver")
def api_data():
    return jsonify(obtener_datos())


# ---------------- Guías de actuación (afectación, solución y plan de acción) ----------------
# Orientativas: cubren los tipos de alerta más comunes. Valida siempre en el equipo antes de actuar.
PRIORIDADES = {
    1: {"codigo": "P1", "nombre": "Urgente", "tiempo": "Atender en menos de 15 min"},
    2: {"codigo": "P2", "nombre": "Alta", "tiempo": "Atender en menos de 1 h"},
    3: {"codigo": "P3", "nombre": "Normal", "tiempo": "Atender en menos de 4 h"},
}

IMPACTO_ROL = {
    "FW": "Es el borde de la red: si falla o se degrada, puede afectar la salida a internet, las VPN y la comunicación entre segmentos.",
    "SW": "Es parte del núcleo de conmutación: una falla puede dejar sin red a todos los equipos conectados a sus puertos.",
    "SRV": "Aloja servicios de la empresa: una falla afecta a los usuarios y sistemas que dependen de este servidor.",
    "AP": "Da cobertura inalámbrica: una falla deja sin Wi-Fi a la zona que atiende.",
}

GUIAS = [
    {"id": "ssh", "patron": r"ssh", "nombre": "Intentos fallidos de acceso SSH",
     "afectacion": ["No hay caída de servicio, pero existe riesgo de acceso no autorizado al equipo.",
                    "Un volumen alto de intentos suele indicar fuerza bruta; si adivinan la clave, obtienen control total."],
     "causas": ["Escaneo o fuerza bruta desde internet o desde la red interna.",
                "Script, backup o herramienta con credenciales vencidas.",
                "Un usuario que se equivoca de contraseña repetidamente."],
     "solucion": ["Identifica la IP de origen y el usuario en el registro (Linux: journalctl -u ssh o /var/log/auth.log; Windows: evento 4625).",
                  "Determina si la IP es conocida (administrador, script, otro servicio).",
                  "Si es desconocida, bloquéala en el FortiGate (política de denegación o grupo de direcciones bloqueadas).",
                  "Confirma que no hubo un ingreso exitoso desde esa IP (Linux: last y grep Accepted en auth.log).",
                  "Si hubo un ingreso exitoso inesperado, aísla el equipo, cambia credenciales y escala a seguridad."],
     "plan": {"ahora": ["Identificar IP y usuario atacado.", "Bloquear la IP si no es reconocida."],
              "hoy": ["Revisar ingresos exitosos del período.", "Rotar la contraseña de las cuentas atacadas."],
              "prevenir": ["Usar llaves SSH y desactivar contraseña.", "Limitar SSH a la red de gestión.", "Instalar fail2ban o equivalente."]},
     "escalar": "A seguridad de la información si hay ingreso exitoso no reconocido o el ataque dura más de 30 min.",
     "resuelto": "Los intentos cesan. Este aviso se cierra solo tras 30 min sin nuevos eventos."},

    {"id": "latencia", "patron": r"latencia|latency|response time|tiempo de respuesta", "nombre": "Latencia alta",
     "afectacion": ["Lentitud en aplicaciones, cortes en voz y video, tiempos de espera agotados.",
                    "El equipo sigue respondiendo, pero con calidad degradada."],
     "causas": ["Congestión del enlace.", "CPU alta en el equipo o en un equipo intermedio.",
                "Bucle de red o tormenta de broadcast.", "Problema del proveedor de internet."],
     "solucion": ["Revisa si hay alertas de tráfico o CPU en el mismo equipo o en su enlace.",
                  "Compara con otros equipos: si todos suben, es el enlace o el proveedor; si es uno solo, es local.",
                  "Ejecuta ping continuo y tracert hacia el equipo para ver en qué salto aumenta el tiempo.",
                  "En la gráfica de tráfico, un uso cercano al 100 % indica saturación.",
                  "En el switch, busca puertos con tráfico broadcast anormalmente alto (posible bucle)."],
     "plan": {"ahora": ["Ubicar si el problema es local o del enlace.", "Identificar quién consume el ancho de banda."],
              "hoy": ["Abrir caso con el proveedor si el problema es externo.", "Limitar o reprogramar el tráfico pesado."],
              "prevenir": ["Configurar QoS para tráfico crítico.", "Activar STP/protección contra bucles.", "Revisar si el enlace necesita más capacidad."]},
     "escalar": "Al proveedor de internet si la latencia es alta en la salida WAN y el tráfico interno es normal.",
     "resuelto": "La latencia vuelve a su rango normal y se mantiene estable durante 15 min."},

    {"id": "perdida", "patron": r"p[eé]rdida|packet loss|\bloss\b", "nombre": "Pérdida de paquetes",
     "afectacion": ["Conexiones intermitentes, cortes de llamadas, descargas lentas y reintentos constantes.",
                    "Suele anticipar una caída total del enlace o del equipo."],
     "causas": ["Cable o conector defectuoso.", "Interferencia o señal débil (en Wi-Fi).",
                "Puerto con errores o dúplex incorrecto.", "Congestión o falla del proveedor."],
     "solucion": ["Revisa los contadores de errores del puerto o interfaz por donde llega el equipo.",
                  "Si es un AP, verifica la señal, el canal y la interferencia en la zona.",
                  "Cambia el cable y prueba otro puerto del switch.",
                  "Confirma que velocidad y dúplex coinciden en ambos extremos.",
                  "Si persiste con cable bueno, sospecha del equipo o del proveedor."],
     "plan": {"ahora": ["Revisar errores del puerto.", "Probar con otro cable o puerto."],
              "hoy": ["Reemplazar el cable o el módulo defectuoso.", "Documentar cuándo ocurre."],
              "prevenir": ["Alertar por errores de interfaz antes de perder paquetes.", "Mantener cableado certificado y ordenado."]},
     "escalar": "Al proveedor si la pérdida aparece solo en el enlace WAN.",
     "resuelto": "La pérdida baja a 0 % y se mantiene durante 15 min."},

    {"id": "agente", "patron": r"agent|agente", "nombre": "Agente de monitoreo sin respuesta",
     "afectacion": ["El equipo puede seguir funcionando, pero dejas de ver CPU, memoria, disco y servicios: queda sin monitoreo.",
                    "Si el servidor también cayó, los servicios que aloja están afectados."],
     "causas": ["Servicio del agente detenido.", "Servidor apagado o reiniciado.",
                "Firewall bloqueando el puerto 10050.", "Cambio de IP o de nombre del equipo."],
     "solucion": ["Haz ping al servidor para saber si está encendido.",
                  "Si responde, revisa el servicio del agente (Linux: systemctl status zabbix-agent; Windows: servicio Zabbix Agent).",
                  "Reinícialo y revisa su registro por errores de conexión.",
                  "Desde el servidor Zabbix, comprueba que alcanza el puerto 10050 del equipo.",
                  "Verifica que el campo Server del agente tenga la IP correcta del Zabbix."],
     "plan": {"ahora": ["Confirmar si el servidor está en línea.", "Reiniciar el servicio del agente."],
              "hoy": ["Corregir la configuración si cambió la IP.", "Revisar por qué se detuvo el servicio."],
              "prevenir": ["Configurar el servicio para reiniciarse solo.", "Monitorear también por ping."]},
     "escalar": "Al responsable del servidor si el equipo está apagado o no se puede acceder.",
     "resuelto": "El agente vuelve a reportar y los gráficos de CPU y memoria se actualizan."},

    {"id": "ping", "patron": r"^ping\b|unavailable by icmp|icmp.*(down|unavailable)|sin respuesta|not reachable|inaccesible",
     "nombre": "Equipo sin respuesta (ping)",
     "afectacion": ["El equipo no responde en la red: los servicios que presta están caídos o inalcanzables.",
                    "Puede ser el equipo apagado, o solo el enlace hacia él."],
     "causas": ["Equipo apagado o reiniciándose.", "Falla eléctrica o de la fuente de poder.",
                "Cable, puerto o enlace caído en el switch o firewall.", "Regla del firewall que bloquea el ICMP."],
     "solucion": ["Comprueba si hay otras alertas de equipos del mismo tramo: si caen varios, el fallo está en el enlace o switch común.",
                  "Haz ping desde otro punto de la red para descartar un problema de tu estación.",
                  "Revisa en el switch si el puerto del equipo está activo (link up) y qué MAC aprende.",
                  "Verifica la alimentación eléctrica y las luces del equipo (acceso físico o remoto).",
                  "Si el equipo está encendido y el enlace activo, revisa las reglas del firewall y la configuración IP."],
     "plan": {"ahora": ["Confirmar si el fallo es del equipo o del enlace.", "Avisar a los usuarios que dependen del servicio."],
              "hoy": ["Restablecer el equipo y verificar los servicios.", "Registrar la causa raíz."],
              "prevenir": ["Conectar a UPS los equipos críticos.", "Tener redundancia de enlace para los servicios clave."]},
     "por_equipo": {"FW": "Si es un FortiGate en alta disponibilidad, revisa el estado del clúster (get system ha status).",
                    "SW": "Un switch caído deja sin red a todo lo conectado a él: prioriza el acceso físico.",
                    "SRV": "Revisa la consola (iLO, iDRAC o hipervisor) si no hay respuesta por red.",
                    "AP": "Verifica que el puerto del switch entregue PoE y que el AP muestre luz de estado."},
     "escalar": "A soporte del fabricante o proveedor si el equipo no vuelve tras reiniciarlo, o a infraestructura si el fallo es eléctrico.",
     "resuelto": "El ping responde de forma estable y la alerta se cierra en el NOC."},

    {"id": "cpu", "patron": r"\bcpu\b|processor|procesador", "nombre": "CPU alta",
     "afectacion": ["Respuesta lenta del equipo, cortes de sesión y pérdida de paquetes si es un equipo de red.",
                    "Si se mantiene al 100 %, el equipo puede dejar de responder."],
     "causas": ["Proceso o servicio descontrolado.", "Pico de tráfico o ataque.",
                "Inspección de seguridad pesada (firewall).", "Tarea programada o actualización en curso."],
     "solucion": ["Revisa en la gráfica si es un pico breve o una tendencia sostenida.",
                  "Identifica qué proceso consume más (servidor: top o Administrador de tareas).",
                  "Si es un equipo de red, revisa el tráfico y las sesiones activas por si hay un ataque o un equipo infectado.",
                  "Detén o reprograma el proceso no esencial; no reinicies el equipo sin avisar.",
                  "Si el consumo se mantiene sin causa clara, planifica un reinicio controlado."],
     "plan": {"ahora": ["Identificar el proceso o tráfico responsable.", "Evitar nuevas cargas en el equipo."],
              "hoy": ["Corregir o reprogramar la causa.", "Dejar registro del pico."],
              "prevenir": ["Ajustar umbrales (aviso 70 %, crítica 90 %).", "Evaluar más recursos si el uso es siempre alto."]},
     "por_equipo": {"FW": "En FortiGate: get system performance status y diagnose sys top para ver procesos.",
                    "SW": "En el switch HP: show cpu y show processes para ver qué consume.",
                    "SRV": "Linux: top o htop. Windows: Administrador de tareas > Detalles, ordenado por CPU."},
     "escalar": "A soporte del fabricante si un equipo de red mantiene CPU alta sin tráfico anormal.",
     "resuelto": "La CPU baja del 70 % y se mantiene estable durante 15 min."},

    {"id": "memoria", "patron": r"memor|\bram\b|swap", "nombre": "Memoria alta",
     "afectacion": ["Lentitud y, en el extremo, cierre forzado de procesos o caída del equipo (modo conserva en FortiGate).",
                    "En servidores, los servicios pueden dejar de responder."],
     "causas": ["Fuga de memoria en un servicio.", "Más carga de la que el equipo soporta.",
                "Demasiadas sesiones o conexiones abiertas.", "Caché o procesos acumulados."],
     "solucion": ["Revisa la tendencia: una subida constante sugiere fuga de memoria.",
                  "Identifica el proceso que más memoria usa.",
                  "Reinicia el servicio afectado en una ventana adecuada.",
                  "En firewall, revisa el número de sesiones y limpia las innecesarias.",
                  "Si no baja, programa un reinicio del equipo y valora ampliar la memoria."],
     "plan": {"ahora": ["Identificar el proceso que consume.", "Reiniciar solo el servicio afectado."],
              "hoy": ["Programar una ventana para reiniciar si no se recupera.", "Registrar la tendencia."],
              "prevenir": ["Alertar a partir del 80 %.", "Planificar ampliación si la tendencia crece cada semana."]},
     "por_equipo": {"FW": "En FortiGate: diagnose hardware sysinfo memory y get system performance status.",
                    "SRV": "Linux: free -h y ps aux --sort=-%mem. Windows: Administrador de tareas > Rendimiento."},
     "escalar": "Al fabricante si es un equipo de red y la memoria crece sin motivo tras reiniciar.",
     "resuelto": "El uso de memoria baja del 80 % y no vuelve a crecer en 30 min."},

    {"id": "disco", "patron": r"disk|disco|espacio|free space|filesystem|\bfs\b|volume|inode", "nombre": "Disco con poco espacio",
     "afectacion": ["Con el disco lleno, los servicios dejan de escribir: bases de datos, registros y aplicaciones fallan.",
                    "Puede causar corrupción de datos o impedir el arranque."],
     "causas": ["Registros (logs) sin rotar.", "Backups o archivos temporales acumulados.",
                "Crecimiento normal de la base de datos.", "Volcados de memoria o instalaciones antiguas."],
     "solucion": ["Identifica la unidad afectada y cuánto espacio queda.",
                  "Busca lo que más ocupa (Linux: du -sh /* | sort -h y df -h; Windows: propiedades del disco).",
                  "Libera espacio con seguridad: rota o comprime logs, vacía temporales, mueve backups viejos.",
                  "No borres archivos de bases de datos ni del sistema sin confirmar qué son.",
                  "Si el crecimiento es normal, amplía el volumen."],
     "plan": {"ahora": ["Liberar espacio suficiente para estabilizar el servicio."],
              "hoy": ["Configurar la rotación de logs.", "Mover los backups a otro almacenamiento."],
              "prevenir": ["Alertar a partir del 80 % de uso.", "Planificar la ampliación según el crecimiento mensual."]},
     "escalar": "Al responsable de la aplicación o base de datos antes de borrar datos.",
     "resuelto": "El espacio libre supera el 20 % y se mantiene."},

    {"id": "reinicio", "patron": r"restart|reinici|uptime|rebooted", "nombre": "Equipo reiniciado",
     "afectacion": ["Corte breve de los servicios del equipo mientras arrancaba.",
                    "Si no fue planificado, puede indicar una falla eléctrica o del propio equipo."],
     "causas": ["Reinicio planificado (actualización, mantenimiento).", "Corte de energía.",
                "Falla de hardware o error del sistema.", "Reinicio manual de otra persona."],
     "solucion": ["Confirma si había un mantenimiento programado.",
                  "Si no lo había, pregunta quién pudo reiniciarlo y revisa el registro de eventos.",
                  "Revisa si hubo cortes de energía en el mismo horario.",
                  "Verifica que todos los servicios y puertos hayan vuelto a su estado normal.",
                  "Si ocurre varias veces, revisa temperatura, fuente de poder y registros de fallos."],
     "plan": {"ahora": ["Comprobar que los servicios volvieron.", "Confirmar si fue planificado."],
              "hoy": ["Documentar la causa.", "Revisar el registro del sistema."],
              "prevenir": ["Conectar a UPS.", "Registrar los mantenimientos en un calendario compartido."]},
     "escalar": "A soporte del fabricante si los reinicios no planificados se repiten.",
     "resuelto": "El equipo permanece estable y sus servicios responden con normalidad."},

    {"id": "errores", "patron": r"error|discard|descart|crc|collision", "nombre": "Errores en una interfaz",
     "afectacion": ["Pérdida de paquetes y lentitud en los equipos conectados a ese enlace.",
                    "Suele ser un aviso temprano de cable o puerto dañado."],
     "causas": ["Cable dañado o conector sucio.", "Velocidad o dúplex distintos en ambos extremos.",
                "Módulo o puerto defectuoso.", "Interferencia o cable demasiado largo."],
     "solucion": ["Anota qué puerto y qué equipo está conectado.",
                  "Revisa en el switch los contadores de errores y comprueba si siguen subiendo.",
                  "Sustituye el cable por uno bueno.",
                  "Fuerza la misma velocidad y dúplex en los dos extremos o deja ambos en automático.",
                  "Prueba otro puerto: si el error se va, el puerto original está dañado."],
     "plan": {"ahora": ["Cambiar el cable.", "Confirmar si los errores siguen aumentando."],
              "hoy": ["Cambiar de puerto si persiste.", "Etiquetar y documentar el cable."],
              "prevenir": ["Cableado certificado.", "Revisión periódica de contadores de error."]},
     "escalar": "A cableado estructurado si varios puertos de la misma zona muestran errores.",
     "resuelto": "Los contadores de errores dejan de crecer."},

    {"id": "trafico", "patron": r"tr[aá]fico|traffic|bandwidth|ancho de banda|bits (received|sent)|utilization|saturaci", "nombre": "Tráfico elevado",
     "afectacion": ["Lentitud general, mayor latencia y cortes en servicios sensibles como voz y videollamadas.",
                    "Si el enlace se satura, los servicios críticos compiten con el resto del tráfico."],
     "causas": ["Descargas o actualizaciones masivas.", "Backup o replicación en horario laboral.",
                "Equipo infectado o comprometido.", "Streaming o uso no laboral."],
     "solucion": ["Revisa la gráfica: determina si es un pico puntual o una tendencia constante.",
                  "En el firewall, identifica las IP y aplicaciones que más tráfico generan.",
                  "Si es una descarga o un backup, reprográmalo fuera del horario laboral.",
                  "Si el origen es un equipo desconocido, aíslalo y revísalo.",
                  "Si el tráfico es legítimo y constante, evalúa ampliar el enlace."],
     "plan": {"ahora": ["Identificar el origen del tráfico.", "Limitar o pausar lo que no sea crítico."],
              "hoy": ["Aplicar control de ancho de banda al tráfico no laboral.", "Reprogramar los backups."],
              "prevenir": ["QoS para servicios críticos.", "Revisión mensual de tendencia para planificar capacidad."]},
     "escalar": "A seguridad si el tráfico viene de un equipo comprometido; al proveedor si se necesita más capacidad.",
     "resuelto": "El uso del enlace baja del 70 % y se mantiene estable."},

    {"id": "puerto", "patron": r"link down|puerto|interface|\bport\s?\d|operational status|\bcaído|caido", "nombre": "Puerto o enlace caído",
     "afectacion": ["Los equipos o redes conectados a ese puerto pierden conectividad.",
                    "Si es un enlace WAN o troncal, se afecta a todos los usuarios que pasan por él."],
     "causas": ["Cable desconectado o dañado.", "Equipo remoto apagado.",
                "Puerto deshabilitado o con falla.", "Corte del proveedor (si es WAN)."],
     "solucion": ["Identifica qué equipo o enlace conecta ese puerto (usa el nombre en el bastidor del NOC).",
                  "Revisa las luces del puerto y que el cable esté firme en ambos extremos.",
                  "Verifica que el equipo del otro lado esté encendido.",
                  "Comprueba que el puerto no esté deshabilitado por configuración.",
                  "Si es WAN, confirma con el proveedor si hay corte en la zona y abre un caso."],
     "plan": {"ahora": ["Identificar qué servicio depende del puerto.", "Revisar cable y alimentación del otro extremo."],
              "hoy": ["Reemplazar cable o puerto.", "Abrir caso con el proveedor si es WAN."],
              "prevenir": ["Tener enlace de respaldo para las rutas críticas.", "Etiquetar cada puerto con su equipo."]},
     "por_equipo": {"FW": "En FortiGate: diagnose hardware deviceinfo nic <puerto> para ver el estado físico.",
                    "SW": "En el switch HP: show interfaces brief y show logging -r para ver el motivo de la caída."},
     "escalar": "Al proveedor si es un enlace WAN; a infraestructura si es un troncal entre switches.",
     "resuelto": "El puerto vuelve a estado UP y el equipo del otro lado responde."},

    {"id": "generico", "patron": r".*", "nombre": "Alerta general",
     "afectacion": ["Depende del servicio asociado: revisa qué función cumple el equipo y quién lo utiliza."],
     "causas": ["Cambio reciente de configuración.", "Falla del equipo o del servicio.", "Problema en un equipo del que depende."],
     "solucion": ["Lee el mensaje completo de la alerta y el equipo afectado.",
                  "Revisa si hay otras alertas en el mismo equipo o en equipos vecinos.",
                  "Consulta los eventos recientes del equipo para ver qué cambió antes.",
                  "Comprueba en el equipo si el servicio indicado está funcionando.",
                  "Si no identificas la causa, documenta lo observado y escala."],
     "plan": {"ahora": ["Evaluar el alcance.", "Revisar eventos recientes."],
              "hoy": ["Resolver o escalar con evidencia.", "Registrar la causa."],
              "prevenir": ["Crear una guía para este tipo de alerta si se repite."]},
     "escalar": "Al responsable del equipo o servicio si no hay avance en 30 min.",
     "resuelto": "La alerta se cierra en el NOC y el servicio responde con normalidad."},
]
GUIAS_POR_ID = {g_["id"]: g_ for g_ in GUIAS}
BADGE_HOST = {d["host"]: d.get("badge", "") for d in DISPOSITIVOS}
BADGE_HOST.setdefault("Zabbix server", "SRV")
_PB_DISPONIBILIDAD = ("ping", "agente", "puerto", "cpu", "memoria", "disco")


def guia_id(msg):
    m = (msg or "").lower()
    for g_ in GUIAS:
        if re.search(g_["patron"], m):
            return g_["id"]
    return "generico"


def prioridad_alerta(a):
    if a["nivel"] != "crit":
        return 3
    badge = BADGE_HOST.get(a["host"], "")
    if re.search(r"wan|uplink|vpn", a["msg"].lower()) or \
            (badge in ("FW", "SW", "SRV") and a.get("pb") in _PB_DISPONIBILIDAD):
        return 1
    return 2


def anotar_alertas(lista):
    for a in lista:
        a["pb"] = guia_id(a["msg"])
        a["prio"] = prioridad_alerta(a)


@app.route("/api/playbooks")
@requiere("ver")
def api_playbooks():
    guias = {g_["id"]: {k: v for k, v in g_.items() if k != "patron"} for g_ in GUIAS}
    equipos = {d["host"]: {"badge": d.get("badge", ""), "nombre": d["titulo"]} for d in DISPOSITIVOS}
    return jsonify({"guias": guias, "prioridades": PRIORIDADES,
                    "roles": IMPACTO_ROL, "equipos": equipos})



# ---------------- Telegram ----------------
_enviados = set()
_ultimo_test = [0]


def enviar_telegram(texto):
    """Devuelve (ok, detalle). El token nunca aparece en los mensajes de error."""
    if not (TELEGRAM_TOKEN and TELEGRAM_CHAT_ID):
        return False, "Falta TELEGRAM_TOKEN o TELEGRAM_CHAT_ID en .env"
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": texto, "parse_mode": "HTML",
                  "disable_web_page_preview": True},
            timeout=10)
        j = r.json()
        return bool(j.get("ok")), j.get("description", "")
    except Exception as e:
        return False, str(e).replace(TELEGRAM_TOKEN, "***")


# ---- Notificaciones con formato ----
_ip_hosts = {"t": 0, "ips": {}}
ZABBIX_IP = urlparse(ZABBIX_API_URL).hostname or ""
RE_PUERTO_ZBX = re.compile(r"Interface\s+(.+?)\(([^)]*)\)\s*:\s*(.*)$")
RE_PUERTO_NOC = re.compile(r"^Puerto\s+(.+?)(?:\(([^)]*)\))?\s+(caído|recuperado)$")
RE_SSH_IP = re.compile(r"\bfrom\s+((?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]{3,})")
RE_SSH_USER = re.compile(r"(?:for(?:\s+invalid\s+user)?|Invalid\s+user)\s+(\S+)\s+from")
TIPOS = [(re.compile(p, re.I), t) for p, t in [
    (r"Unavailable by ICMP ping|Sin respuesta ICMP", "Equipo sin respuesta (ICMP)"),
    (r"High ICMP ping loss", "Pérdida de paquetes ICMP"),
    (r"High ICMP ping response time", "Latencia ICMP alta"),
    (r"Link down|caído$", "Puerto desconectado (Link down)"),
    (r"recuperado$", "Puerto recuperado"),
    (r"lower speed", "Puerto con velocidad reducida"),
    (r"High error rate", "Errores en el puerto"),
    (r"bandwidth", "Uso alto de ancho de banda"),
    (r"fuerza bruta", "Posible fuerza bruta SSH"),
    (r"SSH: acceso fallido", "Acceso SSH fallido"),
    (r"SSH: acceso exitoso", "Acceso SSH exitoso"),
    (r"agent is not available", "Agente Zabbix no disponible"),
    (r"No SNMP data|SNMP agent.*(unavailable|not available)", "Sin datos SNMP"),
    (r"Disk space", "Poco espacio en disco"),
    (r"Disk read/write", "Disco lento"),
    (r"Load average|CPU", "Carga de CPU alta"),
    (r"memor", "Memoria alta"),
    (r"restarted", "Equipo reiniciado"),
]]


def tipo_legible(e):
    for rx, texto in TIPOS:
        if rx.search(e["msg"]):
            return texto
    return e["msg"]


def ips_de_hosts(nombres):
    """IP principal de cada host según Zabbix (se refresca cada 10 min)."""
    ahora = time.time()
    desconocido = any(n not in _ip_hosts["ips"] for n in nombres)
    if ahora - _ip_hosts["t"] > 600 or (desconocido and ahora - _ip_hosts["t"] > 60):
        try:
            res = zbx("host.get", {"output": ["host"], "selectInterfaces": ["ip", "main"]})
            ips = {}
            for h in res:
                principal = [i["ip"] for i in h.get("interfaces", []) if i.get("main") == "1" and i.get("ip")]
                ip = principal[0] if principal else ""
                ips[h["host"]] = ZABBIX_IP if ip.startswith("127.") else ip
            _ip_hosts["ips"] = ips
        except Exception as ex:
            print("Telegram (IPs):", str(ex)[:120], flush=True)
        _ip_hosts["t"] = ahora
    return _ip_hosts["ips"]


def detalles_ssh(eventos):
    """{id_evento: {"origen": ip, "usuario": u}} leyendo la línea de log que disparó cada evento."""
    ids = [e["id"][1:] for e in eventos if e["id"].startswith("z") and e.get("tipo") == "SSH"]
    if not ids:
        return {}
    evs = zbx("event.get", {"eventids": ids, "output": ["eventid", "objectid", "clock"]})
    trigs = zbx("trigger.get", {"triggerids": list({e["objectid"] for e in evs}),
                                "output": ["triggerid"], "selectItems": ["itemid", "value_type"]})
    item_de = {}
    for t in trigs:
        for it in t.get("items", []):
            if str(it.get("value_type")) == "2":          # 2 = item de tipo log
                item_de[t["triggerid"]] = it["itemid"]
    if not item_de or not evs:
        return {}
    relojes = [int(e["clock"]) for e in evs]
    hist = zbx("history.get", {"history": 2, "itemids": sorted(set(item_de.values())),
                               "time_from": min(relojes) - 3, "time_till": max(relojes) + 3,
                               "output": "extend", "sortfield": ["clock", "ns"],
                               "sortorder": "ASC", "limit": 500})
    lineas = {}
    for h in hist:
        lineas.setdefault((h["itemid"], int(h["clock"])), []).append(h["value"])
    grupos = {}
    for e in sorted(evs, key=lambda x: int(x["eventid"])):
        item = item_de.get(e["objectid"])
        if item:
            grupos.setdefault((item, int(e["clock"])), []).append(e["eventid"])
    salida = {}
    for clave, lista in grupos.items():
        vals = lineas.get(clave, [])
        for i, eid in enumerate(lista):      # varios eventos en el mismo segundo: se emparejan en orden
            if i < len(vals):
                ip, us = RE_SSH_IP.search(vals[i]), RE_SSH_USER.search(vals[i])
                salida["z" + eid] = {"origen": ip.group(1) if ip else "",
                                     "usuario": us.group(1) if us else ""}
    return salida


def hora_es(ts_ms):
    dt = datetime.fromtimestamp(ts_ms / 1000, timezone(timedelta(hours=ZONA_HORARIA_UTC)))
    h12 = dt.hour % 12 or 12
    return f"{dt.strftime('%d/%m/%Y')} {h12}:{dt.strftime('%M:%S')} {'a. m.' if dt.hour < 12 else 'p. m.'}"


def formatear_notificacion(e, ctx):
    """Arma el texto de una notificación. ctx: ips, ssh, latencias."""
    esc = html.escape
    icono = {"crit": "🚨", "warn": "⚠️", "ok": "✅"}.get(e["nivel"], "🔔")
    host = e["host"]
    ip = ctx.get("ips", {}).get(host, "")
    tipo = tipo_legible(e)
    puerto = None
    m = RE_PUERTO_ZBX.search(e["msg"])
    if m:
        puerto = (m.group(1).strip(), m.group(2).strip(), m.group(3).strip())
    else:
        m = RE_PUERTO_NOC.match(e["msg"])
        if m:
            puerto = (m.group(1).strip(), (m.group(2) or "").strip(), m.group(3))
    destino = f"{host} ({ip})" if ip else host
    ssh = ctx.get("ssh", {}).get(e["id"])

    lineas = [f"{icono} <b>NOTIFICACIÓN NOC // {esc(NOC_NOMBRE)}</b>",
              f"Tipo: {esc(tipo)}",
              f"Equipo Destino: {esc(destino)}"]
    if puerto:
        nombre, alias, _ = puerto
        lineas.append(f"Puerto afectado: {esc(nombre)}" + (f" ({esc(alias)})" if alias else ""))
    if ssh is not None or tipo.startswith(("Acceso SSH", "Posible fuerza")):
        partes = []
        if ssh and ssh.get("origen"):
            partes.append(f"Origen IP: {esc(ssh['origen'])} -> Destino: {esc(destino)}")
        else:
            partes.append(f"Destino: {esc(destino)}")
        if ssh and ssh.get("usuario"):
            partes.append(f"Usuario: {esc(ssh['usuario'])}")
        lineas.append("Detalle: " + " | ".join(partes))
    elif tipo.startswith(("Equipo sin respuesta", "Pérdida de paquetes", "Latencia ICMP")):
        lat = "sin respuesta" if tipo.startswith("Equipo sin respuesta") else ctx.get("latencias", {}).get(host, "N/D")
        origen = f"Origen IP: {esc(ZABBIX_IP)} (Zabbix) -> " if ZABBIX_IP else ""
        lineas.append(f"Detalle: {origen}Destino: {esc(destino)} | Latencia: {esc(lat)}")
    elif puerto:
        nombre, alias, estado = puerto
        lineas.append(f"Detalle: Puerto {esc(nombre)}" + (f" ({esc(alias)})" if alias else "") + f": {esc(estado)}")
    else:
        lineas.append(f"Detalle: {esc(e['msg'])}")
    lineas.append(f"Hora: {hora_es(e['ts'])}")
    return "\n".join(lineas)


def contexto_notificaciones(lote, datos):
    ctx = {"ips": {}, "ssh": {}, "latencias": {}}
    try:
        ctx["ips"] = ips_de_hosts({e["host"] for e in lote})
    except Exception as ex:
        print("Telegram (contexto):", str(ex)[:120], flush=True)
    try:
        ctx["ssh"] = detalles_ssh(lote)
    except Exception as ex:
        print("Telegram (SSH):", str(ex)[:120], flush=True)
    for t in datos.get("tarjetas", []):
        if t["label"] == "Latencia":
            ctx["latencias"][t["host"]] = t["texto"]
    return ctx


def ciclo_telegram():
    """Revisa cada cierto tiempo si hay eventos nuevos y los manda a Telegram, uno por mensaje."""
    global _enviados
    primera = True
    while True:
        try:
            datos = obtener_datos()
            if datos["zabbix_error"]:
                time.sleep(TELEGRAM_CADA_SEG)
                continue  # no tocar el estado si Zabbix falló, para no repetir mensajes
            actuales = datos["eventos"]
            if primera:
                _enviados = {e["id"] for e in actuales}   # no reenviar el historial
                ok, det = enviar_telegram(f"✅ <b>NOC // {html.escape(NOC_NOMBRE)} conectado</b>\n"
                                          "A partir de ahora recibirás aquí las notificaciones.")
                if not ok:
                    print("Telegram:", det, flush=True)
                primera = False
            else:
                nuevos = sorted((e for e in actuales if e["id"] not in _enviados), key=lambda e: (e["ts"], len(e["id"]), e["id"]))
                elegibles = []
                for e in nuevos:
                    origen_ok = e["id"].startswith("z") or TELEGRAM_INCLUIR_EVENTOS_NOC
                    if e["nivel"] in TELEGRAM_NIVELES and origen_ok:
                        elegibles.append(e)
                    else:
                        _enviados.add(e["id"])          # descartado a propósito
                lote, resto = elegibles[:TELEGRAM_MAX_POR_CICLO], elegibles[TELEGRAM_MAX_POR_CICLO:]
                ctx = contexto_notificaciones(lote, datos) if lote else {}
                completo = True
                for e in lote:
                    ok, det = enviar_telegram(formatear_notificacion(e, ctx))
                    if not ok:
                        print("Telegram:", det, flush=True)
                        completo = False
                        break                           # reintenta en el próximo ciclo
                    _enviados.add(e["id"])
                    time.sleep(1.1)                     # límite de Telegram: ~1 mensaje por segundo
                if completo and resto:
                    ok, _ = enviar_telegram(f"⚠️ <b>NOC // {html.escape(NOC_NOMBRE)}</b>\n"
                                            f"… y {len(resto)} notificación(es) más. Revisa el NOC.")
                    if ok:
                        _enviados.update(e["id"] for e in resto)
            ids_actuales = {e["id"] for e in actuales}
            _enviados = {i for i in _enviados if i in ids_actuales}   # olvida lo que ya salió del historial
        except Exception as e:
            print("Error en ciclo Telegram:", str(e).replace(TELEGRAM_TOKEN or "-", "***"), flush=True)
        time.sleep(TELEGRAM_CADA_SEG)


@app.route("/api/telegram")
@requiere("diagnostico")
def api_telegram():
    """Envía un mensaje de prueba (máximo uno cada 30 s)."""
    if time.time() - _ultimo_test[0] < 30:
        return jsonify({"ok": False, "detalle": "Espera 30 segundos entre pruebas"})
    _ultimo_test[0] = time.time()
    ejemplo = {"id": "zprueba", "ts": int(time.time() * 1000), "nivel": "crit", "host": "FG-DATA",
               "tipo": "PUERTO", "msg": "Interface port7(WAN2): Link down"}
    try:
        ips = ips_de_hosts({"FG-DATA"})
    except Exception:
        ips = {}
    ok, det = enviar_telegram("🧪 <i>Mensaje de prueba. Así se verán las notificaciones:</i>\n\n"
                              + formatear_notificacion(ejemplo, {"ips": ips}))
    return jsonify({"ok": ok, "detalle": det,
                    "token_configurado": bool(TELEGRAM_TOKEN),
                    "chat_id_configurado": bool(TELEGRAM_CHAT_ID)})


@app.route("/api/zabbix")
@requiere("diagnostico")
def api_zabbix():
    """Diagnóstico de la conexión con la API de Zabbix y de los permisos del token."""
    salida = {"token_configurado": bool(ZABBIX_API_TOKEN), "url": ZABBIX_API_URL}
    try:  # apiinfo.version se llama sin autenticación
        r = requests.post(ZABBIX_API_URL, timeout=10,
                          headers={"Content-Type": "application/json-rpc"},
                          json={"jsonrpc": "2.0", "method": "apiinfo.version",
                                "params": {}, "id": 1})
        salida["version_zabbix"] = r.json().get("result", r.json())
    except Exception as e:
        salida["version_zabbix"] = f"ERROR: {e}"
    pruebas = [
        ("hosts_visibles", "host.get", {"output": ["host"], "limit": 50}),
        ("eventos_24h", "event.get", {
            "output": ["name", "clock", "severity"], "selectHosts": ["host"],
            "source": 0, "object": 0, "value": 1,
            "time_from": int(time.time()) - 24 * 3600,
            "sortfield": ["clock"], "sortorder": "DESC", "limit": 5}),
        ("eventos_sin_filtro_de_tiempo", "event.get", {
            "output": ["name", "clock"], "source": 0, "object": 0,
            "sortfield": ["clock"], "sortorder": "DESC", "limit": 5}),
        ("problemas_abiertos", "problem.get", {"output": ["name"], "limit": 5}),
    ]
    for nombre, metodo, params in pruebas:
        try:
            res = zbx(metodo, params)
            muestra = [x.get("host") or x.get("name") for x in res]
            salida[nombre] = {"total": len(res), "muestra": muestra}
        except Exception as e:
            salida[nombre] = {"error": str(e)}
    return jsonify(salida)


@app.route("/api/items/<host>")
@requiere("diagnostico")
def api_items(host):
    """Diagnóstico: lista los nombres reales de items de un host en Zabbix."""
    frames, error = consultar(host, "/.*/")
    nombres = sorted({n for n, _, _ in frames})
    return jsonify({"host": host, "total": len(nombres), "error": error, "items": nombres})


@app.route("/api/puertos/<host>")
@requiere("diagnostico")
def api_puertos(host):
    """Diagnóstico: interfaces que Zabbix reporta para el host y si el NOC las muestra."""
    d = next((x for x in DISPOSITIVOS if x["host"].lower() == host.lower()), None)
    filtro = re.compile((d or {}).get("filtro_puertos", r".*"))
    frames, error = consultar(host, "/Operational status/")
    estados = {1: "up", 2: "down"}
    filas = []
    for nombre, _, v in frames:
        p = nombre_puerto(nombre)
        val = ultimo(v)
        filas.append({"interfaz": p, "estado": estados.get(val, "sin dato" if val is None else f"otro ({val})"),
                      "se_muestra": bool(filtro.search(p)), "fibra": bool(FIBRA_RE.search(p))})
    filas.sort(key=lambda f: clave_natural(f["interfaz"]))
    return jsonify({"host": host, "error": error, "total": len(filas),
                    "ocultas": [f["interfaz"] for f in filas if not f["se_muestra"]],
                    "interfaces": filas})


PAGINA = r"""
<!DOCTYPE html>
<html data-theme="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NOC Dashboard</title>
<style>
  :root {
    --bg:#12143a;
    /* Tema oscuro: vidrio sobre índigo con destellos violeta y azul */
    --bgimg:radial-gradient(900px 620px at 8% -8%, rgba(124,108,240,.55), transparent 62%),
            radial-gradient(900px 700px at 100% 105%, rgba(47,91,234,.50), transparent 60%),
            radial-gradient(560px 460px at 70% 20%, rgba(143,160,255,.26), transparent 70%),
            radial-gradient(520px 420px at 28% 76%, rgba(99,179,237,.22), transparent 70%);
    --side:rgba(255,255,255,.07);
    --card:linear-gradient(150deg, rgba(255,255,255,.13), rgba(255,255,255,.05));
    --panel:rgba(255,255,255,.06); --chip:rgba(255,255,255,.10);
    --border:rgba(255,255,255,.16); --border2:rgba(255,255,255,.28);
    --text:#f1f3ff; --muted:#a3abd6; --accent:#9fb8ff; --grid:rgba(255,255,255,.09);
    --tileText:#d6dcf7; --track:rgba(255,255,255,.14);
    --ok:#34d399; --warn:#fbbf24; --bad:#fb7185; --na:#8a93b8; --led:#22d3ee; --sfp:#8aa4ff;
    --shadow:0 18px 44px rgba(5,6,40,.45); --glow:0 1px 0 rgba(255,255,255,.18) inset;
    --vidrio:blur(26px) saturate(170%);
    --tip:rgba(18,20,58,.92); --rad:28px;
  }
  /* Tema claro (por defecto): lavanda y azul, vidrio blanco esmerilado */
  [data-theme="light"] {
    --bg:#cdd6f4;
    --bgimg:radial-gradient(820px 600px at 6% -6%, rgba(167,139,250,.55), transparent 62%),
            radial-gradient(900px 700px at 100% 104%, rgba(96,165,250,.55), transparent 60%),
            radial-gradient(600px 460px at 62% 12%, rgba(255,255,255,.55), transparent 70%),
            radial-gradient(520px 420px at 22% 78%, rgba(125,211,252,.40), transparent 70%),
            linear-gradient(160deg, #dfe5fb, #c6d0f3 55%, #b9c6ef);
    --side:rgba(255,255,255,.46);
    --card:linear-gradient(150deg, rgba(255,255,255,.68), rgba(255,255,255,.38));
    --panel:rgba(255,255,255,.50); --chip:rgba(255,255,255,.64);
    --border:rgba(255,255,255,.78); --border2:rgba(120,135,200,.38);
    --text:#141a3a; --muted:#59628c; --accent:#2f4fe0; --grid:rgba(80,95,160,.14);
    --tileText:#2a3260; --track:rgba(80,95,160,.16);
    --ok:#15803d; --warn:#b45309; --bad:#dc2626; --na:#6b7499; --led:#14b8a6; --sfp:#4f5fe8;
    --shadow:0 18px 40px rgba(70,80,160,.20), 0 2px 6px rgba(70,80,160,.08); --glow:0 1px 0 rgba(255,255,255,.9) inset;
    --tip:rgba(20,26,58,.94); --vidrio:blur(24px) saturate(150%);
  }
  * { box-sizing:border-box; }
  body { margin:0; background-color:var(--bg); background-image:var(--bgimg); background-attachment:fixed;
         min-height:100vh; color:var(--text);
         font-family:"Segoe UI", system-ui, -apple-system, Roboto, "Helvetica Neue", Arial, sans-serif;
         font-size:14px; font-variant-numeric:tabular-nums; }
  .layout { display:grid; grid-template-columns:300px minmax(0,1fr) 352px; gap:16px;
            padding:16px; align-items:start; }
  @media (max-width:1250px) { .layout { grid-template-columns:300px minmax(0,1fr); }
                              .der { position:static !important; grid-column:1 / -1; } }
  @media (max-width:820px) { .layout { grid-template-columns:1fr; }
                             main { order:1; } .side { order:2; } .der { order:3; } }

  .ok { color:var(--ok); } .warn { color:var(--warn); }
  .bad { color:var(--bad); } .na { color:var(--na); }
  .card { background:var(--card); border:1px solid var(--border); border-radius:16px; padding:18px;
          margin-bottom:16px; box-shadow:var(--shadow), var(--glow); -webkit-backdrop-filter:var(--vidrio); backdrop-filter:var(--vidrio);
          transition:border-color .25s, box-shadow .25s, transform .25s; }
  .card:hover { border-color:var(--border2); }
  .titulo { color:var(--text); font-size:13px; font-weight:600; letter-spacing:.3px; }
  .titulo.ac { color:var(--accent); text-transform:uppercase; font-size:11px; letter-spacing:1.2px; }
  button { background:var(--chip); color:var(--text); border:1px solid var(--border2);
           border-radius:8px; padding:6px 12px; cursor:pointer; font-family:inherit; font-size:12px;
           transition:background .2s, border-color .2s, transform .15s; }
  button:hover { border-color:var(--accent); }
  button:active { transform:scale(.97); }
  button:focus-visible, input:focus-visible { outline:2px solid var(--accent); outline-offset:1px; }
  input[type=search] { width:100%; background:var(--panel); color:var(--text); border:1px solid var(--border2);
           border-radius:10px; padding:9px 12px 9px 34px; font-family:inherit; font-size:13px;
           background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%237f93bd' stroke-width='2' stroke-linecap='round'%3E%3Ccircle cx='11' cy='11' r='7'/%3E%3Cpath d='M20 20l-3.5-3.5'/%3E%3C/svg%3E");
           background-repeat:no-repeat; background-position:11px center; }

  @keyframes aparecer { from { opacity:0; transform:translateY(8px); } to { opacity:1; transform:none; } }
  @keyframes pulso { 0%,100% { box-shadow:0 0 0 0 currentColor; } 50% { box-shadow:0 0 0 6px transparent; } }
  @keyframes alarma { 0%,100% { box-shadow:var(--shadow), 0 0 0 0 rgba(251,113,133,0); } 50% { box-shadow:var(--shadow), 0 0 26px 2px rgba(251,113,133,.38); } }
  @keyframes resalte { from { background:color-mix(in srgb, var(--accent) 28%, transparent); } to { background:transparent; } }
  .layout > *, main > * { animation:aparecer .55s ease both; }
  main > *:nth-child(2) { animation-delay:.05s; } main > *:nth-child(3) { animation-delay:.1s; }
  main > *:nth-child(4) { animation-delay:.15s; } main > *:nth-child(5) { animation-delay:.2s; }

  /* ---------- Barra lateral ---------- */
  .side { background:var(--side); border:1px solid var(--border); border-radius:14px; padding:16px;
          box-shadow:var(--shadow); -webkit-backdrop-filter:var(--vidrio); backdrop-filter:var(--vidrio); }
  .marca { display:flex; align-items:center; gap:10px; margin-bottom:14px; }
  .marca .logo { width:34px; height:34px; border-radius:10px; display:grid; place-items:center;
                 background:linear-gradient(135deg, #0b3be6, #5283fc); color:#fff; box-shadow:0 0 18px rgba(11,59,230,.40); }
  .marca b { display:block; font-size:14px; } .marca span { color:var(--muted); font-size:11px; }
  .side h2 { color:var(--muted); font-size:11px; font-weight:600; letter-spacing:1.2px; margin:0 0 8px; }
  /* ---- Bastidor físico ---- */
  .bast-t { display:flex; justify-content:space-between; align-items:center; margin:0 0 8px; }
  .bast-t b { color:var(--accent); font-size:10px; letter-spacing:1.2px; font-weight:700; }
  .bast-t span { color:var(--muted); font-size:10px; }
  .bastidor { background:linear-gradient(180deg, rgba(2,6,20,.40), rgba(6,12,32,.48));
              border:2px solid var(--border2); border-radius:10px; padding:6px 0;
              box-shadow:inset 0 0 24px rgba(0,0,0,.5); }
  [data-theme="light"] .bastidor { background:#e3eafc; box-shadow:inset 0 0 10px rgba(11,27,77,.12); }
  .slot { display:grid; grid-template-columns:30px minmax(0,1fr); margin-bottom:4px; cursor:pointer; }
  .slot .num { display:flex; justify-content:center; padding-top:7px; font-size:9px; font-weight:700;
               color:var(--muted); border-right:1px solid var(--border); letter-spacing:.3px; }
  .eq { position:relative; margin:0 5px 0 5px; padding:7px 9px 6px; min-height:calc(var(--u) * 34px);
        background:var(--chip); border:1px solid var(--border2); border-radius:5px;
        transition:border-color .2s, box-shadow .2s, transform .2s; }
  .eq::before, .eq::after { content:""; position:absolute; top:5px; width:4px; height:4px; border-radius:50%;
        background:var(--border2); }
  .eq::before { left:-1px; transform:translateX(-50%); display:none; }
  .eq::after { right:4px; }
  .slot:hover .eq { border-color:var(--accent); transform:translateX(2px); }
  .slot.sel .eq { border-color:var(--accent); background:color-mix(in srgb, var(--accent) 10%, transparent); box-shadow:0 0 18px color-mix(in srgb, var(--accent) 20%, transparent); }
  .slot.sel .num { color:var(--accent); }
  .slot.alerta .eq { border-color:rgba(251,113,133,.55); }
  .slot.alerta .num { color:var(--bad); }
  .eq .r1 { display:flex; align-items:center; gap:7px; font-size:12px; padding-right:10px; }
  .eq .r1 .u { background:var(--panel); border:1px solid var(--border2); border-radius:4px;
               padding:0 5px; font-size:9px; color:var(--muted); font-weight:700; }
  .eq .r1 b { color:var(--text); font-weight:600; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .eq .r1 em { margin-left:auto; font-style:normal; color:var(--muted); font-size:9px; white-space:nowrap; }
  .leds { display:flex; flex-wrap:wrap; gap:4px 3px; margin-top:7px; }
  .led { width:16px; text-align:center; cursor:default; }
  .led i { display:block; width:12px; height:8px; margin:0 auto; border-radius:2px; background:var(--na); transition:transform .15s; }
  .led b { display:block; margin-top:1px; font-size:7px; line-height:1.1; font-weight:600; color:var(--muted); }
  .led:hover i { transform:scale(1.35); }
  .led.up i { background:var(--led); box-shadow:0 0 6px var(--led); }
  .led.down i { background:var(--bad); }
  .led.otro i { background:var(--warn); }
  .led.sfp i { border-radius:50%; width:9px; height:9px; }
  .solo { margin-top:6px; color:var(--muted); font-size:10px; }
  .libre { margin:0 5px 0 35px; padding:12px 0; text-align:center; font-size:10px; letter-spacing:.8px;
           color:var(--muted); border:1px dashed var(--border); border-radius:5px; opacity:.8; }
  .pinfo { margin-top:8px; background:var(--panel); border:1px solid var(--border); border-radius:8px;
           padding:7px 10px; font-size:11px; color:var(--muted); min-height:40px; line-height:1.4; }
  .pinfo b { color:var(--text); }
  .pinfo .up { color:var(--ok); } .pinfo .down { color:var(--bad); } .pinfo .otro { color:var(--warn); }
  #tema { width:100%; margin-top:12px; }
  .cuenta { border-top:1px solid var(--border); margin-top:14px; padding-top:12px; font-size:12px; }
  .cuenta .cu-n { color:var(--text); font-size:13px; font-weight:600; }
  .cuenta .cu-r { color:var(--muted); margin-bottom:6px; }
  .cuenta .cu-l a { color:var(--accent); margin-right:10px; text-decoration:none; }
  .cuenta .cu-l a:hover { text-decoration:underline; }
  .cuenta form { margin-top:8px; } .cuenta button { width:100%; }
  .alertas-lado { border-top:1px solid var(--border); margin-top:14px; padding-top:14px; }
  #alertas { max-height:280px; }
  .al-res { color:var(--muted); font-size:11px; margin:4px 0 2px; }
  .al { display:flex; gap:10px; align-items:flex-start; background:var(--panel); border:1px solid var(--border);
        border-left:3px solid var(--na); border-radius:9px; padding:8px 10px; margin-bottom:7px; cursor:pointer;
        transition:transform .2s, border-color .2s; }
  .al:hover { transform:translateX(2px); border-color:var(--border2); }
  .al.crit { border-left-color:var(--bad); background:linear-gradient(90deg, rgba(251,113,133,.12), transparent 75%), var(--panel); }
  .al.warn { border-left-color:var(--warn); background:linear-gradient(90deg, rgba(251,191,36,.10), transparent 75%), var(--panel); }
  .al .ic { width:8px; height:8px; border-radius:50%; margin-top:4px; flex:none; background:currentColor; box-shadow:0 0 8px currentColor; }
  .al.crit .ic { color:var(--bad); animation:pulso 1.8s infinite; } .al.warn .ic { color:var(--warn); }
  .al .tx { min-width:0; flex:1; }
  .al .nv { font-size:9px; letter-spacing:1px; font-weight:700; }
  .al.crit .nv { color:var(--bad); } .al.warn .nv { color:var(--warn); }
  .al .hs { color:var(--muted); font-size:10px; margin-left:6px; }
  .al .ms { font-size:12px; line-height:1.3; margin-top:2px; word-break:break-word; }

  /* ---------- Centro ---------- */
  .cab { display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap; margin-bottom:16px; }
  .cab h1 { margin:0; font-size:20px; font-weight:700; letter-spacing:.3px; }
  .cab .sub { color:var(--muted); font-size:12px; margin-top:3px; }
  .live { display:inline-flex; align-items:center; gap:7px; color:var(--ok); font-size:11px; font-weight:600;
          letter-spacing:1px; border:1px solid var(--ok); border-radius:999px; padding:4px 11px;
          background:rgba(52,211,153,.08); }
  .live i { width:7px; height:7px; border-radius:50%; background:var(--ok); color:var(--ok); animation:pulso 1.8s infinite; }

  .kpis { display:grid; grid-template-columns:repeat(auto-fit, minmax(190px,1fr)); gap:14px; margin-bottom:16px; }
  .kpi { display:flex; align-items:center; gap:14px; background:var(--card); border:1px solid var(--border);
         border-radius:14px; padding:16px; box-shadow:var(--shadow), var(--glow); -webkit-backdrop-filter:var(--vidrio); backdrop-filter:var(--vidrio);
         transition:transform .25s, border-color .25s, box-shadow .25s; }
  .kpi:hover { transform:translateY(-2px); border-color:var(--border2); }
  .kpi .ico { width:48px; height:48px; border-radius:14px; display:grid; place-items:center; flex:none;
              color:var(--accent); background:rgba(11,59,230,.10); background:color-mix(in srgb, var(--accent) 13%, transparent);
              box-shadow:0 0 18px color-mix(in srgb, var(--accent) 18%, transparent); }
  .kpi .ico svg { width:26px; height:26px; }
  .kpi .kl { color:var(--muted); font-size:11px; letter-spacing:.8px; font-weight:600; }
  .kpi .kv { font-size:28px; font-weight:700; line-height:1.15; }
  .kpi .kv.txt { font-size:22px; }
  .kpi .kv small { font-size:12px; font-weight:400; color:var(--muted); margin-left:4px; }
  .kpi.ok .ico { color:var(--ok); background:rgba(52,211,153,.12); box-shadow:0 0 18px rgba(52,211,153,.2); }
  .kpi.ok .kv.est { color:var(--ok); }
  .kpi.warn .ico { color:var(--warn); background:rgba(251,191,36,.12); box-shadow:0 0 18px rgba(251,191,36,.2); }
  .kpi.warn .kv.est { color:var(--warn); }
  .kpi.bad .ico { color:var(--bad); background:rgba(251,113,133,.14); box-shadow:0 0 20px rgba(251,113,133,.3); }
  .kpi.bad .kv.est { color:var(--bad); }
  .kpi.alarma { border-color:rgba(251,113,133,.5); animation:aparecer .55s ease both, alarma 2.4s ease-in-out infinite .6s; }
  .kpi.morado .ico { color:var(--sfp); background:rgba(61,107,255,.14); box-shadow:0 0 18px rgba(61,107,255,.22); }

  .dev-head { display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:10px; }
  .dev-head h2 { margin:0; font-size:18px; font-weight:700; }
  .dev-head .s { color:var(--muted); font-size:12px; margin-top:3px; }
  .pill { display:inline-flex; align-items:center; gap:7px; font-size:12px; font-weight:600; border-radius:999px;
          padding:4px 12px; border:1px solid currentColor; background:rgba(127,147,189,.08); }
  .pill i { width:7px; height:7px; border-radius:50%; background:currentColor; box-shadow:0 0 8px currentColor; }

  .gauges { display:flex; flex-wrap:wrap; gap:26px; justify-content:center; padding:20px 0 12px; }
  .gauge { width:118px; text-align:center; position:relative; }
  .gauge svg { width:118px; height:118px; transform:rotate(-90deg); overflow:visible; }
  .gauge circle { fill:none; stroke-width:9; }
  .g-track { stroke:var(--track); }
  .g-val { stroke-linecap:round; stroke-dasharray:251.327; stroke-dashoffset:251.327;
           transition:stroke-dashoffset 1.1s cubic-bezier(.22,1,.36,1), stroke .4s;
           filter:drop-shadow(0 0 5px currentColor); }
  .g-txt { position:absolute; top:0; left:0; width:118px; height:118px; display:grid; place-items:center;
           font-size:20px; font-weight:700; }
  .g-txt b { font-weight:700; max-width:76px; text-align:center; line-height:1.1; }
  .g-txt b.chico { font-size:15px; }
  .g-lbl { margin-top:8px; font-size:12px; color:var(--muted); font-weight:600; letter-spacing:.5px; }
  .g-err { display:block; color:var(--bad); font-size:10px; margin-top:2px; }

  .panel { background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:14px; margin-top:6px; }
  .panel .ph { display:flex; justify-content:space-between; margin-bottom:12px; font-size:12px; }
  .puertos { display:flex; flex-wrap:wrap; gap:8px; }
  .tile { width:76px; height:74px; background:var(--chip); border:1px solid var(--border2);
          border-radius:8px; text-align:center; color:var(--tileText); cursor:default;
          padding:0 3px; overflow:hidden; transition:transform .18s, box-shadow .18s; }
  .tile:hover { transform:translateY(-3px) scale(1.04); }
  .tile i { display:block; width:15px; height:5px; border-radius:3px; margin:7px auto 4px; background:var(--na); }
  .tile b { display:block; font-size:12px; font-weight:600; }
  .tile .pn { display:block; font-size:10px; color:var(--text); margin-top:2px; font-weight:600;
              white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .tile .pa { display:block; font-size:9px; color:var(--muted); margin-top:1px; min-height:11px;
              white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .tile.up { box-shadow:0 0 12px rgba(34,211,238,.14); }
  .tile.up i { background:var(--led); box-shadow:0 0 8px var(--led); }
  .tile.down { border-color:rgba(251,113,133,.35); }
  .tile.down i { background:var(--bad); box-shadow:0 0 8px var(--bad); }
  .tile.otro i { background:var(--warn); box-shadow:0 0 8px var(--warn); }
  .tile.sfp { border-color:var(--sfp); }
  .aviso { color:var(--warn); font-size:12px; margin-top:8px; }

  .seccion { display:flex; align-items:center; gap:10px; }
  .graficas { display:grid; grid-template-columns:repeat(2, minmax(0,1fr)); gap:14px; margin-top:14px; }
  @media (max-width:760px) { .graficas { grid-template-columns:1fr; } }
  .gbox { background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:14px; }
  #gb-traf { grid-column:1 / -1; }
  .gtit { color:var(--text); font-size:13px; font-weight:600; margin-bottom:8px; }
  .gtit span { color:var(--muted); font-weight:400; }
  .grafica { height:230px; position:relative; }
  #gb-traf .grafica { height:250px; }
  .grafica.alta { height:260px; }

  .fila2 { display:grid; grid-template-columns:minmax(0,1.5fr) minmax(0,1fr); gap:16px; align-items:stretch; }
  @media (max-width:1000px) { .fila2 { grid-template-columns:1fr; } }
  .fila2 .card { margin-bottom:16px; }
  .svc { display:flex; justify-content:space-between; align-items:center; gap:10px; padding:9px 0;
         border-bottom:1px solid var(--border); font-size:13px; }
  .svc:last-child { border-bottom:0; }
  .st { display:inline-flex; align-items:center; gap:7px; font-size:12px; font-weight:600; }
  .st i { width:8px; height:8px; border-radius:50%; background:currentColor; box-shadow:0 0 8px currentColor; }

  /* ---------- Derecha y listas ---------- */
  .der { position:sticky; top:16px; }
  .lista { max-height:300px; overflow-y:auto; margin-top:10px; }
  .lista.log { max-height:calc(100vh - 250px); min-height:260px; margin-top:12px; }
  .lista::-webkit-scrollbar { width:6px; } .lista::-webkit-scrollbar-thumb { background:var(--border2); border-radius:3px; }
  .item { border-left:3px solid var(--na); background:var(--panel); border-radius:8px;
          padding:8px 11px; margin-bottom:7px; font-size:12px; transition:transform .2s; }
  .item:hover { transform:translateX(2px); }
  .item.crit { border-left-color:var(--bad); box-shadow:0 0 14px rgba(251,113,133,.08); }
  .item.warn { border-left-color:var(--warn); }
  .item.ok { border-left-color:var(--ok); }
  .item .h { color:var(--muted); font-size:10px; margin-bottom:3px; }
  .ev { display:flex; gap:11px; padding:10px 8px; border-bottom:1px solid var(--border); border-radius:8px; }
  .ev:last-child { border-bottom:0; }
  .ev.nuevo { animation:resalte 4s ease-out; }
  .ev .pt { width:9px; height:9px; border-radius:50%; margin-top:5px; flex:none; background:var(--na); }
  .ev.crit .pt { background:var(--bad); box-shadow:0 0 9px var(--bad); }
  .ev.warn .pt { background:var(--warn); box-shadow:0 0 9px var(--warn); }
  .ev.ok .pt { background:var(--ok); box-shadow:0 0 9px var(--ok); }
  .ev .tx { flex:1; min-width:0; }
  .ev .m { font-size:13px; line-height:1.3; word-break:break-word; }
  .ev .h { color:var(--muted); font-size:11px; margin-top:3px; }
  .ev .t { color:var(--muted); font-size:11px; white-space:nowrap; margin-top:2px; }
  .tag { display:inline-block; font-size:9px; letter-spacing:.8px; border:1px solid var(--border2);
         border-radius:4px; padding:0 5px; margin-left:6px; color:var(--accent); font-weight:600; }
  #zerr { color:var(--warn); }
  .vacio { color:var(--muted); font-size:12px; padding:10px 0; }
  .badge { display:inline-block; min-width:20px; text-align:center; border-radius:10px;
           padding:1px 7px; font-size:11px; font-weight:700; background:var(--bad); color:#fff; margin-left:6px; }
  .badge.cero { background:var(--ok); color:#04130d; }
  .hrow { display:flex; justify-content:space-between; align-items:center; gap:8px; }
  .chips { display:flex; gap:6px; flex-wrap:wrap; margin-top:10px; }
  .chips button { border-radius:999px; padding:4px 12px; font-size:12px; }
  .chips button.on { background:color-mix(in srgb, var(--accent) 16%, transparent); border-color:var(--accent); color:var(--accent); }
  @media (prefers-reduced-motion:reduce) { *, *::before, *::after { animation:none !important; transition:none !important; } }

  @media (prefers-reduced-transparency:reduce) {
    :root:not([data-theme="light"]) { --side:rgba(6,15,51,.92); --card:linear-gradient(165deg, rgba(11,27,77,.94), rgba(6,15,51,.97));
            --panel:rgba(4,10,38,.6); --tip:rgba(6,15,51,.97); --vidrio:none; }
  }
  @supports not ((backdrop-filter:blur(1px)) or (-webkit-backdrop-filter:blur(1px))) {
    :root:not([data-theme="light"]) { --side:rgba(6,15,51,.85); --card:linear-gradient(165deg, rgba(11,27,77,.90), rgba(6,15,51,.93));
            --panel:rgba(4,10,38,.55); }
  }

  /* ---- Plan de acción ---- */
  .pa-nota { color:var(--muted); font-size:11px; margin:6px 0 12px; }
  .pa { border:1px solid var(--border); border-left:3px solid var(--na); border-radius:12px; background:var(--panel); margin-bottom:9px; overflow:hidden; }
  .pa.p1 { border-left-color:var(--bad); } .pa.p2 { border-left-color:#fb923c; } .pa.p3 { border-left-color:var(--warn); }
  .pa > summary { list-style:none; cursor:pointer; display:flex; align-items:center; gap:10px; padding:10px 12px; }
  .pa > summary::-webkit-details-marker { display:none; }
  .pa > summary::after { content:''; margin-left:auto; width:8px; height:8px; border-right:2px solid var(--muted); border-bottom:2px solid var(--muted); transform:rotate(45deg); transition:transform .2s; flex:none; }
  .pa[open] > summary::after { transform:rotate(-135deg); }
  .pa > summary:focus-visible { outline:2px solid var(--accent); outline-offset:-2px; }
  .pa-p { font-size:10px; font-weight:700; border-radius:6px; padding:2px 7px; flex:none; color:#fff; background:var(--warn); color:#1a1200; }
  .pa.p1 .pa-p { background:var(--bad); color:#fff; } .pa.p2 .pa-p { background:#fb923c; color:#1a0d00; }
  .pa-t { min-width:0; } .pa-t b { font-size:13px; } .pa-t span { display:block; color:var(--muted); font-size:11px; margin-top:1px; word-break:break-word; }
  .pa-prog { font-size:11px; color:var(--muted); flex:none; }
  .pa-cuerpo { padding:4px 14px 14px; border-top:1px solid var(--border); }
  .pa-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:16px; margin-top:12px; }
  .pa h3 { margin:0 0 6px; font-size:12px; color:var(--accent); font-weight:700; }
  .pa ul, .pa ol { margin:0; padding-left:18px; font-size:12.5px; line-height:1.45; }
  .pa li { margin-bottom:4px; }
  .pa ol.pasos { list-style:none; padding:0; }
  .pa ol.pasos li { margin-bottom:6px; }
  .pa ol.pasos label { display:flex; gap:8px; align-items:flex-start; cursor:pointer; margin:0; font-size:12.5px; line-height:1.45; color:var(--text); letter-spacing:0; }
  .pa ol.pasos input { margin-top:3px; flex:none; accent-color:var(--accent); }
  .pa ol.pasos input:checked + span { color:var(--muted); text-decoration:line-through; }
  .pa-plan { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:10px; margin-top:14px; }
  .pa-plan > div { border:1px solid var(--border); border-radius:10px; padding:10px 12px; background:color-mix(in srgb, var(--accent) 5%, transparent); }
  .pa-plan h3 { color:var(--text); } .pa-plan small { color:var(--muted); font-weight:400; }
  .pa-pie { display:flex; gap:14px; flex-wrap:wrap; justify-content:space-between; align-items:flex-end; margin-top:14px; font-size:12px; }
  .pa-pie p { margin:0 0 4px; } .pa-pie b { color:var(--accent); }
  .pa-tip { margin-top:8px; font-size:12px; border-left:2px solid var(--accent); padding:2px 0 2px 10px; color:var(--muted); }
  .pa-rel { margin-top:8px; font-size:12px; color:var(--warn); }
  @media (prefers-reduced-motion: reduce) { .pa > summary::after { transition:none; } }

  /* =====================================================================
     DISEÑO CRISTAL: paneles de vidrio esmerilado sobre fondo lavanda con burbujas.
     Solo cambia la apariencia; ids, clases y lógica se conservan.
     ===================================================================== */
  body { font-family:"Inter","Segoe UI Variable","Segoe UI",system-ui,-apple-system,Roboto,"Helvetica Neue",Arial,sans-serif;
         -webkit-font-smoothing:antialiased; }

  /* Burbujas decorativas (estáticas: no repintan el vidrio y no gastan CPU en una pantalla 24/7) */
  .burbujas { position:fixed; inset:0; overflow:hidden; pointer-events:none; z-index:0; }
  .burbujas i { position:absolute; border-radius:50%; border:1px solid rgba(255,255,255,.55);
    background:radial-gradient(circle at 30% 24%, rgba(255,255,255,.9), rgba(255,255,255,0) 28%),
               radial-gradient(circle at 72% 80%, rgba(139,124,246,.38), rgba(139,124,246,0) 58%),
               radial-gradient(circle at 50% 50%, rgba(255,255,255,.08), rgba(170,195,255,.26) 70%, rgba(255,255,255,.5));
    box-shadow:inset 0 0 46px rgba(255,255,255,.5), 0 30px 80px rgba(90,100,190,.22); }
  .burbujas .b1 { width:300px; height:300px; left:-110px; top:7%; }
  .burbujas .b2 { width:360px; height:360px; right:-140px; top:30%; }
  .burbujas .b3 { width:240px; height:240px; left:38%; bottom:-130px; }
  .burbujas .b4 { width:110px; height:110px; right:24%; top:-40px; }
  .burbujas .b5 { width:84px; height:84px; left:5%; bottom:16%; }
  [data-theme="dark"] .burbujas i { opacity:.5; border-color:rgba(255,255,255,.22);
    box-shadow:inset 0 0 46px rgba(160,170,255,.25), 0 30px 80px rgba(10,10,60,.5); }

  .layout { position:relative; z-index:1; max-width:1780px; margin:0 auto; padding:22px; gap:22px; }
  .side, .card, .cab { border-radius:var(--rad); }
  .side { padding:20px; border:1px solid var(--border); box-shadow:var(--shadow), var(--glow); }
  .card { padding:22px; margin-bottom:22px; }
  .fila2 .card { margin-bottom:22px; }
  .fila2 { gap:22px; }

  /* Títulos de sección en minúscula normal, sin etiquetas gritando */
  .titulo { font-size:16px; font-weight:700; letter-spacing:0; }
  .titulo.ac { text-transform:none; font-size:15px; letter-spacing:0; color:var(--text); }

  /* Marca */
  .marca { gap:12px; margin-bottom:18px; padding-bottom:16px; border-bottom:1px solid var(--border); }
  .marca .logo { width:44px; height:44px; border-radius:15px; background:linear-gradient(140deg,#2f5bea,#8b7cf6);
                 box-shadow:0 10px 22px rgba(63,91,234,.38), 0 1px 0 rgba(255,255,255,.5) inset; }
  .marca b { font-size:17px; font-weight:700; } .marca span { font-size:12px; }

  /* Bastidor: cada equipo es una pastilla de vidrio */
  .bast-t b { font-size:12px; letter-spacing:0; font-weight:600; color:var(--text); }
  .bastidor { border:1px solid var(--border); border-radius:22px; padding:8px 0; background:var(--panel); box-shadow:inset 0 1px 0 rgba(255,255,255,.35); }
  [data-theme="light"] .bastidor { background:rgba(255,255,255,.38); box-shadow:inset 0 1px 8px rgba(70,80,160,.10); }
  .slot .num { border-right:0; }
  .eq { border-radius:16px; background:var(--chip); border:1px solid var(--border); }
  .eq::after { display:none; }
  .slot:hover .eq { border-color:var(--accent); }
  .slot.sel .eq { background:linear-gradient(135deg, rgba(47,91,234,.22), rgba(139,124,246,.22)); border-color:rgba(47,91,234,.55);
                  box-shadow:0 8px 22px rgba(47,91,234,.22); }
  .slot.alerta .eq { border-color:rgba(251,113,133,.6); }
  .libre { border-radius:14px; }
  .pinfo { border-radius:16px; background:var(--panel); }

  /* Cuenta: chip de perfil con avatar */
  .cuenta { display:grid; grid-template-columns:44px 1fr; column-gap:12px; align-items:center; margin-top:16px; padding:12px;
            background:var(--panel); border:1px solid var(--border); border-radius:22px; }
  .cu-av { grid-row:1 / 3; width:44px; height:44px; border-radius:50%; display:grid; place-items:center; font-weight:700; font-size:18px;
           color:#fff; background:linear-gradient(140deg,#5b7cf6,#8b5cf6); box-shadow:0 8px 18px rgba(91,124,246,.4); }
  .cuenta .cu-r { margin:0; }
  .cuenta .cu-l, .cuenta form { grid-column:1 / -1; }
  .cuenta .cu-l { margin-top:10px; }

  /* Botones en píldora; el principal lleva el azul de la referencia */
  button { border-radius:999px; padding:8px 16px; font-weight:500; background:var(--chip); border:1px solid var(--border);
           box-shadow:0 1px 0 rgba(255,255,255,.55) inset, 0 4px 12px rgba(70,80,160,.08); }
  button:hover { background:var(--chip); border-color:var(--accent); }
  #exportar { background:linear-gradient(135deg,#2f5bea,#5b7cf6); color:#fff; border-color:transparent; box-shadow:0 8px 18px rgba(47,91,234,.35); }
  #exportar:hover { filter:brightness(1.08); border-color:transparent; }
  input[type=search] { border-radius:999px; background-color:var(--chip); border:1px solid var(--border); padding:10px 16px 10px 40px; background-position:15px center; }

  /* Filtros como control segmentado (Todos / Críticos / Alertas / OK) */
  .chips { display:inline-flex; gap:2px; padding:4px; background:var(--panel); border:1px solid var(--border); border-radius:999px; }
  .chips button { border:0; background:transparent; box-shadow:none; padding:6px 12px; }
  .chips button:hover { background:color-mix(in srgb, var(--accent) 10%, transparent); }
  .chips button.on { background:linear-gradient(135deg,#2f5bea,#5b7cf6); color:#fff; box-shadow:0 6px 16px rgba(47,91,234,.35); }

  /* Encabezado como barra de vidrio */
  .cab { background:var(--card); border:1px solid var(--border); box-shadow:var(--shadow), var(--glow);
         -webkit-backdrop-filter:var(--vidrio); backdrop-filter:var(--vidrio); padding:20px 26px; margin-bottom:22px; }
  .cab h1 { font-size:26px; font-weight:700; letter-spacing:-.2px; }
  .cab .sub { font-size:13px; margin-top:4px; }
  .live { font-size:12px; letter-spacing:.2px; border-color:color-mix(in srgb, var(--ok) 45%, transparent); background:color-mix(in srgb, var(--ok) 12%, transparent); }

  /* Detalle del equipo */
  .dev-head h2 { font-size:22px; }
  .gauge circle { stroke-width:10; }
  .panel, .gbox { border-radius:22px; padding:18px; background:var(--panel); border:1px solid var(--border); }
  .panel .ph { margin-bottom:14px; }
  .tile { border-radius:16px; width:82px; height:78px; background:var(--chip); border:1px solid var(--border); }
  .tile.sfp { border-color:var(--sfp); }
  .svc { padding:12px 4px; }

  /* Listas: alertas, eventos, plan de acción */
  .al { border-radius:16px; border-left-width:4px; }
  .item { border-radius:14px; }
  .ev { border-radius:16px; padding:12px 10px; }
  .ev:hover { background:var(--panel); }
  .tag { border-radius:999px; padding:1px 8px; background:var(--chip); font-weight:600; }
  details.pa { border-radius:20px; border-left-width:4px; }
  /* el alias del puerto reutiliza la clase .pa: se neutraliza para que no herede el estilo de las tarjetas del plan */
  .tile .pa { border:0; border-radius:0; background:none; margin:1px 0 0; overflow:hidden; }
  .pa-plan > div { border-radius:16px; }
  .pa-p { border-radius:999px; padding:2px 9px; }
  .pill { background:color-mix(in srgb, currentColor 10%, transparent); }

  @media (max-width:820px) {
    :root { --rad:22px; }
    .layout { padding:12px; gap:14px; }
    .cab { padding:16px 18px; } .cab h1 { font-size:21px; }
    .burbujas .b1, .burbujas .b2 { opacity:.7; }
  }
  @media (prefers-reduced-transparency:reduce) {
    :root[data-theme="light"] { --side:rgba(255,255,255,.95); --card:rgba(255,255,255,.97); --panel:#eef1fd; --chip:#f3f5fe; --vidrio:none; }
    :root[data-theme="dark"] { --side:#1a1d4a; --card:#1c1f50; --panel:#23275c; --chip:#2a2e68; --vidrio:none; }
  }
  @supports not ((backdrop-filter:blur(1px)) or (-webkit-backdrop-filter:blur(1px))) {
    :root[data-theme="light"] { --side:rgba(255,255,255,.88); --card:rgba(255,255,255,.90); --panel:rgba(244,246,254,.92); }
    :root[data-theme="dark"] { --side:rgba(26,29,74,.92); --card:rgba(28,31,80,.94); --panel:rgba(35,39,92,.9); }
  }

  /* =====================================================================
     TABLERO NOC: mosaicos de color, topología, panal de puertos y resúmenes
     (misma paleta del tema; solo cambia la composición del centro)
     ===================================================================== */
  .kpis { display:grid; grid-template-columns:repeat(auto-fit, minmax(124px,1fr)); gap:14px; margin-bottom:22px; }
  .kpi { --k1:#6f8dff; --k2:#3d5bea; position:relative; display:flex; flex-direction:column; align-items:center; justify-content:center;
         text-align:center; gap:8px; min-height:128px; padding:18px 12px; border-radius:22px; color:#fff;
         border:1px solid rgba(255,255,255,.45); background:linear-gradient(150deg,var(--k1),var(--k2));
         box-shadow:0 14px 28px color-mix(in srgb, var(--k2) 32%, transparent), 0 1px 0 rgba(255,255,255,.5) inset;
         overflow:hidden; -webkit-backdrop-filter:none; backdrop-filter:none; }
  .kpi::after { content:""; position:absolute; inset:0; pointer-events:none;
                background:radial-gradient(120% 70% at 20% -10%, rgba(255,255,255,.34), transparent 60%); }
  .kpi.ok { --k1:#34d399; --k2:#0f9d68; }
  .kpi.warn { --k1:#f5a623; --k2:#d97706; }
  .kpi.bad { --k1:#fb7185; --k2:#e11d48; }
  .kpi.morado { --k1:#a393fa; --k2:#6d5ae0; }
  .kpi.neutro { --k1:#8b97c9; --k2:#5d6aa6; }
  .kpi .kv, .kpi.ok .kv.est, .kpi.warn .kv.est, .kpi.bad .kv.est { color:#fff; font-weight:700; letter-spacing:-1px; line-height:1;
                                                                     text-shadow:0 2px 8px rgba(0,0,0,.18); }
  .kpi .kv { font-size:42px; }
  .kpi .kv.txt { font-size:23px; letter-spacing:-.3px; }
  .kpi .kv small { font-size:13px; font-weight:500; color:rgba(255,255,255,.88); margin-left:6px; letter-spacing:0; }
  .kpi .kl { font-size:13px; font-weight:600; color:#fff; letter-spacing:0; text-shadow:0 1px 2px rgba(0,0,0,.22); }
  .kpi .kl small { display:block; font-weight:500; opacity:.9; margin-top:2px; }

  /* Topología + resúmenes */
  .fila-topo { display:grid; grid-template-columns:minmax(0,2.1fr) minmax(0,1fr); gap:22px; align-items:stretch; }
  .fila-topo > .card, .col-res > .card { margin-bottom:22px; }
  .col-res { display:flex; flex-direction:column; min-width:0; }
  .col-res > .card:last-child { flex:1; }
  .topo { overflow-x:auto; margin-top:8px; }
  .topo svg { width:100%; min-width:560px; height:auto; display:block; }
  .arista { fill:none; stroke-width:3; stroke-linecap:round; }
  .arista.ok { stroke:var(--ok); } .arista.warn { stroke:var(--warn); } .arista.bad { stroke:var(--bad); }
  .arista.na { stroke:var(--na); stroke-dasharray:6 7; }
  .tn { cursor:pointer; }
  .tn .halo { fill:none; stroke:var(--accent); stroke-width:2.5; stroke-dasharray:5 5; opacity:0; }
  .tn.sel .halo { opacity:1; }
  .tn .caja { fill:var(--chip); stroke-width:3; transition:filter .2s; }
  .tn:hover .caja { filter:drop-shadow(0 6px 12px rgba(60,80,200,.35)); }
  .tn .gl { fill:none; stroke:var(--text); stroke-width:2; stroke-linecap:round; stroke-linejoin:round; }
  .tn .nube { fill:var(--chip); stroke-width:3; }
  .tn text { fill:var(--text); text-anchor:middle; font-weight:700; font-size:16px; }
  .tn text.sub { fill:var(--muted); font-weight:500; font-size:13px; }
  .tn .est { stroke:var(--chip); stroke-width:2; }
  .est.ok { fill:var(--ok); } .est.warn { fill:var(--warn); } .est.bad { fill:var(--bad); } .est.na { fill:var(--na); }
  .tn .caja.ok, .tn .nube.ok { stroke:var(--ok); } .tn .caja.warn, .tn .nube.warn { stroke:var(--warn); }
  .tn .caja.bad, .tn .nube.bad { stroke:var(--bad); } .tn .caja.na, .tn .nube.na { stroke:var(--na); }
  .topo-ley { display:flex; flex-wrap:wrap; gap:16px; font-size:12px; color:var(--muted); margin-top:6px; }
  .topo-ley span { display:inline-flex; align-items:center; gap:6px; }
  .topo-ley i { width:11px; height:11px; border-radius:3px; display:inline-block; }
  .topo-ley i.ok { background:var(--ok); } .topo-ley i.warn { background:var(--warn); }
  .topo-ley i.bad { background:var(--bad); } .topo-ley i.na { background:var(--na); }

  .rnodos { display:grid; grid-template-columns:repeat(auto-fit, minmax(96px,1fr)); gap:12px; margin-top:12px; }
  .rn { border-radius:18px; padding:16px 8px; text-align:center; color:#fff; box-shadow:0 10px 22px rgba(60,70,150,.2), 0 1px 0 rgba(255,255,255,.45) inset; }
  .rn b { display:block; font-size:32px; line-height:1.1; font-weight:700; }
  .rn span { font-size:12px; font-weight:600; text-shadow:0 1px 2px rgba(0,0,0,.2); }
  .rn.ok { background:linear-gradient(150deg,#34d399,#0f9d68); } .rn.bad { background:linear-gradient(150deg,#fb7185,#e11d48); }
  .rn.warn { background:linear-gradient(150deg,#f5a623,#d97706); } .rn.na { background:linear-gradient(150deg,#a393fa,#6d5ae0); }
  .rn.total { background:var(--panel); color:var(--text); border:1px solid var(--border); box-shadow:none; }
  .rn.total span { text-shadow:none; color:var(--muted); }
  .rsev { display:flex; flex-direction:column; gap:10px; margin-top:12px; }
  .sv { width:var(--w); min-width:58%; display:flex; align-items:center; gap:10px; padding:9px 16px; border-radius:999px; color:#fff;
        font-size:13px; font-weight:600; text-shadow:0 1px 2px rgba(0,0,0,.2); transition:width .6s ease; }
  .sv b { font-size:18px; }
  .sv.bad { background:linear-gradient(90deg,#fb7185,#e11d48); } .sv.warn { background:linear-gradient(90deg,#f5a623,#d97706); }
  .sv.ok { background:linear-gradient(90deg,#2dd4bf,#0f9d68); }

  /* Panal de puertos */
  .puertos { display:block; }
  .hx-fila { display:flex; gap:4px; margin-top:-19px; }
  .hx-fila:first-child { margin-top:0; }
  .hexw { width:78px; height:90px; flex:none; filter:drop-shadow(0 6px 7px rgba(50,60,140,.28)); transition:transform .15s ease; position:relative; }
  .hexw:hover { transform:translateY(-3px) scale(1.06); z-index:3; }
  .hex { --h1:#2dd4bf; --h2:#0d9488; width:100%; height:100%; display:flex; flex-direction:column; align-items:center; justify-content:center;
         padding:0 10px; text-align:center; color:#fff; background:linear-gradient(150deg,var(--h1),var(--h2));
         clip-path:polygon(50% 0, 100% 25%, 100% 75%, 50% 100%, 0 75%, 0 25%); }
  .hex.down { --h1:#fb7185; --h2:#e11d48; } .hex.otro { --h1:#f5a623; --h2:#d97706; } .hex.na { --h1:#a3adc9; --h2:#6b7499; }
  .hex.up.sfp { --h1:#8da2ff; --h2:#4f5fe8; }
  .hex b { font-size:15px; line-height:1.1; text-shadow:0 1px 2px rgba(0,0,0,.25); }
  .hex span { font-size:9px; max-width:58px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; opacity:.95; margin-top:2px; }

  /* Top de recursos con barras segmentadas */
  .toprec { margin-top:8px; font-size:13px; }
  .tr { display:grid; grid-template-columns:minmax(90px,1.1fr) minmax(150px,1.5fr) minmax(150px,1.5fr); gap:12px; align-items:center;
        padding:10px 4px; border-bottom:1px solid var(--border); }
  .tr:last-child { border-bottom:0; }
  .tr.h { color:var(--muted); font-size:12px; font-weight:600; }
  .tr .nm { font-weight:600; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .seg { display:inline-flex; gap:2px; vertical-align:middle; margin-right:8px; }
  .seg i { width:7px; height:15px; border-radius:2px; background:var(--track); display:block; }
  .seg i.g { background:#34d399; } .seg i.a { background:#fbbf24; } .seg i.r { background:#fb7185; }
  .tr .v { font-variant-numeric:tabular-nums; font-weight:600; font-size:12.5px; }

  /* Estado por equipo: mosaicos de color */
  .rtiles { display:grid; grid-template-columns:repeat(auto-fill, minmax(126px,1fr)); gap:10px; margin-top:12px; }
  .rt { display:flex; flex-direction:column; align-items:center; gap:4px; padding:14px 8px; border-radius:16px; color:#fff; text-align:center;
        cursor:pointer; box-shadow:0 8px 18px rgba(60,70,150,.18), 0 1px 0 rgba(255,255,255,.4) inset; transition:transform .15s; }
  .rt:hover { transform:translateY(-2px); }
  .rt svg { width:22px; height:22px; fill:none; stroke:#fff; stroke-width:2.4; stroke-linecap:round; stroke-linejoin:round; }
  .rt b { font-size:13px; word-break:break-word; text-shadow:0 1px 2px rgba(0,0,0,.2); }
  .rt em { font-style:normal; font-size:11px; opacity:.95; }
  .rt.ok { background:linear-gradient(150deg,#34d399,#0f9d68); } .rt.bad { background:linear-gradient(150deg,#fb7185,#e11d48); }
  .rt.warn { background:linear-gradient(150deg,#f5a623,#d97706); } .rt.na { background:linear-gradient(150deg,#a3adc9,#6b7499); }
  .rt.sel { outline:3px solid var(--accent); outline-offset:2px; }

  @media (max-width:1100px) { .fila-topo { grid-template-columns:1fr; } }
  @media (max-width:820px) { .kpi .kv { font-size:36px; } .kpi .kv.txt { font-size:21px; } }

  /* ===== Distribución: barra lateral con eventos, cuenta y tema en el encabezado ===== */
  .layout { grid-template-columns:330px minmax(0,1fr); }
  .eventos-lado { border-top:1px solid var(--border); margin-top:16px; padding-top:16px; }
  .eventos-lado .lista.log { max-height:540px; min-height:200px; margin-top:12px; }
  .eventos-lado .chips { margin-top:12px; max-width:100%; }
  .eventos-lado .chips button { padding:6px 11px; }
  .eventos-lado .hrow .titulo { white-space:nowrap; }
  .eventos-lado #exportar { padding:6px 12px; font-size:12.5px; white-space:nowrap; }

  .cab { gap:16px 24px; }
  .cab-izq { min-width:0; }
  .cab-t { display:flex; align-items:center; gap:14px; flex-wrap:wrap; }
  .cab-t h1 { font-size:25px; }
  .cab-der { display:flex; align-items:center; gap:12px; flex-wrap:wrap; justify-content:flex-end; margin-left:auto; }
  .cab .cuenta { display:flex; align-items:center; gap:14px; margin:0; padding:7px 8px 7px 7px; border-radius:999px; font-size:12px; }
  .cab .cuenta .cu-av { width:40px; height:40px; font-size:16px; flex:none; }
  .cab .cuenta .cu-id { min-width:0; line-height:1.25; }
  .cab .cuenta .cu-n { font-size:13.5px; font-weight:700; white-space:nowrap; }
  .cab .cuenta .cu-r { color:var(--muted); margin:0; white-space:nowrap; }
  .cab .cuenta .cu-l { display:flex; flex-direction:column; gap:1px; margin:0; line-height:1.3; white-space:nowrap; }
  .cab .cuenta .cu-l a { margin:0; }
  .cab .cuenta form { margin:0; }
  .cab .cuenta form button { padding:7px 16px; white-space:nowrap; }
  #tema { width:44px; height:44px; padding:0; margin:0; border-radius:50%; display:grid; place-items:center; flex:none; }
  #tema svg { width:21px; height:21px; }

  @media (max-width:1250px) { .layout { grid-template-columns:300px minmax(0,1fr); } }
  @media (max-width:820px) {
    .layout { grid-template-columns:1fr; }
    .cab .cuenta { border-radius:26px; flex-wrap:wrap; }
    .cab-der { width:100%; justify-content:space-between; }
  }
</style>
</head>
<body>
<div class="burbujas" aria-hidden="true"><i class="b1"></i><i class="b2"></i><i class="b3"></i><i class="b4"></i><i class="b5"></i></div>
<div class="layout">

  <aside class="side">
    <div class="marca">
      <div class="logo"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 17l5-5-5-5"/><path d="M12 19h8"/></svg></div>
      <div><b>NOC</b><span>Operaciones de red</span></div>
    </div>
    <div class="bast-t"><b id="bast-t">Bastidor 24U · vista frontal</b><span id="bast-s"></span></div>
    <div class="bastidor" id="lateral">Cargando...</div>
    <div class="pinfo" id="pinfo">Pasa el mouse sobre un puerto del bastidor para ver su nombre.</div>
    <div class="alertas-lado">
      <div class="hrow">
        <span class="titulo ac">Alertas activas</span><span class="badge cero" id="nalert">0</span>
      </div>
      <div class="al-res" id="alres"></div>
      <div class="lista" id="alertas"></div>
      <div class="vacio" id="zerr"></div>
    </div>
    <div class="eventos-lado">
      <div class="hrow">
        <span class="titulo">Eventos recientes</span>
        <button id="exportar">Exportar JSON</button>
      </div>
      <div style="margin-top:12px"><input type="search" id="buscar" placeholder="Buscar equipo, puerto o mensaje..." aria-label="Buscar eventos"></div>
      <div class="chips" id="chips">
        <button class="on" data-f="todos">Todos</button>
        <button data-f="crit">Críticos</button>
        <button data-f="warn">Alertas</button>
        <button data-f="ok">OK</button>
      </div>
      <div class="lista log" id="eventos"></div>
    </div>
  </aside>

  <main>
    <header class="cab">
      <div class="cab-izq">
        <div class="cab-t"><h1>Centro de Operaciones de Red</h1><div class="live"><i></i>En vivo</div></div>
        <div class="sub">Zabbix &rarr; Grafana &rarr; Flask &middot; actualizado <span id="hora">--</span></div>
      </div>
      <div class="cab-der">
        <div class="cuenta">
          <div class="cu-av" aria-hidden="true">__INICIAL__</div>
          <div class="cu-id"><div class="cu-n">__USUARIO__</div><div class="cu-r">__ROL__</div></div>
          <div class="cu-l"><a href="/cuenta">Mi cuenta</a>__LINK_ADMIN__</div>
          <form method="post" action="/logout"><input type="hidden" name="csrf" value="__CSRF__"><button type="submit">Cerrar sesión</button></form>
        </div>
        <button id="tema" type="button" aria-label="Cambiar tema"></button>
      </div>
    </header>

    <section class="kpis">
      <div class="kpi ok" id="kpi-estado"><div class="kv txt est" id="k-estado">--</div><div class="kl">Estado general</div></div>
      <div class="kpi" id="kpi-eq"><div class="kv"><span id="k-eq">0</span><small id="k-eq-s"></small></div><div class="kl">Equipos en línea</div></div>
      <div class="kpi morado" id="kpi-pt"><div class="kv"><span id="k-pt">0</span><small id="k-pt-s"></small></div><div class="kl">Enlaces activos</div></div>
      <div class="kpi neutro" id="kpi-pd"><div class="kv"><span id="k-pd">0</span></div><div class="kl">Puertos sin enlace</div></div>
      <div class="kpi" id="kpi-alertas"><div class="kv"><span id="k-al">0</span></div><div class="kl">Alertas abiertas<small id="k-al-s"></small></div></div>
      <div class="kpi morado" id="kpi-ev"><div class="kv"><span id="k-ev">0</span></div><div class="kl">Eventos registrados</div></div>
    </section>

    <div class="fila-topo">
      <div class="card">
        <div class="hrow"><span class="titulo">Topología de red</span><span class="muted" style="color:var(--muted);font-size:11px">Estado en vivo</span></div>
        <div class="topo" id="topo"></div>
      </div>
      <div class="col-res">
        <div class="card"><div class="hrow"><span class="titulo">Resumen de equipos</span></div><div class="rnodos" id="res-nodos"></div></div>
        <div class="card"><div class="hrow"><span class="titulo">Resumen de alertas</span></div><div class="rsev" id="res-sev"></div></div>
      </div>
    </div>

    <div class="card">
      <div class="dev-head">
        <div>
          <h2 id="dev-nombre">--</h2>
          <div class="s" id="dev-sub"></div>
        </div>
        <span class="pill na" id="dev-estado"><i></i><span>--</span></span>
      </div>
      <div class="gauges" id="gauges"></div>

      <div class="panel" id="panel-puertos">
        <div class="ph">
          <span class="titulo ac" id="panel-titulo">Panel frontal · estado de puertos</span>
          <span class="ok" id="activos">--</span>
        </div>
        <div class="puertos" id="puertos"></div>
        <div class="aviso" id="aviso"></div>
      </div>
    </div>

    <div class="fila2">
      <div class="card">
        <div class="hrow"><span class="titulo">Uso de recursos por equipo</span><span class="muted" style="color:var(--muted);font-size:11px">Mayor CPU primero</span></div>
        <div class="toprec" id="top-rec"></div>
      </div>
      <div class="card">
        <div class="hrow"><span class="titulo">Estado de los equipos</span></div>
        <div class="rtiles" id="servicios"></div>
      </div>
    </div>

    <div class="card">
      <div class="seccion">
        <span class="titulo">Métricas temporales en tiempo real</span>
      </div>
      <div class="graficas">
        <div class="gbox" id="gb-traf"><div class="gtit">Tráfico <span>(Mbps)</span></div>
          <div class="grafica"><canvas id="chart-traf"></canvas></div></div>
        <div class="gbox" id="gb-lat"><div class="gtit">Latencia <span>(ms)</span></div>
          <div class="grafica"><canvas id="chart-lat"></canvas></div></div>
        <div class="gbox" id="gb-cpu"><div class="gtit">CPU <span>(%)</span></div>
          <div class="grafica"><canvas id="chart-cpu"></canvas></div></div>
      </div>
    </div>

    <div class="card">
      <div class="hrow">
        <span class="titulo">Incidencias registradas por equipo</span>
        <span class="muted" style="color:var(--muted);font-size:11px">Últimas 24 h</span>
      </div>
      <div class="grafica alta" style="margin-top:12px"><canvas id="chart-inc"></canvas></div>
    </div>
    <div class="card" id="plan-card">
      <div class="hrow">
        <span class="titulo ac">Plan de acción</span><span class="badge cero" id="npa">0</span>
      </div>
      <div class="pa-nota">Posible afectación, solución y plan para cada alerta abierta, ordenadas por prioridad. Son guías orientativas: valida en el equipo antes de actuar.</div>
      <div id="plan"><div class="vacio">Cargando guías...</div></div>
    </div>
  </main>

</div>

<script src="/static/chart.umd.min.js"></script>
<script>
  const PERMISOS = __PERMISOS__;
  const charts = {};
  let datos = null, sel = null, claveGauges = '', filtroNivel = 'todos', busqueda = '', primeraCarga = true;
  const vistos = new Set();
  const GAUGE_C = 251.327;
  const $ = id => document.getElementById(id);
  const esc = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
  const hora = ts => new Date(ts).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'});
  const css = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
  const reducir = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
  const hace = ts => {
    const s = Math.max(0, (Date.now() - ts) / 1000);
    if (s < 60) return 'ahora';
    if (s < 3600) return 'hace ' + Math.floor(s / 60) + ' min';
    if (s < 86400) return 'hace ' + Math.floor(s / 3600) + ' h';
    return 'hace ' + Math.floor(s / 86400) + ' d';
  };

  // ---------- Tema ----------
  const ICO_SOL = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>';
  const ICO_LUNA = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>';
  function etiquetaTema(t) {
    const b = $('tema'), txt = t === 'dark' ? 'Cambiar a modo claro' : 'Cambiar a modo oscuro';
    b.innerHTML = t === 'dark' ? ICO_SOL : ICO_LUNA;
    b.title = txt; b.setAttribute('aria-label', txt);
  }
  let tema = 'light';
  try { tema = localStorage.getItem('tema-noc') || 'light'; } catch (e) {}
  document.documentElement.setAttribute('data-theme', tema);
  etiquetaTema(tema);
  $('tema').addEventListener('click', () => {
    tema = tema === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', tema);
    etiquetaTema(tema);
    try { localStorage.setItem('tema-noc', tema); } catch (e) {}
    Object.keys(charts).forEach(k => { charts[k].destroy(); delete charts[k]; });
    if (datos) { dibujarGraficas(); pintarGauges(true); }
  });

  // ---------- Números animados ----------
  function animarNumero(el, hasta) {
    const desde = parseFloat(el.dataset.v || '0');
    el.dataset.v = hasta;
    if (reducir || desde === hasta) { el.textContent = hasta; return; }
    const t0 = performance.now(), dur = 700;
    (function paso(t) {
      const k = Math.min(1, (t - t0) / dur), e = 1 - Math.pow(1 - k, 3);
      el.textContent = Math.round(desde + (hasta - desde) * e);
      if (k < 1) requestAnimationFrame(paso);
    })(t0);
  }

  // ---------- Gráficas ----------
  function opciones(apilado, recto) {
    return {
      animation: {duration: reducir ? 0 : 700, easing: 'easeOutQuart'},
      maintainAspectRatio: false, interaction: {mode: 'index', intersect: false},
      plugins: {
        legend: {labels: {color: css('--text'), usePointStyle: true, pointStyle: 'circle', boxWidth: 8, boxHeight: 8}},
        tooltip: {backgroundColor: css('--tip'), borderColor: 'rgba(96,140,255,.4)', borderWidth: 1, titleColor: '#e8efff', bodyColor: '#cfe0ff'}
      },
      scales: {
        x: {stacked: !!apilado, ticks: {color: css('--muted'), maxTicksLimit: 6, maxRotation: recto ? 0 : 50}, grid: {color: css('--grid')}},
        y: {stacked: !!apilado, ticks: {color: css('--muted'), precision: 0}, grid: {color: css('--grid')}, beginAtZero: true}
      }
    };
  }
  function upsert(clave, tipo, data, apilado) {
    if (charts[clave]) { charts[clave].data = data; charts[clave].update(); return; }
    charts[clave] = new Chart($('chart-' + clave), {type: tipo, data: data, options: opciones(apilado, tipo === 'line')});
  }
  function linea(label, vals, color) {
    return {label: label, data: vals, borderColor: color, borderWidth: 2, tension: 0.4,
            pointRadius: 0, pointHoverRadius: 4, pointBackgroundColor: color, fill: true,
            backgroundColor: ctx => {
              const ch = ctx.chart, a = ch.chartArea;
              if (!a) return color + '33';
              const g = ch.ctx.createLinearGradient(0, a.top, 0, a.bottom);
              g.addColorStop(0, color + '66'); g.addColorStop(1, color + '00');
              return g;
            }};
  }
  function barra(label, vals, color) {
    return {label: label, data: vals, backgroundColor: color, borderRadius: 5, borderSkipped: false, maxBarThickness: 34};
  }
  function dibujarGraficas() {
    if (typeof Chart === 'undefined' || !datos) return;
    const d = datos.dispositivos.find(x => x.id === sel);
    if (d) {
      const s = d.series;
      if (d.graficas.includes('traf')) upsert('traf', 'line', {labels: s.traf.t.map(hora), datasets: [
        linea('Entrada (Mbps)', s.traf.rx, '#3d6bff'), linea('Salida (Mbps)', s.traf.tx, '#34d399')]});
      if (d.graficas.includes('lat')) upsert('lat', 'line', {labels: s.lat.t.map(hora), datasets: [linea('Latencia (ms)', s.lat.v, '#fbbf24')]});
      if (d.graficas.includes('cpu')) upsert('cpu', 'line', {labels: s.cpu.t.map(hora), datasets: [linea('CPU (%)', s.cpu.v, '#3d6bff')]});
    }
    const hosts = [];
    datos.tarjetas.forEach(t => { if (!hosts.includes(t.host)) hosts.push(t.host); });
    datos.dispositivos.forEach(x => { if (!hosts.includes(x.host)) hosts.push(x.host); });
    const cuenta = n => hosts.map(h => datos.eventos.filter(e => e.host === h && e.nivel === n).length);
    upsert('inc', 'bar', {labels: hosts, datasets: [
      barra('Críticas', cuenta('crit'), '#fb7185'), barra('Advertencias', cuenta('warn'), '#fbbf24'),
      barra('Recuperaciones', cuenta('ok'), '#34d399')]}, true);
  }

  // ---------- Indicadores circulares ----------
  const PALETA = {cpu: '#3d6bff', mem: '#34d399', lat: '#29b6f6', enl: '#5283fc'};
  function definirGauges(d) {
    const t = l => datos.tarjetas.find(x => x.host === d.host && x.label === l);
    const num = x => { const n = parseFloat(x.texto); return isNaN(n) ? null : n; };
    const col = (k, tj) => !tj || tj.color === 'ok' ? PALETA[k] : tj.color === 'warn' ? css('--warn') : tj.color === 'bad' ? css('--bad') : css('--na');
    const g = [];
    const cpu = t('CPU'), mem = t('Memoria'), lat = t('Latencia');
    if (cpu) g.push({k: 'cpu', label: 'CPU', pct: num(cpu), txt: cpu.texto, color: col('cpu', cpu), err: cpu.error});
    if (mem) g.push({k: 'mem', label: 'Memoria', pct: num(mem), txt: mem.texto, color: col('mem', mem), err: mem.error});
    if (lat) { const ms = num(lat); g.push({k: 'lat', label: 'Latencia', pct: ms == null ? null : Math.min(100, ms), txt: lat.texto, color: col('lat', lat), err: lat.error, chico: true}); }
    if (d.con_puertos && d.puertos.length) {
      const up = d.puertos.filter(p => p.estado === 'up').length;
      g.push({k: 'enl', label: 'Enlaces', pct: up * 100 / d.puertos.length, txt: up + '/' + d.puertos.length,
              color: up === 0 ? css('--bad') : PALETA.enl, err: '', chico: true});
    }
    return g;
  }
  function pintarGauges(forzar) {
    const d = datos.dispositivos.find(x => x.id === sel);
    const cont = $('gauges');
    if (!d) { cont.innerHTML = ''; return; }
    const lista = definirGauges(d);
    const clave = d.id + '|' + lista.map(g => g.k).join(',');
    if (forzar || clave !== claveGauges) {
      claveGauges = clave;
      cont.innerHTML = lista.map(g =>
        '<div class="gauge" data-k="' + g.k + '"><svg viewBox="0 0 100 100"><circle class="g-track" cx="50" cy="50" r="40"/>' +
        '<circle class="g-val" cx="50" cy="50" r="40"/></svg><div class="g-txt"><b>--</b></div>' +
        '<div class="g-lbl">' + esc(g.label) + '</div><small class="g-err"></small></div>').join('') ||
        '<div class="vacio">Este equipo no reporta métricas de recursos.</div>';
      void cont.offsetWidth;   // fuerza el reflujo para que la primera animación se vea
    }
    lista.forEach(g => {
      const el = cont.querySelector('[data-k="' + g.k + '"]'); if (!el) return;
      const v = g.pct == null ? 0 : Math.max(0, Math.min(100, g.pct));
      const arco = el.querySelector('.g-val');
      arco.style.stroke = g.color; arco.style.color = g.color;
      requestAnimationFrame(() => { arco.style.strokeDashoffset = GAUGE_C * (1 - v / 100); });
      const b = el.querySelector('.g-txt b');
      b.textContent = g.pct == null ? 'N/D' : g.txt; b.className = g.chico ? 'chico' : '';
      el.querySelector('.g-err').textContent = g.pct == null ? (g.err || '') : '';
    });
  }

  // ---------- Estado de equipos ----------
  function estadoHost(h) {
    const ts = datos.tarjetas.filter(t => t.host === h);
    const t = ts.find(x => x.label === 'Ping' || x.label === 'Agente') || ts[0];
    if (!t) return {cls: 'na', txt: 'Sin datos'};
    if (t.color === 'ok') return {cls: 'ok', txt: 'Operativo'};
    if (t.color === 'bad') return {cls: 'bad', txt: 'Caído'};
    if (t.color === 'warn') return {cls: 'warn', txt: 'Advertencia'};
    return {cls: 'na', txt: 'Sin datos'};
  }
  function hostsConocidos() {
    const hs = [];
    datos.tarjetas.forEach(t => { if (!hs.includes(t.host)) hs.push(t.host); });
    return hs;
  }

  // ---------- Pintar ----------
  function pintarKpis() {
    const crit = datos.alertas.filter(a => a.nivel === 'crit').length;
    const warn = datos.alertas.length - crit;
    const est = crit ? {t: 'Crítico', c: 'bad'} : warn ? {t: 'Con advertencias', c: 'warn'} : {t: 'Operativo', c: 'ok'};
    $('k-estado').textContent = est.t; $('kpi-estado').className = 'kpi ' + est.c;
    const hs = hostsConocidos(), online = hs.filter(h => estadoHost(h).cls === 'ok').length;
    animarNumero($('k-eq'), online); $('k-eq-s').textContent = 'de ' + hs.length;
    $('kpi-eq').className = 'kpi ' + (!hs.length ? '' : online === hs.length ? 'ok' : online === 0 ? 'bad' : 'warn');
    let up = 0, tot = 0;
    datos.dispositivos.forEach(d => { if (d.con_puertos) { tot += d.puertos.length; up += d.puertos.filter(p => p.estado === 'up').length; } });
    animarNumero($('k-pt'), up); $('k-pt-s').textContent = 'de ' + tot;
    animarNumero($('k-pd'), tot - up);
    animarNumero($('k-al'), datos.alertas.length);
    $('k-al-s').textContent = crit ? crit + ' crítica' + (crit > 1 ? 's' : '') : warn ? warn + ' aviso' + (warn > 1 ? 's' : '') : 'todo en orden';
    $('kpi-alertas').className = 'kpi ' + (crit ? 'bad alarma' : warn ? 'warn' : 'ok');
    animarNumero($('k-ev'), datos.eventos.length);
  }

  const U_POR_TIPO = {FW: 2, SW: 2, SRV: 2, AP: 1};
  function pintarLateral() {
    let u = 24;
    const ocupado = datos.dispositivos.reduce((n, d) => n + (d.u || U_POR_TIPO[d.badge] || 2), 0);
    const total = Math.max(24, ocupado);
    u = total;
    const slots = datos.dispositivos.map(d => {
      const h = d.u || U_POR_TIPO[d.badge] || 2;
      const top = u; u -= h;
      const up = d.puertos.filter(p => p.estado === 'up').length;
      const hayAlerta = datos.alertas.some(a => a.host === d.host);
      const leds = d.con_puertos
        ? '<div class="leds">' + d.puertos.map(p =>
            '<span class="led ' + p.estado + (p.fibra ? ' sfp' : '') + '" data-n="' + esc(p.nombre) +
            '" data-e="' + p.estado + '" data-rx="' + (p.rx === null ? 'N/D' : p.rx) + '" data-tx="' + (p.tx === null ? 'N/D' : p.tx) +
            '"><i></i><b>' + esc(p.label) + '</b></span>').join('') + '</div>'
        : '<div class="solo">Solo monitoreo ICMP</div>';
      return '<div class="slot ' + (d.id === sel ? 'sel ' : '') + (hayAlerta ? 'alerta' : '') + '" data-id="' + esc(d.id) + '">' +
        '<div class="num">U' + top + '</div>' +
        '<div class="eq" style="--u:' + h + '"><div class="r1"><span class="u">' + esc(d.badge || 'EQ') + '</span><b>' + esc(d.titulo) + '</b>' +
        '<em>' + (d.con_puertos ? up + '/' + d.puertos.length + ' UP' : esc(d.host)) + '</em></div>' + leds + '</div></div>';
    }).join('');
    const libre = total - ocupado;
    $('bast-t').textContent = 'Bastidor ' + total + 'U · vista frontal';
    $('bast-s').textContent = ocupado + 'U en uso';
    $('lateral').innerHTML = slots + (libre > 0
      ? '<div class="libre">U' + libre + '&ndash;U1 &middot; espacio libre</div>' : '');
  }
  $('lateral').addEventListener('click', ev => {
    const el = ev.target.closest('.slot'); if (!el) return;
    sel = el.dataset.id; pintar();
  });
  const INFO_VACIA = 'Pasa el mouse sobre un puerto del bastidor para ver su nombre.';
  const ESTADO_TXT = {up: 'UP', down: 'DOWN', otro: 'OTRO', na: 'SIN DATOS'};
  $('lateral').addEventListener('mouseover', ev => {
    const l = ev.target.closest('.led');
    if (!l) return;
    $('pinfo').innerHTML = '<b>' + esc(l.dataset.n) + '</b> &middot; <span class="' + l.dataset.e + '">' + ESTADO_TXT[l.dataset.e] +
      '</span><br>Entrada: ' + esc(l.dataset.rx) + (l.dataset.rx === 'N/D' ? '' : ' Mbps') +
      ' &middot; Salida: ' + esc(l.dataset.tx) + (l.dataset.tx === 'N/D' ? '' : ' Mbps');
  });
  $('lateral').addEventListener('mouseleave', () => { $('pinfo').textContent = INFO_VACIA; });

  function pintarCentro() {
    const d = datos.dispositivos.find(x => x.id === sel);
    if (!d) return;
    $('dev-nombre').textContent = d.titulo + ' (' + d.host + ')';
    $('dev-sub').textContent = d.subtitulo;
    const e = estadoHost(d.host);
    $('dev-estado').className = 'pill ' + e.cls;
    $('dev-estado').querySelector('span').textContent = e.txt;
    $('panel-titulo').textContent = d.panel || '';
    $('panel-puertos').style.display = d.con_puertos ? '' : 'none';
    ['traf', 'lat', 'cpu'].forEach(m => { $('gb-' + m).style.display = d.graficas.includes(m) ? '' : 'none'; });
    // si la última gráfica de una fila queda sola, ocupa todo el ancho
    const resto = ['lat', 'cpu'].filter(m => d.graficas.includes(m));
    ['lat', 'cpu'].forEach(m => { $('gb-' + m).style.gridColumn = ''; });
    if (resto.length % 2 === 1) $('gb-' + resto[resto.length - 1]).style.gridColumn = '1 / -1';

    const up = d.puertos.filter(p => p.estado === 'up').length;
    $('activos').textContent = up + '/' + d.puertos.length + ' enlaces activos';
    pintarPanal(d);
    $('aviso').textContent = d.puertos.length === 0
      ? 'Sin datos de puertos para ' + d.host + '. Revisa el descubrimiento de interfaces en Zabbix o el filtro de puertos.' : '';
  }

  function pintarServicios() {
    $('servicios').innerHTML = hostsConocidos().map(h => {
      const e = estadoHost(h), d = datos.dispositivos.find(x => x.host === h);
      const ic = e.cls === 'ok' ? '<path d="M5 12.5l4.5 4.5L19 7.5"/>' : e.cls === 'na' ? '<path d="M9.5 9a2.5 2.5 0 1 1 3.5 2.3c-.7.4-1 .9-1 1.7M12 17h.01"/>' : '<path d="M12 7v6M12 17h.01"/>';
      return '<div class="rt ' + e.cls + (d && d.id === sel ? ' sel' : '') + '"' + (d ? ' data-id="' + esc(d.id) + '"' : '') + '><svg viewBox="0 0 24 24">' + ic + '</svg><b>' + esc(h) + '</b><em>' + e.txt + '</em></div>';
    }).join('');
  }
  $('servicios').addEventListener('click', ev => {
    const t = ev.target.closest('.rt'); if (!t || !t.dataset.id) return;
    sel = t.dataset.id; pintar();
  });

  function pintarEventos() {
    const q = busqueda.trim().toLowerCase();
    const lista = datos.eventos.filter(e =>
      (filtroNivel === 'todos' || e.nivel === filtroNivel) &&
      (!q || (e.host + ' ' + e.msg + ' ' + (e.tipo || '')).toLowerCase().includes(q)));
    $('eventos').innerHTML = !datos.eventos.length
      ? '<div class="vacio">Aún no hay eventos. Se registrarán los cambios de estado de puertos, ping y umbrales.</div>'
      : !lista.length ? '<div class="vacio">Ningún evento coincide con el filtro.</div>'
      : lista.map(e => {
          const nuevo = !primeraCarga && !vistos.has(e.id) ? ' nuevo' : '';
          return '<div class="ev ' + e.nivel + nuevo + '"><span class="pt"></span><div class="tx">' +
            '<div class="m">' + esc(e.msg) + '</div>' +
            '<div class="h">' + esc(e.host) + (e.tipo ? '<span class="tag">' + esc(e.tipo) + '</span>' : '') + '</div></div>' +
            '<div class="t" title="' + esc(new Date(e.ts).toLocaleString()) + '">' + hace(e.ts) + '</div></div>';
        }).join('');
    datos.eventos.forEach(e => vistos.add(e.id));
  }

  function pintarAlertas() {
    const n = datos.alertas.length;
    const crit = datos.alertas.filter(a => a.nivel === 'crit').length;
    const b = $('nalert');
    b.textContent = n; b.className = 'badge' + (n === 0 ? ' cero' : '');
    $('alres').textContent = n === 0 ? '' : crit + ' crítica' + (crit === 1 ? '' : 's') + ' · ' + (n - crit) + ' aviso' + (n - crit === 1 ? '' : 's');
    $('alertas').innerHTML = n === 0
      ? '<div class="vacio">Sin alertas activas. Todo opera con normalidad.</div>'
      : datos.alertas.map(a =>
          '<div class="al ' + a.nivel + '" data-host="' + esc(a.host) + '" data-k="' + esc(claveAl(a)) + '" title="Ver plan de acción"><span class="ic"></span><div class="tx">' +
            '<span class="nv">' + (a.nivel === 'crit' ? 'CRÍTICA' : 'AVISO') + '</span>' +
            '<span class="hs">' + esc(a.host) + (a.tipo ? '<span class="tag">' + esc(a.tipo) + '</span>' : '') + '</span>' +
            '<div class="ms">' + esc(a.msg) + '</div></div></div>').join('');
    $('zerr').textContent = datos.zabbix_error ? 'Zabbix: ' + datos.zabbix_error : '';
    pintarEventos();
  }
  $('alertas').addEventListener('click', ev => {
    const el = ev.target.closest('.al'); if (!el || !datos) return;
    const k = el.dataset.k;
    if (k) { abiertos.add(k); sigPA = ''; }
    const d = datos.dispositivos.find(x => x.host === el.dataset.host);
    if (d) { sel = d.id; pintar(); } else pintarPlan();
    if (k && $('plan')) {
      const t = $('plan').querySelector('details[data-k="' + CSS.escape(k) + '"]');
      if (t) t.scrollIntoView({behavior: reducir ? 'auto' : 'smooth', block: 'nearest'});
    }
  });


  // ---------- Plan de acción ----------
  let guias = null, sigPA = '', primeraPA = true;
  const abiertos = new Set();
  let hechos = {};
  try { hechos = JSON.parse(localStorage.getItem('pa-hechos') || '{}'); } catch (e) { hechos = {}; }
  const guardarHechos = () => { try { localStorage.setItem('pa-hechos', JSON.stringify(hechos)); } catch (e) {} };
  const claveAl = a => a.host + '|' + a.msg;
  const lis = arr => '<ul>' + (arr || []).map(x => '<li>' + esc(x) + '</li>').join('') + '</ul>';

  function textoPA(a, g, P) {
    const nl = String.fromCharCode(10);
    const l = ['[' + P.codigo + '] ' + a.host + ' — ' + a.msg, g.nombre, '', 'Posible afectación:'];
    g.afectacion.forEach(x => l.push('- ' + x));
    l.push('', 'Plan de acción:', 'Ahora: ' + g.plan.ahora.join(' '), 'Hoy: ' + g.plan.hoy.join(' '),
           'Prevención: ' + g.plan.prevenir.join(' '), '', 'Escalar: ' + g.escalar);
    return l.join(nl);
  }

  function tarjetaPA(a) {
    const g = guias.guias[a.pb] || guias.guias.generico;
    const P = guias.prioridades[a.prio || 3];
    const eq = guias.equipos[a.host] || {};
    const k = claveAl(a), hec = hechos[k] || [];
    const otras = datos.alertas.filter(x => x.host === a.host && claveAl(x) !== k).length;
    const rol = guias.roles[eq.badge] || '';
    const tip = g.por_equipo && g.por_equipo[eq.badge] ? g.por_equipo[eq.badge] : '';
    const pasos = g.solucion.map((s, i) =>
      '<li><label><input type="checkbox" data-k="' + esc(k) + '" data-i="' + i + '"' + (hec.includes(i) ? ' checked' : '') +
      '><span>' + esc(s) + '</span></label></li>').join('');
    return '<details class="pa p' + (a.prio || 3) + '" data-k="' + esc(k) + '"' + (abiertos.has(k) ? ' open' : '') + '>' +
      '<summary><span class="pa-p" title="' + esc(P.nombre + ' · ' + P.tiempo) + '">' + P.codigo + '</span>' +
      '<div class="pa-t"><b>' + esc(g.nombre) + ' · ' + esc(a.host) + '</b><span>' + esc(a.msg) + '</span></div>' +
      '<span class="pa-prog">' + hec.length + '/' + g.solucion.length + ' pasos</span></summary>' +
      '<div class="pa-cuerpo"><div class="pa-grid">' +
        '<div><h3>Posible afectación</h3>' + lis(g.afectacion) +
          (rol ? '<div class="pa-tip">' + esc(rol) + '</div>' : '') +
          (otras ? '<div class="pa-rel">Este equipo tiene ' + otras + ' alerta' + (otras === 1 ? '' : 's') + ' más abierta' + (otras === 1 ? '' : 's') + ': revísalas juntas, pueden compartir causa.</div>' : '') +
          '<h3 style="margin-top:14px">Causas probables</h3>' + lis(g.causas) + '</div>' +
        '<div><h3>Solución paso a paso <small style="color:var(--muted);font-weight:400">· marca lo que ya hiciste</small></h3><ol class="pasos">' + pasos + '</ol>' +
          (tip ? '<div class="pa-tip">En este equipo: ' + esc(tip) + '</div>' : '') + '</div>' +
      '</div>' +
      '<div class="pa-plan">' +
        '<div><h3>Ahora <small>· ' + esc(P.tiempo.replace('Atender en ', '')) + '</small></h3>' + lis(g.plan.ahora) + '</div>' +
        '<div><h3>Hoy <small>· corto plazo</small></h3>' + lis(g.plan.hoy) + '</div>' +
        '<div><h3>Prevención <small>· evitar que se repita</small></h3>' + lis(g.plan.prevenir) + '</div>' +
      '</div>' +
      '<div class="pa-pie"><div><p><b>Escalar:</b> ' + esc(g.escalar) + '</p><p><b>Resuelta cuando:</b> ' + esc(g.resuelto) + '</p></div>' +
        '<button type="button" class="pa-copiar" data-k="' + esc(k) + '">Copiar resumen</button></div>' +
      '</div></details>';
  }

  function pintarPlan() {
    if (!datos || !guias) return;
    const vist = new Set(), lista = [];
    datos.alertas.forEach(a => { const k = claveAl(a); if (!vist.has(k)) { vist.add(k); lista.push(a); } });
    lista.sort((x, y) => (x.prio || 3) - (y.prio || 3));
    // olvidar lo marcado de alertas que ya se resolvieron
    let cambio = false;
    Object.keys(hechos).forEach(k => { if (!vist.has(k)) { delete hechos[k]; cambio = true; } });
    if (cambio) guardarHechos();
    const n = lista.length, b = $('npa');
    b.textContent = n; b.className = 'badge' + (n === 0 ? ' cero' : '');
    const sig = lista.map(a => claveAl(a) + '#' + (a.prio || 3)).join('|');
    if (sig === sigPA) return;
    sigPA = sig;
    if (primeraPA && lista.length && lista[0].prio === 1) abiertos.add(claveAl(lista[0]));
    primeraPA = false;
    $('plan').innerHTML = n === 0
      ? '<div class="vacio">Sin alertas abiertas: no hay acciones pendientes. Aprovecha para revisar los planes de prevención de cada guía.</div>'
      : lista.map(tarjetaPA).join('');
  }

  $('plan').addEventListener('toggle', ev => {
    const d = ev.target; if (!d.dataset || !d.dataset.k) return;
    d.open ? abiertos.add(d.dataset.k) : abiertos.delete(d.dataset.k);
  }, true);
  $('plan').addEventListener('change', ev => {
    const c = ev.target; if (c.type !== 'checkbox') return;
    const k = c.dataset.k, i = Number(c.dataset.i), arr = hechos[k] || [];
    hechos[k] = c.checked ? arr.concat(i) : arr.filter(x => x !== i);
    if (!hechos[k].length) delete hechos[k];
    guardarHechos();
    const det = c.closest('details'), tot = det.querySelectorAll('input[type=checkbox]').length;
    det.querySelector('.pa-prog').textContent = (hechos[k] || []).length + '/' + tot + ' pasos';
  });
  $('plan').addEventListener('click', async ev => {
    const bt = ev.target.closest('.pa-copiar'); if (!bt || !datos || !guias) return;
    const a = datos.alertas.find(x => claveAl(x) === bt.dataset.k); if (!a) return;
    const g = guias.guias[a.pb] || guias.guias.generico, P = guias.prioridades[a.prio || 3];
    try { await navigator.clipboard.writeText(textoPA(a, g, P)); bt.textContent = 'Copiado'; }
    catch (e) { bt.textContent = 'No se pudo copiar'; }
    setTimeout(() => { bt.textContent = 'Copiar resumen'; }, 1800);
  });
  async function cargarGuias() {
    try {
      const r = await fetch('/api/playbooks');
      if (r.ok) { guias = await r.json(); pintarPlan(); }
      else $('plan').innerHTML = '<div class="vacio">No se pudieron cargar las guías.</div>';
    } catch (e) { $('plan').innerHTML = '<div class="vacio">No se pudieron cargar las guías.</div>'; }
  }

  // ---------- Colores de estado ----------
  const RANGO = {ok: 0, na: 1, warn: 2, bad: 3};
  const peor = (a, b) => RANGO[a] >= RANGO[b] ? a : b;
  const ESTADO_PUERTO = {up: 'ok', down: 'bad', otro: 'warn', na: 'na'};

  // ---------- Topología de red ----------
  const GLIFO = {
    FW: '<path d="M0 -13l11 4v8c0 7-5 12-11 15-6-3-11-8-11-15v-8z"/><path d="M-4.5 1l3.5 3.5 6.5-7.5"/>',
    SW: '<rect x="-15" y="-9" width="30" height="18" rx="3"/><path d="M-9 -2v4M-3 -2v4M3 -2v4M9 -2v4"/>',
    AP: '<path d="M-12 -4a17 17 0 0 1 24 0"/><path d="M-7 1a10 10 0 0 1 14 0"/><circle cx="0" cy="8" r="1.8"/>',
    SRV: '<rect x="-12" y="-13" width="24" height="9" rx="2"/><rect x="-12" y="-1" width="24" height="9" rx="2"/><path d="M-7 -8.5h.01M-7 3.5h.01"/><path d="M-12 13h24"/>'
  };
  const NUBE = 'M-24 14a12 12 0 0 1-1-24 17 17 0 0 1 32-5 14 14 0 0 1 17 29z';
  const corto = t => String(t).length > 15 ? String(t).slice(0, 14) + '…' : String(t);
  function nodoEquipo(n) {
    const d = n.d, e = estadoHost(d.host).cls;
    const cpu = datos.tarjetas.find(t => t.host === d.host && t.label === 'CPU');
    const tip = d.titulo + ' · ' + d.host + ' · ' + estadoHost(d.host).txt + (cpu ? ' · CPU ' + cpu.texto : '');
    return '<g class="tn' + (d.id === sel ? ' sel' : '') + '" data-id="' + esc(d.id) + '" transform="translate(' + n.x + ',' + n.y + ')"><title>' + esc(tip) + '</title>' +
      '<rect class="halo" x="-38" y="-38" width="76" height="76" rx="22"/>' +
      '<rect class="caja ' + e + '" x="-30" y="-30" width="60" height="60" rx="16"/>' +
      '<g class="gl">' + (GLIFO[d.badge] || GLIFO.SRV) + '</g>' +
      '<rect class="est ' + e + '" x="19" y="-36" width="15" height="15" rx="4"/>' +
      '<text y="58">' + esc(corto(d.titulo)) + '</text><text class="sub" y="76">' + esc(corto(d.host)) + '</text></g>';
  }
  function nodoIsp(n) {
    return '<g class="tn" transform="translate(' + n.x + ',' + n.y + ')"><title>' + esc(n.label) + '</title>' +
      '<path class="nube ' + n.est + '" d="' + NUBE + '"/><rect class="est ' + n.est + '" x="22" y="-30" width="15" height="15" rx="4"/>' +
      '<text y="44">' + esc(corto(n.label)) + '</text></g>';
  }
  function pintarTopologia() {
    const ds = datos.dispositivos, el = $('topo');
    if (!ds.length) { el.innerHTML = '<div class="vacio">Sin equipos configurados.</div>'; return; }
    const W = 860, Y0 = 60, DY = 140;
    const fws = ds.filter(d => d.badge === 'FW'), sws = ds.filter(d => d.badge === 'SW');
    const resto = ds.filter(d => d.badge !== 'FW' && d.badge !== 'SW');
    const capas = [];
    if (fws.length) {
      const isps = [];
      fws.forEach(f => (f.puertos || []).forEach(p => {
        if (/wan|isp|internet/i.test((p.alias || '') + ' ' + (p.base || '') + ' ' + (p.nombre || ''))) isps.push({kind: 'isp', fw: f, label: p.alias || p.base || 'WAN', est: ESTADO_PUERTO[p.estado] || 'na'});
      }));
      capas.push(isps.length ? isps : [{kind: 'isp', fw: null, label: 'Internet', est: 'na'}]);
    }
    [fws, sws, resto].forEach(t => { if (t.length) capas.push(t.map(d => ({kind: 'eq', d: d}))); });
    capas.forEach((c, i) => c.forEach((n, j) => { n.x = Math.round(W * (j + 1) / (c.length + 1)); n.y = Y0 + DY * i; }));
    const estN = n => n.kind === 'isp' ? n.est : estadoHost(n.d.host).cls;
    let aristas = '';
    for (let i = 0; i < capas.length - 1; i++) {
      capas[i].forEach(a => capas[i + 1].forEach(b => {
        if (a.kind === 'isp' && a.fw && a.fw !== b.d) return;
        let est = peor(estN(a), estN(b));
        if (a.kind === 'isp' && a.est === 'na') est = estN(b);
        const y1 = a.y + 32, y2 = b.y - 34, ym = (y1 + y2) / 2;
        aristas += '<path class="arista ' + est + '" d="M' + a.x + ' ' + y1 + 'C' + a.x + ' ' + ym + ' ' + b.x + ' ' + ym + ' ' + b.x + ' ' + y2 + '"/>';
      }));
    }
    const nodos = capas.map(c => c.map(n => n.kind === 'isp' ? nodoIsp(n) : nodoEquipo(n)).join('')).join('');
    const H = Y0 + DY * (capas.length - 1) + 90;
    el.innerHTML = '<svg viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="Topología de red">' + aristas + nodos + '</svg>' +
      '<div class="topo-ley"><span><i class="ok"></i>Operativo</span><span><i class="warn"></i>Advertencia</span><span><i class="bad"></i>Caído</span><span><i class="na"></i>Sin datos</span><span>Haz clic en un equipo para ver su detalle</span></div>';
  }
  $('topo').addEventListener('click', ev => {
    const t = ev.target.closest('.tn'); if (!t || !t.dataset.id) return;
    sel = t.dataset.id; pintar();
  });

  // ---------- Resúmenes ----------
  function pintarResumen() {
    const hs = hostsConocidos(), c = {ok: 0, bad: 0, warn: 0, na: 0};
    hs.forEach(h => { c[estadoHost(h).cls]++; });
    $('res-nodos').innerHTML = [['ok', 'Disponibles'], ['bad', 'No disponibles'], ['warn', 'Con advertencia'], ['na', 'Sin datos']]
      .map(x => '<div class="rn ' + x[0] + '"><b>' + c[x[0]] + '</b><span>' + x[1] + '</span></div>').join('') +
      '<div class="rn total"><b>' + hs.length + '</b><span>Total</span></div>';
    const crit = datos.alertas.filter(a => a.nivel === 'crit').length, av = datos.alertas.length - crit;
    const rec = datos.eventos.filter(e => e.nivel === 'ok').length, tot = Math.max(1, crit + av + rec);
    $('res-sev').innerHTML = [['bad', crit, 'Críticas'], ['warn', av, 'Avisos'], ['ok', rec, 'Recuperadas']]
      .map(x => '<div class="sv ' + x[0] + '" style="--w:' + Math.max(58, Math.round(x[1] * 100 / tot)) + '%"><b>' + x[1] + '</b><span>' + x[2] + '</span></div>').join('');
  }

  // ---------- Top de recursos ----------
  function segBar(p) {
    const n = 12, on = p == null ? 0 : Math.round(Math.max(0, Math.min(100, p)) / 100 * n);
    let h = '';
    for (let i = 0; i < n; i++) h += '<i class="' + (i < on ? (i < 7 ? 'g' : i < 10 ? 'a' : 'r') : '') + '"></i>';
    return '<span class="seg">' + h + '</span>';
  }
  function pintarTop() {
    const num = t => { if (!t) return null; const v = parseFloat(t.texto); return isNaN(v) ? null : v; };
    const txt = v => v == null ? 'N/D' : v.toFixed(1) + ' %';
    const filas = hostsConocidos().map(h => ({
      h: h, c: num(datos.tarjetas.find(t => t.host === h && t.label === 'CPU')), m: num(datos.tarjetas.find(t => t.host === h && t.label === 'Memoria'))
    })).filter(f => f.c != null || f.m != null);
    filas.sort((a, b) => (b.c == null ? -1 : b.c) - (a.c == null ? -1 : a.c));
    $('top-rec').innerHTML = !filas.length ? '<div class="vacio">Sin datos de CPU ni memoria.</div>' :
      '<div class="tr h"><span>Equipo</span><span>CPU</span><span>Memoria</span></div>' + filas.map(f =>
        '<div class="tr"><span class="nm" title="' + esc(f.h) + '">' + esc(f.h) + '</span>' +
        '<span class="v">' + segBar(f.c) + txt(f.c) + '</span><span class="v">' + segBar(f.m) + txt(f.m) + '</span></div>').join('');
  }

  // ---------- Panal de puertos ----------
  const HEX_W = 78, HEX_G = 4;
  let panalDe = null;
  function hexPuerto(p) {
    const sfp = p.fibra ? ' sfp' : '';
    const tip = p.nombre + (p.fibra ? ' (fibra)' : '') + ' | Entrada: ' + (p.rx === null ? 'N/D' : p.rx + ' Mbps') + ' | Salida: ' + (p.tx === null ? 'N/D' : p.tx + ' Mbps');
    return '<div class="hexw" title="' + esc(tip) + '"><div class="hex ' + p.estado + sfp + '"><b>' + esc(p.label) + '</b><span>' + esc(p.alias || p.base || '') + '</span></div></div>';
  }
  function pintarPanal(d) {
    panalDe = d.id;
    const cont = $('puertos'), n = d.puertos.length;
    if (!n) { cont.innerHTML = ''; return; }
    const paso = HEX_W + HEX_G, ancho = cont.clientWidth || 640;
    const cols = Math.max(1, Math.min(n, Math.floor((ancho - paso / 2) / paso)));
    const filas = [];
    for (let i = 0; i < n; i += cols) filas.push(d.puertos.slice(i, i + cols));
    const total = cols * paso + (filas.length > 1 ? paso / 2 : 0);
    const izq = Math.max(0, Math.floor((ancho - total) / 2));
    cont.innerHTML = filas.map((f, r) => '<div class="hx-fila" style="margin-left:' + (izq + (r % 2 ? paso / 2 : 0)) + 'px">' + f.map(hexPuerto).join('') + '</div>').join('');
  }
  let tRedim = null;
  window.addEventListener('resize', () => {
    clearTimeout(tRedim);
    tRedim = setTimeout(() => {
      if (!datos || !panalDe) return;
      const d = datos.dispositivos.find(x => x.id === panalDe);
      if (d && d.con_puertos) pintarPanal(d);
    }, 150);
  });

  function pintar() {
    pintarKpis(); pintarLateral(); pintarTopologia(); pintarResumen(); pintarCentro(); pintarGauges(false);
    pintarAlertas(); pintarPlan(); pintarServicios(); pintarTop(); dibujarGraficas();
  }

  async function cargar() {
    try {
      const r = await fetch('/api/data');
      if (r.status === 401) { location.href = '/login'; return; }
      datos = await r.json();
      if (!sel || !datos.dispositivos.some(x => x.id === sel)) {
        sel = datos.dispositivos.length ? datos.dispositivos[0].id : null;
      }
      pintar();
      primeraCarga = false;
      $('hora').textContent = new Date().toLocaleTimeString();
    } catch (e) {
      $('hora').textContent = 'error: ' + e.message;
    }
  }

  $('buscar').addEventListener('input', ev => { busqueda = ev.target.value; if (datos) pintarEventos(); });
  $('chips').addEventListener('click', ev => {
    const b = ev.target.closest('button'); if (!b) return;
    filtroNivel = b.dataset.f;
    document.querySelectorAll('#chips button').forEach(x => x.classList.toggle('on', x === b));
    if (datos) pintarEventos();
  });

  if (!PERMISOS.includes('exportar')) $('exportar').style.display = 'none';
  $('exportar').addEventListener('click', () => {
    if (!datos) return;
    const blob = new Blob([JSON.stringify(datos.eventos, null, 2)], {type: 'application/json'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'eventos-noc.json';
    a.click();
    URL.revokeObjectURL(a.href);
  });

  cargarGuias();
  cargar();
  setInterval(cargar, 15000);
</script>
</body>
</html>
"""


@app.route("/")
@requiere("ver")
def index():
    u = g.usuario
    enlace_admin = '<a href="/admin">Administración</a>' if "usuarios" in u["permisos"] else ""
    pag = (PAGINA
           .replace("__INICIAL__", html.escape(((u["nombre"] or u["usuario"] or "?").strip() or "?")[:1].upper()))
           .replace("__USUARIO__", html.escape(u["nombre"] or u["usuario"]))
           .replace("__ROL__", html.escape(u["rol"]))
           .replace("__LINK_ADMIN__", enlace_admin)
           .replace("__CSRF__", asegurar_csrf())
           .replace("__PERMISOS__", _json.dumps(sorted(u["permisos"]))))
    return Response(pag, mimetype="text/html")


if __name__ == "__main__":
    if TELEGRAM_TOKEN and TELEGRAM_CHAT_ID:
        threading.Thread(target=ciclo_telegram, daemon=True).start()
    app.run(host="0.0.0.0", port=443, ssl_context="adhoc")
