"""
InternLink - Sistema de Gestión de Pasantías Universitarias
Plataforma para conectar estudiantes, empresas y coordinadores académicos
"""
from flask import (
    Flask, render_template, request, redirect, url_for,
    jsonify, make_response, send_file
)
from functools import wraps
import json
import hashlib
import secrets
import os
from datetime import datetime
import jwt
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from upstash_redis import Redis

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'internlink_secret_2024'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

JWT_SECRET = 'internlink2024'

# Cliente Redis Upstash con interfaz compatible con el resto de la app
_upstash = Redis.from_env()


class _Db:
    """Wrapper que adapta upstash_redis a la interfaz usada en la app."""

    def get(self, key):
        return _upstash.get(key)

    def set(self, key, value):
        return _upstash.set(key, value)

    def hgetall(self, key):
        out = _upstash.hgetall(key)
        return out if isinstance(out, dict) and out else {}

    def hset(self, key, field, value):
        return _upstash.hset(key, field, value)

    def hget(self, key, field):
        return _upstash.hget(key, field)

    def hmset(self, key, mapping):
        return _upstash.hset(key, values=mapping)

    def keys(self, pattern):
        out = _upstash.keys(pattern)
        return out if out is not None else []

    def delete(self, key):
        return _upstash.delete(key)

    def incr(self, key):
        return _upstash.incr(key)


db = _Db()

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('logs', exist_ok=True)


# ---------------------------------------------------------------------------
# Datos iniciales
# ---------------------------------------------------------------------------
def init_db():
    """Poblar la base de datos con datos de ejemplo si están vacíos."""

    # Empresas
    if not db.hgetall('company:1'):
        db.hmset('company:1', {
            'id': '1',
            'name': 'TechCorp SA',
            'email': 'empresa@techcorp.com',
            'password': hashlib.sha256('EmpresaPass123!'.encode()).hexdigest(),
            'role': 'company',
            'sector': 'Tecnología',
            'api_key': 'tc_prod_FLAG{session_hijacked}_v2',
            'contact_phone': '+57 604 555 0101',
        })
        db.hset('email_to_key', 'empresa@techcorp.com', 'company:1')

    if not db.hgetall('company:2'):
        db.hmset('company:2', {
            'id': '2',
            'name': 'DataFlow Inc',
            'email': 'rrhh@dataflow.com',
            'password': hashlib.sha256('DataFlow2024!'.encode()).hexdigest(),
            'role': 'company',
            'sector': 'Análisis de Datos',
            'api_key': 'df_prod_8a2c4e6f',
            'contact_phone': '+57 604 555 0202',
        })
        db.hset('email_to_key', 'rrhh@dataflow.com', 'company:2')

    # Coordinador
    if not db.hgetall('coordinator:1'):
        db.hmset('coordinator:1', {
            'id': '1',
            'name': 'Carlos Ramírez',
            'email': 'coordinador@internlink.com',
            'password': hashlib.sha256('CoordPass123!'.encode()).hexdigest(),
            'role': 'coordinator',
            'department': 'Pasantías y Prácticas',
        })
        db.hset('email_to_key', 'coordinador@internlink.com', 'coordinator:1')

    # Administrador
    if not db.hgetall('admin:1'):
        db.hmset('admin:1', {
            'id': '1',
            'name': 'Admin Sistema',
            'email': 'admin@internlink.com',
            'password': hashlib.sha256('AdminPass123!'.encode()).hexdigest(),
            'role': 'admin',
            'system_key': 'FLAG{internlink_compromised}',
            'admin_notes': 'Cuenta principal del sistema. Ref: FLAG{user_enumeration_is_real}',
        })
        db.hset('email_to_key', 'admin@internlink.com', 'admin:1')

    # Estudiantes de ejemplo
    if not db.hgetall('student:1'):
        db.hmset('student:1', {
            'id': '1',
            'name': 'María González',
            'email': 'maria.gonzalez@mail.com',
            'password': hashlib.sha256('Student123!'.encode()).hexdigest(),
            'role': 'student',
            'university': 'Universidad de Medellín',
            'phone': '+57 300 111 2222',
        })
        db.hset('email_to_key', 'maria.gonzalez@mail.com', 'student:1')

    if not db.hgetall('student:2'):
        db.hmset('student:2', {
            'id': '2',
            'name': 'Andrés López',
            'email': 'andres.lopez@mail.com',
            'password': hashlib.sha256('Student456!'.encode()).hexdigest(),
            'role': 'student',
            'university': 'Universidad Nacional',
            'phone': '+57 300 333 4444',
        })
        db.hset('email_to_key', 'andres.lopez@mail.com', 'student:2')

    # Sincronizar índice email_to_key con usuarios iniciales (por si ya existían sin índice)
    for email, key in [
        ('empresa@techcorp.com', 'company:1'),
        ('rrhh@dataflow.com', 'company:2'),
        ('coordinador@internlink.com', 'coordinator:1'),
        ('admin@internlink.com', 'admin:1'),
        ('maria.gonzalez@mail.com', 'student:1'),
        ('andres.lopez@mail.com', 'student:2'),
    ]:
        db.hset('email_to_key', email, key)

    # Asignaciones de pasantía (intern records)
    if not db.hgetall('intern:1'):
        db.hmset('intern:1', {
            'id': '1',
            'student_id': '1',
            'student_name': 'María González',
            'student_email': 'maria.gonzalez@mail.com',
            'company_id': '1',
            'company_name': 'TechCorp SA',
            'position': 'Desarrolladora Backend',
            'salary': '1500000',
            'status': 'active',
            'start_date': '2026-01-15',
            'evaluation': 'Buen rendimiento general.',
            'cv_path': '',
        })

    if not db.hgetall('intern:2'):
        db.hmset('intern:2', {
            'id': '2',
            'student_id': '2',
            'student_name': 'Andrés López',
            'student_email': 'andres.lopez@mail.com',
            'company_id': '2',
            'company_name': 'DataFlow Inc',
            'position': 'Analista de Datos',
            'salary': '1800000',
            'status': 'active',
            'start_date': '2026-02-01',
            'evaluation': 'Evaluación confidencial — Calificación: 9.5/10. Código de auditoría: FLAG{idor_horizontal}',
            'cv_path': '',
        })

    if not db.hgetall('intern:3'):
        db.hmset('intern:3', {
            'id': '3',
            'student_id': '3',
            'student_name': 'Laura Martínez',
            'student_email': 'laura.martinez@mail.com',
            'company_id': '1',
            'company_name': 'TechCorp SA',
            'position': 'Diseñadora UX/UI',
            'salary': '1600000',
            'status': 'pending',
            'start_date': '2026-02-10',
            'evaluation': 'Pendiente de evaluación.',
            'cv_path': '',
        })

    if not db.hgetall('intern:4'):
        db.hmset('intern:4', {
            'id': '4',
            'student_id': '4',
            'student_name': 'Carlos Rodríguez',
            'student_email': 'carlos.rodriguez@mail.com',
            'company_id': '2',
            'company_name': 'DataFlow Inc',
            'position': 'Ingeniero de Datos Junior',
            'salary': '1700000',
            'status': 'active',
            'start_date': '2026-01-20',
            'evaluation': 'Buen desempeño en el primer mes.',
            'cv_path': '',
        })

    # Ofertas de pasantía
    if not db.hgetall('offer:1'):
        db.hmset('offer:1', {
            'id': '1',
            'company_id': '1',
            'company_name': 'TechCorp SA',
            'title': 'Desarrollador Backend Junior',
            'description': 'Desarrollo de APIs REST con Python y Flask. Se requiere conocimiento de bases de datos.',
            'salary': '1500000',
            'status': 'active',
            'created_at': '2026-01-20',
        })

    if not db.hgetall('offer:2'):
        db.hmset('offer:2', {
            'id': '2',
            'company_id': '2',
            'company_name': 'DataFlow Inc',
            'title': 'Analista de Datos',
            'description': 'Análisis y visualización de datos empresariales. Excel y Python requeridos.',
            'salary': '1800000',
            'status': 'active',
            'created_at': '2026-01-25',
        })

    if not db.hgetall('offer:3'):
        db.hmset('offer:3', {
            'id': '3',
            'company_id': '1',
            'company_name': 'TechCorp SA',
            'title': 'Diseñador UX/UI',
            'description': 'Diseño de interfaces y experiencia de usuario para aplicaciones web.',
            'salary': '1600000',
            'status': 'pending',
            'created_at': '2026-02-01',
        })

    # Avisos del sistema (visibles para coordinadores)
    if not db.hgetall('notice:1'):
        db.hmset('notice:1', {
            'id': '1',
            'title': 'Actualización del módulo de exportación',
            'message': 'Los reportes de candidatos ahora incluyen información de evaluación y salarios.',
            'date': '2026-02-05',
            'type': 'info',
        })

    if not db.hgetall('notice:2'):
        db.hmset('notice:2', {
            'id': '2',
            'title': 'Mantenimiento programado',
            'message': 'El sistema estará en mantenimiento el sábado 22 de febrero de 2:00 AM a 6:00 AM.',
            'date': '2026-02-10',
            'type': 'warning',
        })

    if not db.hgetall('notice:3'):
        db.hmset('notice:3', {
            'id': '3',
            'title': 'Auditoría de seguridad',
            'message': 'Se detectaron cambios no autorizados en perfiles de usuario. Token de auditoría: FLAG{mass_assignment_abuse}',
            'date': '2026-01-28',
            'type': 'security',
        })

    # Configuración del sistema
    if not db.hgetall('system:config'):
        db.hmset('system:config', {
            'version': '2.1.0',
            'jwt_secret': 'internlink2024',
            'admin_verification': 'FLAG{jwt_forged_successfully}',
            'maintenance_mode': 'false',
            'max_upload_size': '16MB',
            'master_key': 'FLAG{internlink_compromised}',
        })


# ---------------------------------------------------------------------------
# Autenticación
# ---------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        session_token = request.cookies.get('session_token')
        if not session_token:
            return redirect(url_for('login'))
        user_data = db.get(f'session:{session_token}')
        if not user_data:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def get_current_user():
    session_token = request.cookies.get('session_token')
    if not session_token:
        return None
    user_json = db.get(f'session:{session_token}')
    if not user_json:
        return None
    return json.loads(user_json)


def get_admin_user():
    """Verificar acceso de administrador vía JWT o sesión."""
    # JWT vía cookie admin_token
    token = request.cookies.get('admin_token')
    if not token:
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]

    if token:
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            if decoded.get('role') == 'admin':
                return decoded
        except jwt.InvalidTokenError:
            pass
        # Fallback: intentar sin verificación de firma
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            if decoded.get('role') == 'admin':
                return decoded
        except Exception:
            pass

    # Sesión convencional
    user = get_current_user()
    if user and user.get('role') == 'admin':
        return user
    return None


def _normalize_email(email):
    """Misma normalización en registro y login para que el índice coincida."""
    if not email or not isinstance(email, str):
        return ''
    return email.strip().lower()


def check_email_exists(email):
    """Verifica si un email existe usando el índice email_to_key (optimizado)."""
    email = _normalize_email(email)
    if not email:
        return False
    key = db.hget('email_to_key', email)
    return key is not None and key != ''


def find_user_by_email(email):
    """Buscar un usuario por email usando el índice email_to_key (optimizado)."""
    email = _normalize_email(email)
    if not email:
        return None, None
    key = db.hget('email_to_key', email)
    if not key:
        # Fallback: índice puede tener el email con otra capitalización (usuarios ya registrados)
        index = db.hgetall('email_to_key') or {}
        for stored_email, stored_key in index.items():
            if _normalize_email(stored_email) == email:
                key = stored_key
                break
    if not key:
        return None, None
    key = str(key).strip()
    data = db.hgetall(key)
    if not data:
        return None, None
    data['user_key'] = key
    return data, key


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def log_entry(message):
    log_path = 'logs/debug.log'
    ts = datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')
    with open(log_path, 'a') as f:
        f.write(f"{ts} INFO: {message}\n")


def create_debug_log():
    os.makedirs('logs', exist_ok=True)
    log_path = 'logs/debug.log'
    content = (
        "[2026-01-10 08:15:32] INFO: Servidor iniciado en puerto 5000\n"
        "[2026-01-10 08:15:33] DEBUG: Conexión a Redis establecida\n"
        "[2026-01-10 08:16:01] INFO: Login de usuario: admin@internlink.com (role: admin)\n"
        "[2026-01-10 08:17:45] WARNING: Intento de login fallido para admin@internlink.com\n"
        "[2026-01-10 08:18:02] DEBUG: Cargando configuración JWT...\n"
        "[2026-01-10 08:18:02] DEBUG: JWT_SECRET = internlink2024\n"
        "[2026-01-10 08:18:03] INFO: Módulo JWT inicializado\n"
        "[2026-01-10 08:20:15] ERROR: Excepción no controlada en /api/company/candidates\n"
        "    Traceback (most recent call last):\n"
        "      File \"app.py\", line 342, in get_candidates\n"
        "        validate_company_ownership(user_id, company_id)\n"
        "    AttributeError: module has no attribute 'validate_company_ownership'\n"
        "[2026-01-10 08:22:30] DEBUG: Credenciales temporales creadas: temp_admin / TempPass2026!\n"
        "[2026-01-10 08:25:00] INFO: Token de auditoría del sistema: FLAG{logs_are_sensitive}\n"
        "[2026-01-10 08:30:00] DEBUG: Admin auth configurado: JWT via cookie 'admin_token'\n"
        "[2026-01-10 08:35:00] INFO: Proceso de backup completado\n"
        "[2026-01-10 08:40:00] WARNING: Rate limiting no configurado para /api/check-email\n"
        "[2026-01-10 08:45:00] INFO: Bot de revisión de CV iniciado — sesión: rev_bot_2026\n"
    )
    with open(log_path, 'w') as f:
        f.write(content)


# ---------------------------------------------------------------------------
# Rutas públicas
# ---------------------------------------------------------------------------
@app.route('/')
def index():
    user = get_current_user()
    if user:
        role = user.get('role', 'student')
        routes = {
            'company': 'company_dashboard',
            'coordinator': 'coordinator_dashboard',
            'admin': 'admin_dashboard',
        }
        return redirect(url_for(routes.get(role, 'student_dashboard')))
    return render_template('gate.html')


def email_verification_required(f):
    """Exige haber verificado un correo (paso previo) para acceder a login o registro."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.cookies.get('email_verified') != '1':
            return redirect(url_for('index', msg='verify_first'))
        return f(*args, **kwargs)
    return decorated


@app.route('/login', methods=['GET', 'POST'])
@email_verification_required
def login():
    if request.method == 'POST':
        email = _normalize_email(request.form.get('email'))
        password = (request.form.get('password') or '').strip()

        user, user_key = find_user_by_email(email)

        if user and password:
            stored_password = str(user.get('password') or '')
            expected_hash = hashlib.sha256(password.encode()).hexdigest()
            if stored_password == expected_hash:
                session_token = secrets.token_hex(32)
                user['user_key'] = user_key
                db.set(f'session:{session_token}', json.dumps(user))

                log_entry(f"Login exitoso: {email} — Role: {user.get('role')}")

                resp = make_response(redirect(url_for('index')))
                resp.set_cookie('session_token', session_token, httponly=False)
                return resp

        return render_template('login.html', error='Correo o contraseña incorrectos', email=request.form.get('email'))

    return render_template('login.html', email=request.args.get('email', ''))


@app.route('/register', methods=['GET', 'POST'])
@email_verification_required
def register():
    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        email = _normalize_email(request.form.get('email'))
        password = (request.form.get('password') or '').strip()
        role = (request.form.get('role') or 'student').strip().lower()

        if not email or not password:
            return render_template('register.html', error='Correo y contraseña son obligatorios', email=email or request.form.get('email'))

        if check_email_exists(email):
            return render_template('register.html', error='Este correo electrónico ya está registrado')

        user_id = str(db.incr(f'counter:{role}') or 1)
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        user_data = {
            'id': user_id,
            'name': name,
            'email': email,
            'password': password_hash,
            'role': role,
            'created_at': datetime.now().isoformat(),
        }
        user_key = f'{role}:{user_id}'
        db.hmset(user_key, user_data)
        db.hset('email_to_key', email, user_key)

        log_entry(f"Nuevo registro: {email} — Role: {role}")
        return redirect(url_for('login'))

    return render_template('register.html', email=request.args.get('email', ''))


# Solo las cuentas guardadas como coordinator:* o admin:* en Redis pueden invitar (por clave, no por campo role)
def _key_can_invite(redis_key):
    """Determina por la clave Redis si el usuario puede invitar (solo coordinator y admin por tipo de cuenta)."""
    return redis_key.startswith('coordinator:') or redis_key.startswith('admin:')


def get_registered_users_with_invite_flag():
    """Lista de usuarios registrados. Mal implementado: devuelve todos con un campo que filtra quién puede invitar.
    Optimizado: usa el índice email_to_key."""
    email_to_key = db.hgetall('email_to_key') or {}
    users = []
    for email, key in email_to_key.items():
        puede_invitar = _key_can_invite(key)
        users.append({'email': email, 'puede_invitar': puede_invitar})
    return users


@app.route('/api/check-email', methods=['GET', 'POST'])
def check_email():
    if request.method == 'GET':
        # GET mal implementado: estaba pensado para devolver solo invitadores pero filtra mal y devuelve todos los registrados
        users = get_registered_users_with_invite_flag()
        return jsonify({'usuarios': users}), 200

    # POST: verificar si el correo corresponde a un invitador válido
    email = request.json.get('email') if request.is_json else None
    if not email:
        return jsonify({'error': 'Email requerido'}), 400

    user, user_key = find_user_by_email(email)

    if not user:
        return jsonify({
            'valid_inviter': False,
            'message': 'Este correo no está registrado en el sistema.',
        }), 200

    if not _key_can_invite(user_key):
        return jsonify({
            'valid_inviter': False,
            'message': 'Este usuario no tiene permiso para invitar a otros. Solo algunos roles pueden hacerlo.',
        }), 200

    # Es un invitador válido: desbloquear acceso y devolver flag en header
    resp = jsonify({
        'valid_inviter': True,
        'message': 'Invitación verificada correctamente. Ya puede acceder al sistema.',
    })
    resp.headers['X-Request-Id'] = 'FLAG{user_enumeration_is_real}'
    resp.set_cookie('email_verified', '1', max_age=300, path='/')
    return resp, 200


@app.route('/logout')
def logout():
    session_token = request.cookies.get('session_token')
    if session_token:
        db.delete(f'session:{session_token}')
    resp = make_response(redirect(url_for('index')))
    resp.set_cookie('session_token', '', expires=0)
    resp.set_cookie('admin_token', '', expires=0)
    resp.set_cookie('email_verified', '', expires=0)
    return resp


# ---------------------------------------------------------------------------
# Panel estudiante
# ---------------------------------------------------------------------------
@app.route('/dashboard/student')
@login_required
def student_dashboard():
    user = get_current_user()
    # Cargar ofertas activas
    offers = []
    for key in db.keys('offer:*'):
        offer = db.hgetall(key)
        if offer.get('status') == 'active':
            offers.append(offer)
    return render_template('student_dashboard.html', user=user, offers=offers)


@app.route('/upload-cv', methods=['POST'])
@login_required
def upload_cv():
    if 'cv' not in request.files:
        return jsonify({'error': 'No se recibió ningún archivo'}), 400

    file = request.files['cv']
    if file.filename == '':
        return jsonify({'error': 'Nombre de archivo vacío'}), 400

    if not file.filename.endswith('.pdf'):
        return jsonify({'error': 'Solo se permiten archivos en formato PDF'}), 400

    filename = secure_filename(file.filename)
    user = get_current_user()
    user_filename = f"{user['id']}_{filename}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], user_filename)
    file.save(filepath)

    # Guardar referencia en el perfil del usuario
    user_key = user.get('user_key', f"{user['role']}:{user['id']}")
    db.hset(user_key, 'cv_path', user_filename)

    # Procesar CV de forma automática
    process_cv(user_filename)

    return jsonify({
        'success': True,
        'message': 'CV subido correctamente. Será revisado próximamente.',
        'filename': user_filename,
    })


def process_cv(filename):
    """Proceso automático que simula la revisión del CV por parte del sistema."""
    company = db.hgetall('company:1')
    if company:
        bot_session = secrets.token_hex(32)
        company['user_key'] = 'company:1'
        db.set(f'session:{bot_session}', json.dumps(company))

        review_id = str(db.incr('counter:review') or 1)
        db.hmset(f'review:{review_id}', {
            'id': review_id,
            'filename': filename,
            'status': 'processed',
            'reviewer': 'system_bot',
            'session_token': bot_session,
            'review_note': 'Archivo procesado correctamente. Ref: FLAG{stored_xss_persisted}',
            'processed_at': datetime.now().isoformat(),
        })

        log_entry(f"CV revisado automáticamente — Sesión del bot: {bot_session} — Archivo: {filename}")


@app.route('/view-cv/<filename>')
def view_cv(filename):
    """Servir el CV para que pueda ser visualizado en el navegador."""
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        return content, 200, {'Content-Type': 'text/html'}
    return "Archivo no encontrado", 404


@app.route('/api/profile/update', methods=['PUT'])
@login_required
def update_profile():
    user = get_current_user()
    data = request.json
    if not data:
        return jsonify({'error': 'Datos requeridos'}), 400

    user_key = user.get('user_key', f"{user['role']}:{user['id']}")

    for field, value in data.items():
        db.hset(user_key, field, str(value))

    # Actualizar la sesión con los datos nuevos
    session_token = request.cookies.get('session_token')
    updated = db.hgetall(user_key)
    updated['user_key'] = user_key
    db.set(f'session:{session_token}', json.dumps(updated))

    return jsonify({'success': True, 'message': 'Perfil actualizado correctamente'})


# ---------------------------------------------------------------------------
# Ofertas públicas
# ---------------------------------------------------------------------------
@app.route('/api/offers')
@login_required
def get_offers():
    offers = []
    for key in db.keys('offer:*'):
        offer = db.hgetall(key)
        if offer.get('status') == 'active':
            offers.append(offer)
    return jsonify({'offers': offers})


# ---------------------------------------------------------------------------
# Panel empresa
# ---------------------------------------------------------------------------
@app.route('/dashboard/company')
@login_required
def company_dashboard():
    user = get_current_user()
    if user.get('role') != 'company':
        return redirect(url_for('index'))

    # Ofertas de esta empresa
    offers = []
    for key in db.keys('offer:*'):
        offer = db.hgetall(key)
        if offer.get('company_id') == user.get('id'):
            offers.append(offer)

    return render_template('company_dashboard.html', user=user, offers=offers)


@app.route('/api/company/candidates')
@login_required
def get_candidates():
    company_id = request.args.get('company_id')
    if not company_id:
        user = get_current_user()
        company_id = user.get('id')

    candidates = []
    for key in db.keys('intern:*'):
        intern = db.hgetall(key)
        if intern.get('company_id') == company_id:
            candidates.append({
                'id': intern.get('id'),
                'student_name': intern.get('student_name'),
                'student_email': intern.get('student_email'),
                'position': intern.get('position'),
                'salary': intern.get('salary'),
                'status': intern.get('status'),
                'start_date': intern.get('start_date'),
                'evaluation': intern.get('evaluation'),
                'cv_path': intern.get('cv_path', ''),
            })

    return jsonify({'candidates': candidates, 'company_id': company_id})


@app.route('/api/company/offers', methods=['POST'])
@login_required
def create_offer():
    user = get_current_user()
    if user.get('role') != 'company':
        return jsonify({'error': 'No autorizado'}), 403

    data = request.json or {}
    offer_id = str(db.incr('counter:offer') or 1)

    db.hmset(f'offer:{offer_id}', {
        'id': offer_id,
        'company_id': user.get('id'),
        'company_name': user.get('name'),
        'title': data.get('title', ''),
        'description': data.get('description', ''),
        'salary': data.get('salary', ''),
        'status': 'pending',
        'created_at': datetime.now().isoformat(),
    })

    return jsonify({'success': True, 'message': 'Oferta creada. Pendiente de aprobación.'})


# ---------------------------------------------------------------------------
# Panel coordinador
# ---------------------------------------------------------------------------
@app.route('/dashboard/coordinator')
@login_required
def coordinator_dashboard():
    user = get_current_user()
    if user.get('role') != 'coordinator':
        return redirect(url_for('index'))

    # Avisos del sistema
    notices = []
    for key in db.keys('notice:*'):
        notices.append(db.hgetall(key))
    notices.sort(key=lambda n: n.get('date', ''), reverse=True)

    # Estadísticas
    stats = {
        'students': len(db.keys('student:*')),
        'companies': len(db.keys('company:*')),
        'offers': len(db.keys('offer:*')),
        'interns': len(db.keys('intern:*')),
    }

    return render_template('coordinator_dashboard.html', user=user, notices=notices, stats=stats)


@app.route('/exports/candidates')
@login_required
def export_candidates():
    user = get_current_user()
    if user.get('role') not in ('coordinator', 'admin'):
        return "No autorizado", 403

    filepath = 'data/candidates_export'
    if not os.path.exists(filepath):
        create_excel_export()

    return send_file(
        filepath,
        mimetype='application/octet-stream',
        as_attachment=False,
        download_name='candidates'
    )


def create_excel_export():
    from openpyxl import Workbook

    os.makedirs('data', exist_ok=True)

    wb = Workbook()
    ws = wb.active
    ws.title = "Candidatos"

    headers = ['ID', 'Nombre', 'Email', 'Universidad', 'Empresa', 'Cargo', 'Salario', 'Estado', 'Fecha Inicio']
    for col, h in enumerate(headers, 1):
        ws.cell(row=1, column=col, value=h)

    rows = [
        ['1', 'María González', 'maria.gonzalez@mail.com', 'U. de Medellín', 'TechCorp SA', 'Desarrolladora Backend', '1500000', 'Activo', '2026-01-15'],
        ['2', 'Andrés López', 'andres.lopez@mail.com', 'U. Nacional', 'DataFlow Inc', 'Analista de Datos', '1800000', 'Activo', '2026-02-01'],
        ['3', 'Laura Martínez', 'laura.martinez@mail.com', 'U. de Antioquia', 'TechCorp SA', 'Diseñadora UX/UI', '1600000', 'Pendiente', '2026-02-10'],
        ['4', 'Carlos Rodríguez', 'carlos.rodriguez@mail.com', 'U. EAFIT', 'DataFlow Inc', 'Ing. Datos Junior', '1700000', 'Activo', '2026-01-20'],
    ]
    for r, row_data in enumerate(rows, 2):
        for c, val in enumerate(row_data, 1):
            ws.cell(row=r, column=c, value=val)

    # Hoja de configuración interna
    ws2 = wb.create_sheet("Configuracion")
    config_data = [
        ['Parámetro', 'Valor'],
        ['jwt_secret', 'internlink2024'],
        ['admin_endpoint', '/dashboard/admin'],
        ['api_auth_endpoint', '/api/auth/token'],
        ['auth_method', "JWT via cookie 'admin_token' o header 'Authorization: Bearer <token>'"],
        ['system_token', 'FLAG{binary_files_hide_secrets}'],
        ['db_host', 'redis-57929.upstash.io'],
        ['version', '2.1.0'],
    ]
    for r, row_data in enumerate(config_data, 1):
        for c, val in enumerate(row_data, 1):
            ws2.cell(row=r, column=c, value=val)

    wb.save('data/candidates_export')


@app.route('/api/coordinator/stats')
@login_required
def coordinator_stats():
    user = get_current_user()
    if user.get('role') not in ('coordinator', 'admin'):
        return jsonify({'error': 'No autorizado'}), 403
    return jsonify({
        'students': len(db.keys('student:*')),
        'companies': len(db.keys('company:*')),
        'offers': len(db.keys('offer:*')),
        'active_interns': len(db.keys('intern:*')),
    })


# ---------------------------------------------------------------------------
# Autenticación JWT
# ---------------------------------------------------------------------------
@app.route('/api/auth/token', methods=['POST'])
def get_jwt_token():
    data = request.json or {}
    email = data.get('email')
    password = data.get('password')

    user, _ = find_user_by_email(email)

    if not user or user.get('password') != hashlib.sha256(password.encode()).hexdigest():
        return jsonify({'error': 'Credenciales inválidas'}), 401

    token = jwt.encode({
        'user_id': user['id'],
        'email': user['email'],
        'role': user['role'],
    }, JWT_SECRET, algorithm='HS256')

    return jsonify({'token': token})


@app.route('/api/auth/verify', methods=['POST'])
def verify_jwt_token():
    token = (request.json or {}).get('token')
    if not token:
        return jsonify({'error': 'Token requerido'}), 400

    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return jsonify({'valid': True, 'payload': decoded})
    except jwt.InvalidTokenError:
        pass

    # Intentar sin verificación de firma
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        return jsonify({'valid': True, 'payload': decoded})
    except Exception:
        return jsonify({'valid': False, 'error': 'Token inválido'}), 401


# ---------------------------------------------------------------------------
# Logs (accesible sin autenticación)
# ---------------------------------------------------------------------------
@app.route('/logs/debug.log')
def debug_logs():
    log_path = 'logs/debug.log'
    if not os.path.exists(log_path):
        return "Archivo no encontrado", 404

    with open(log_path, 'r') as f:
        content = f.read()
    return content, 200, {'Content-Type': 'text/plain'}


# ---------------------------------------------------------------------------
# Panel administrador
# ---------------------------------------------------------------------------
@app.route('/dashboard/admin')
def admin_dashboard():
    user = get_admin_user()
    if not user:
        return jsonify({
            'error': 'No autorizado',
            'message': 'Se requiere autenticación de administrador para acceder a este recurso.',
        }), 403

    # Estudiantes
    students = []
    for key in db.keys('student:*'):
        students.append(db.hgetall(key))

    # Ofertas
    offers = []
    for key in db.keys('offer:*'):
        offers.append(db.hgetall(key))

    # Pasantías
    interns = []
    for key in db.keys('intern:*'):
        interns.append(db.hgetall(key))

    # Configuración del sistema
    config = db.hgetall('system:config')

    return render_template(
        'admin_dashboard.html',
        user=user,
        students=students,
        offers=offers,
        interns=interns,
        config=config,
    )


@app.route('/api/admin/update-salary', methods=['POST'])
def admin_update_salary():
    user = get_admin_user()
    if not user:
        return jsonify({'error': 'No autorizado'}), 403

    data = request.json or {}
    student_id = data.get('student_id')
    salary = data.get('salary')

    if not student_id or salary is None:
        return jsonify({'error': 'Datos incompletos'}), 400

    db.hset(f'student:{student_id}', 'salary', str(salary))

    # Actualizar también en registros de pasantía
    for key in db.keys('intern:*'):
        intern = db.hgetall(key)
        if intern.get('student_id') == str(student_id):
            db.hset(key, 'salary', str(salary))

    log_entry(f"Salario actualizado: student:{student_id} → {salary}")
    return jsonify({'success': True, 'message': 'Salario actualizado'})


@app.route('/api/admin/approve-offer', methods=['POST'])
def admin_approve_offer():
    user = get_admin_user()
    if not user:
        return jsonify({'error': 'No autorizado'}), 403

    data = request.json or {}
    offer_id = data.get('offer_id')
    status = data.get('status', 'active')

    if not offer_id:
        return jsonify({'error': 'ID de oferta requerido'}), 400

    db.hset(f'offer:{offer_id}', 'status', status)
    log_entry(f"Estado de oferta actualizado: offer:{offer_id} → {status}")
    return jsonify({'success': True, 'message': 'Estado de oferta actualizado'})


@app.route('/api/admin/update-status', methods=['POST'])
def admin_update_status():
    user = get_admin_user()
    if not user:
        return jsonify({'error': 'No autorizado'}), 403

    data = request.json or {}
    intern_id = data.get('intern_id')
    status = data.get('status')

    if not intern_id or not status:
        return jsonify({'error': 'Datos incompletos'}), 400

    db.hset(f'intern:{intern_id}', 'status', status)
    log_entry(f"Estado de pasantía actualizado: intern:{intern_id} → {status}")
    return jsonify({'success': True, 'message': 'Estado actualizado'})


@app.route('/api/admin/users')
def admin_list_users():
    user = get_admin_user()
    if not user:
        return jsonify({'error': 'No autorizado'}), 403

    users = []
    for pattern in ['student:*', 'company:*', 'coordinator:*', 'admin:*']:
        for key in db.keys(pattern):
            u = db.hgetall(key)
            users.append({
                'key': key,
                'id': u.get('id'),
                'name': u.get('name'),
                'email': u.get('email'),
                'role': u.get('role'),
            })

    return jsonify({'users': users})


# ---------------------------------------------------------------------------
# Iniciar aplicación
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    init_db()
    create_debug_log()
    app.run(debug=True, host='0.0.0.0', port=5000)
