"""
InternLink - Laboratorio CTF Vulnerable
Sistema de gestión de pasantías con vulnerabilidades encadenadas
"""
from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response, send_file
from functools import wraps
import redis
import json
import hashlib
import secrets
import os
from datetime import datetime
import jwt
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

load_dotenv()

# Configuración
app = Flask(__name__)
app.config['SECRET_KEY'] = 'internlink_secret_2024'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

# JWT Secret débil (ACTO 7)
JWT_SECRET = 'internlink2024'

# Conectar a Redis
redis_url = os.getenv('UPSTASH_REDIS_REST_URL')
redis_token = os.getenv('UPSTASH_REDIS_REST_TOKEN')

# Cliente Redis usando Upstash REST API
import requests

class RedisClient:
    def __init__(self, url, token):
        self.url = url.rstrip('/')
        self.token = token
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
    
    def execute(self, command):
        response = requests.post(self.url, json=command, headers=self.headers)
        return response.json().get('result')
    
    def get(self, key):
        result = self.execute(['GET', key])
        return result
    
    def set(self, key, value):
        return self.execute(['SET', key, value])
    
    def hgetall(self, key):
        result = self.execute(['HGETALL', key])
        if not result:
            return {}
        return {result[i]: result[i+1] for i in range(0, len(result), 2)}
    
    def hset(self, key, field, value):
        return self.execute(['HSET', key, field, value])
    
    def hmset(self, key, mapping):
        command = ['HMSET', key]
        for k, v in mapping.items():
            command.extend([k, v])
        return self.execute(command)
    
    def keys(self, pattern):
        return self.execute(['KEYS', pattern])
    
    def delete(self, key):
        return self.execute(['DEL', key])
    
    def incr(self, key):
        return self.execute(['INCR', key])

db = RedisClient(redis_url, redis_token)

# Crear carpetas necesarias
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('logs', exist_ok=True)

# Inicializar datos de ejemplo
def init_db():
    """Inicializar base de datos con datos de ejemplo"""
    # Crear empresa de ejemplo
    if not db.hgetall('company:1'):
        db.hmset('company:1', {
            'id': '1',
            'name': 'TechCorp SA',
            'email': 'empresa@techcorp.com',
            'password': hashlib.sha256('EmpresaPass123!'.encode()).hexdigest(),
            'role': 'company'
        })
    
    # Crear coordinador de ejemplo
    if not db.hgetall('coordinator:1'):
        db.hmset('coordinator:1', {
            'id': '1',
            'name': 'Carlos Coordinador',
            'email': 'coordinador@internlink.com',
            'password': hashlib.sha256('CoordPass123!'.encode()).hexdigest(),
            'role': 'coordinator'
        })
    
    # Crear admin de ejemplo
    if not db.hgetall('admin:1'):
        db.hmset('admin:1', {
            'id': '1',
            'name': 'Admin Sistema',
            'email': 'admin@internlink.com',
            'password': hashlib.sha256('AdminPass123!'.encode()).hexdigest(),
            'role': 'admin'
        })

# Decorador de autenticación
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_token = request.cookies.get('session_token')
        if not session_token:
            return redirect(url_for('login'))
        
        user_data = db.get(f'session:{session_token}')
        if not user_data:
            return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    """Obtener usuario actual desde cookie"""
    session_token = request.cookies.get('session_token')
    if not session_token:
        return None
    
    user_json = db.get(f'session:{session_token}')
    if not user_json:
        return None
    
    return json.loads(user_json)

# RUTAS PRINCIPALES

@app.route('/')
def index():
    user = get_current_user()
    if user:
        role = user.get('role', 'student')
        if role == 'company':
            return redirect(url_for('company_dashboard'))
        elif role == 'coordinator':
            return redirect(url_for('coordinator_dashboard'))
        elif role == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('student_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Buscar usuario en todas las colecciones
        user = None
        user_key = None
        
        # Buscar en estudiantes
        for key in db.keys('student:*') or []:
            data = db.hgetall(key)
            if data.get('email') == email:
                user = data
                user_key = key
                break
        
        # Buscar en empresas
        if not user:
            for key in db.keys('company:*') or []:
                data = db.hgetall(key)
                if data.get('email') == email:
                    user = data
                    user_key = key
                    break
        
        # Buscar en coordinadores
        if not user:
            for key in db.keys('coordinator:*') or []:
                data = db.hgetall(key)
                if data.get('email') == email:
                    user = data
                    user_key = key
                    break
        
        # Buscar en admins
        if not user:
            for key in db.keys('admin:*') or []:
                data = db.hgetall(key)
                if data.get('email') == email:
                    user = data
                    user_key = key
                    break
        
        if user and user.get('password') == hashlib.sha256(password.encode()).hexdigest():
            # Crear sesión - Cookie SIN HttpOnly (vulnerable)
            session_token = secrets.token_hex(32)
            db.set(f'session:{session_token}', json.dumps(user))
            
            # Log de login (para ACTO 8)
            log_entry(f"Login exitoso: {email} - Role: {user.get('role', 'student')}")
            
            resp = make_response(redirect(url_for('index')))
            # VULNERABILIDAD: Cookie sin HttpOnly
            resp.set_cookie('session_token', session_token, httponly=False)
            return resp
        else:
            return render_template('login.html', error='Credenciales inválidas')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'student')
        
        # Validar que no exista
        existing = check_email_exists(email)
        if existing:
            return render_template('register.html', error='El email ya está registrado')
        
        # Crear usuario
        user_id = str(db.incr(f'counter:{role}') or 1)
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        user_data = {
            'id': user_id,
            'name': name,
            'email': email,
            'password': password_hash,
            'role': role,
            'created_at': datetime.now().isoformat()
        }
        
        db.hmset(f'{role}:{user_id}', user_data)
        
        # Log
        log_entry(f"Nuevo registro: {email} - Role: {role}")
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

# ACTO 1: Enumeración de usuarios
@app.route('/api/check-email', methods=['POST'])
def check_email():
    """VULNERABILIDAD: Respuestas distintas permiten enumeración"""
    email = request.json.get('email')
    
    if not email:
        return jsonify({'error': 'Email requerido'}), 400
    
    # Sin rate limiting (vulnerable)
    exists = check_email_exists(email)
    
    if exists:
        # Respuesta diferente cuando existe
        return jsonify({
            'exists': True,
            'message': 'Este email ya está registrado',
            'flag': 'FLAG{user_enumeration_is_real}'
        }), 200
    else:
        # Respuesta diferente cuando no existe
        return jsonify({
            'exists': False,
            'message': 'Email disponible'
        }), 200

def check_email_exists(email):
    """Verificar si un email existe en la base de datos"""
    for pattern in ['student:*', 'company:*', 'coordinator:*', 'admin:*']:
        for key in db.keys(pattern) or []:
            data = db.hgetall(key)
            if data.get('email') == email:
                return True
    return False

# ACTO 2: Subida de CV vulnerable
@app.route('/dashboard/student')
@login_required
def student_dashboard():
    user = get_current_user()
    return render_template('student_dashboard.html', user=user)

@app.route('/upload-cv', methods=['POST'])
@login_required
def upload_cv():
    """VULNERABILIDAD: Solo valida extensión, permite HTML como PDF"""
    if 'cv' not in request.files:
        return jsonify({'error': 'No hay archivo'}), 400
    
    file = request.files['cv']
    if file.filename == '':
        return jsonify({'error': 'Archivo vacío'}), 400
    
    # VULNERABILIDAD: Solo valida extensión
    if not file.filename.endswith('.pdf'):
        return jsonify({'error': 'Solo archivos PDF permitidos'}), 400
    
    # Guardar archivo
    filename = secure_filename(file.filename)
    user = get_current_user()
    user_filename = f"{user['id']}_{filename}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], user_filename)
    file.save(filepath)
    
    # Guardar referencia
    db.hset(f"{user['role']}:{user['id']}", 'cv_path', user_filename)
    
    # Simular procesamiento automático
    process_cv_automatic(user_filename)
    
    return jsonify({
        'success': True,
        'message': 'CV subido correctamente',
        'flag': 'FLAG{stored_xss_persisted}'
    })

def process_cv_automatic(filename):
    """Simular procesamiento automático que ejecuta el XSS"""
    # En un escenario real, esto sería un navegador headless
    # Aquí simplemente registramos que se procesó
    log_entry(f"CV procesado automáticamente: {filename}")

@app.route('/view-cv/<filename>')
def view_cv(filename):
    """Servir CV como HTML (permite XSS)"""
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(filepath):
        # VULNERABILIDAD: Servir como HTML sin sanitizar
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        return content
    return "Archivo no encontrado", 404

# ACTO 3: Panel empresa (acceso con cookie robada)
@app.route('/dashboard/company')
@login_required
def company_dashboard():
    user = get_current_user()
    if user.get('role') != 'company':
        return "Acceso denegado", 403
    
    return render_template('company_dashboard.html', 
                          user=user,
                          flag='FLAG{session_hijacked}')

# ACTO 4: IDOR Horizontal
@app.route('/api/company/candidates')
@login_required
def get_candidates():
    """VULNERABILIDAD: No valida ownership de company_id"""
    company_id = request.args.get('company_id')
    
    if not company_id:
        return jsonify({'error': 'company_id requerido'}), 400
    
    # VULNERABILIDAD: No valida que el usuario sea dueño de la empresa
    candidates = []
    for key in db.keys('student:*') or []:
        student = db.hgetall(key)
        candidates.append({
            'id': student.get('id'),
            'name': student.get('name'),
            'email': student.get('email'),
            'cv_path': student.get('cv_path', 'N/A')
        })
    
    return jsonify({
        'candidates': candidates,
        'company_id': company_id,
        'flag': 'FLAG{idor_horizontal}'
    })

# ACTO 5: Mass Assignment
@app.route('/api/profile/update', methods=['PUT'])
@login_required
def update_profile():
    """VULNERABILIDAD: Actualiza cualquier campo enviado"""
    user = get_current_user()
    data = request.json
    
    # VULNERABILIDAD: No filtra campos, acepta 'role'
    user_key = f"{user['role']}:{user['id']}"
    
    for key, value in data.items():
        db.hset(user_key, key, str(value))
    
    # Actualizar sesión
    session_token = request.cookies.get('session_token')
    updated_user = db.hgetall(user_key)
    db.set(f'session:{session_token}', json.dumps(updated_user))
    
    flag = None
    if 'role' in data:
        flag = 'FLAG{mass_assignment_abuse}'
    
    return jsonify({
        'success': True,
        'message': 'Perfil actualizado',
        'flag': flag
    })

# ACTO 6: Endpoint binario (Excel sin extensión)
@app.route('/exports/candidates')
@login_required
def export_candidates():
    """VULNERABILIDAD: Archivo XLSX sin extensión visible"""
    user = get_current_user()
    
    # Solo coordinador o admin
    if user.get('role') not in ['coordinator', 'admin']:
        return "Acceso denegado", 403
    
    # Servir archivo Excel sin extensión
    filepath = 'data/candidates.xlsx'
    
    # Crear archivo si no existe
    if not os.path.exists(filepath):
        create_excel_file()
    
    return send_file(filepath, 
                    mimetype='application/octet-stream',
                    as_attachment=False,
                    download_name='candidates')

def create_excel_file():
    """Crear archivo Excel con información y flag"""
    from openpyxl import Workbook
    
    os.makedirs('data', exist_ok=True)
    
    wb = Workbook()
    ws = wb.active
    ws.title = "Candidatos"
    
    # Headers
    ws['A1'] = 'ID'
    ws['B1'] = 'Nombre'
    ws['C1'] = 'Email'
    ws['D1'] = 'Estado'
    
    # Datos de ejemplo
    ws['A2'] = '1'
    ws['B2'] = 'Juan Estudiante'
    ws['C2'] = 'estudiante@mail.com'
    ws['D2'] = 'Aprobado'
    
    # Hoja oculta con información sensible
    ws2 = wb.create_sheet("Config")
    ws2['A1'] = 'Configuración del Sistema'
    ws2['A3'] = 'JWT_SECRET:'
    ws2['B3'] = 'internlink2024'
    ws2['A5'] = 'Admin Endpoint:'
    ws2['B5'] = '/admin/panel'
    ws2['A7'] = 'FLAG:'
    ws2['B7'] = 'FLAG{binary_files_hide_secrets}'
    
    wb.save('data/candidates.xlsx')

# ACTO 7: JWT vulnerable
@app.route('/api/auth/jwt-login', methods=['POST'])
def jwt_login():
    """Sistema JWT con secret débil"""
    email = request.json.get('email')
    password = request.json.get('password')
    
    # Validar usuario
    user = None
    for pattern in ['student:*', 'company:*', 'coordinator:*', 'admin:*']:
        for key in db.keys(pattern) or []:
            data = db.hgetall(key)
            if data.get('email') == email:
                if data.get('password') == hashlib.sha256(password.encode()).hexdigest():
                    user = data
                    break
        if user:
            break
    
    if not user:
        return jsonify({'error': 'Credenciales inválidas'}), 401
    
    # Generar JWT con secret débil
    token = jwt.encode({
        'user_id': user['id'],
        'email': user['email'],
        'role': user['role']
    }, JWT_SECRET, algorithm='HS256')
    
    return jsonify({'token': token})

@app.route('/api/auth/verify-jwt', methods=['POST'])
def verify_jwt():
    """VULNERABILIDAD: Acepta alg: none"""
    token = request.json.get('token')
    
    try:
        # VULNERABILIDAD: No valida algoritmo correctamente
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256', 'none'])
        
        flag = None
        if decoded.get('role') == 'admin':
            flag = 'FLAG{jwt_forged_successfully}'
        
        return jsonify({
            'valid': True,
            'user': decoded,
            'flag': flag
        })
    except:
        return jsonify({'valid': False}), 401

# Panel coordinador
@app.route('/dashboard/coordinator')
@login_required
def coordinator_dashboard():
    user = get_current_user()
    if user.get('role') != 'coordinator':
        return "Acceso denegado", 403
    
    return render_template('coordinator_dashboard.html', user=user)

# ACTO 8: Logs expuestos
@app.route('/logs/debug.log')
def debug_logs():
    """VULNERABILIDAD: Logs accesibles públicamente"""
    log_path = 'logs/debug.log'
    
    if not os.path.exists(log_path):
        create_debug_log()
    
    with open(log_path, 'r') as f:
        content = f.read()
    
    # Agregar flag si contiene información sensible
    if 'FLAG' in content:
        return f"{content}", 200, {'Content-Type': 'text/plain'}
    
    return content, 200, {'Content-Type': 'text/plain'}

def create_debug_log():
    """Crear log con información sensible"""
    os.makedirs('logs', exist_ok=True)
    
    log_content = """
[2024-02-15 10:23:45] INFO: Sistema iniciado
[2024-02-15 10:24:12] DEBUG: Conexión Redis establecida
[2024-02-15 10:24:15] WARNING: Intento de login fallido para admin@internlink.com
[2024-02-15 10:24:30] INFO: Login exitoso: admin@internlink.com
[2024-02-15 10:25:00] DEBUG: JWT_SECRET=internlink2024
[2024-02-15 10:25:15] ERROR: Stack trace:
  File "app.py", line 245, in process_payment
    db.execute(f"UPDATE salaries SET amount={amount}")
[2024-02-15 10:26:00] DEBUG: Credencial temporal: temp_admin_pass_2024!
[2024-02-15 10:27:00] INFO: FLAG{logs_are_sensitive}
[2024-02-15 10:28:00] DEBUG: Redis URL: https://proven-bonefish-57929.upstash.io
[2024-02-15 10:29:00] INFO: Backup completado
"""
    
    with open('logs/debug.log', 'w') as f:
        f.write(log_content)

def log_entry(message):
    """Agregar entrada al log"""
    log_path = 'logs/debug.log'
    timestamp = datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')
    
    with open(log_path, 'a') as f:
        f.write(f"{timestamp} INFO: {message}\n")

# ACTO FINAL: Panel admin
@app.route('/dashboard/admin')
@login_required
def admin_dashboard():
    user = get_current_user()
    if user.get('role') != 'admin':
        return "Acceso denegado", 403
    
    # Obtener todos los estudiantes
    students = []
    for key in db.keys('student:*') or []:
        student = db.hgetall(key)
        students.append(student)
    
    return render_template('admin_dashboard.html', 
                          user=user, 
                          students=students,
                          flag='FLAG{internlink_compromised}')

@app.route('/api/admin/update-salary', methods=['POST'])
@login_required
def update_salary():
    """VULNERABILIDAD: Sin validaciones adicionales"""
    user = get_current_user()
    if user.get('role') != 'admin':
        return jsonify({'error': 'No autorizado'}), 403
    
    student_id = request.json.get('student_id')
    salary = request.json.get('salary')
    
    # Sin validación de datos
    db.hset(f'student:{student_id}', 'salary', str(salary))
    
    log_entry(f"Admin {user['email']} modificó salario de student:{student_id} a {salary}")
    
    return jsonify({'success': True})

@app.route('/api/admin/approve-offer', methods=['POST'])
@login_required
def approve_offer():
    """Aprobar ofertas sin verificación"""
    user = get_current_user()
    if user.get('role') != 'admin':
        return jsonify({'error': 'No autorizado'}), 403
    
    offer_id = request.json.get('offer_id')
    status = request.json.get('status', 'approved')
    
    db.hset(f'offer:{offer_id}', 'status', status)
    
    log_entry(f"Admin {user['email']} cambió estado de offer:{offer_id} a {status}")
    
    return jsonify({'success': True})

@app.route('/logout')
def logout():
    session_token = request.cookies.get('session_token')
    if session_token:
        db.delete(f'session:{session_token}')
    
    resp = make_response(redirect(url_for('login')))
    resp.set_cookie('session_token', '', expires=0)
    return resp

# Inicializar
if __name__ == '__main__':
    init_db()
    create_debug_log()
    app.run(debug=True, host='0.0.0.0', port=5000)
