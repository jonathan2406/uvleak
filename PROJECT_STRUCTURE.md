# 📁 Estructura del Proyecto InternLink

```
uvleak/
│
├── 📄 app.py                    # Aplicación Flask principal
├── 📄 requirements.txt          # Dependencias de Python
├── 📄 .env                      # Variables de entorno (Redis)
├── 📄 .gitignore               # Archivos ignorados por Git
│
├── 📚 Documentación
│   ├── 📄 README.md            # Documentación principal
│   ├── 📄 START.md             # Guía de inicio rápido
│   ├── 📄 WALKTHROUGH.md       # Solución paso a paso
│   ├── 📄 prompt.md            # Diseño original del lab
│   └── 📄 PROJECT_STRUCTURE.md # Este archivo
│
├── 📂 templates/               # Plantillas HTML
│   ├── 📄 base.html            # Template base
│   ├── 📄 login.html           # Página de login
│   ├── 📄 register.html        # Página de registro
│   ├── 📄 student_dashboard.html      # Panel estudiante
│   ├── 📄 company_dashboard.html      # Panel empresa
│   ├── 📄 coordinator_dashboard.html  # Panel coordinador
│   └── 📄 admin_dashboard.html        # Panel administrador
│
├── 📂 static/                  # Archivos estáticos
│   ├── 📂 css/
│   │   └── 📄 style.css        # Estilos (glassmorphism)
│   └── 📂 uploads/             # CVs subidos por usuarios
│       └── 📄 .gitkeep
│
├── 📂 logs/                    # Logs de la aplicación
│   └── 📄 .gitkeep
│
├── 📂 data/                    # Datos y archivos generados
│   └── 📄 .gitkeep
│   └── 📄 candidates.xlsx      # (se genera automáticamente)
│
└── 📂 payloads/                # Payloads de ejemplo
    ├── 📄 xss_cv.html          # Payload XSS para ACTO 2
    └── 📄 jwt_forge.py         # Script para forjar JWT (ACTO 7)
```

## 📦 Componentes Principales

### Backend (app.py)

**Rutas Públicas:**
- `GET /` - Página principal (redirige según usuario)
- `GET /login` - Página de login
- `POST /login` - Autenticación
- `GET /register` - Página de registro
- `POST /register` - Crear cuenta
- `GET /logout` - Cerrar sesión

**API Endpoints:**
- `POST /api/check-email` - 🚩 ACTO 1: Enumeración de usuarios
- `POST /upload-cv` - 🚩 ACTO 2: Upload vulnerable
- `GET /view-cv/<filename>` - Servir CV (XSS)
- `GET /api/company/candidates` - 🚩 ACTO 4: IDOR
- `PUT /api/profile/update` - 🚩 ACTO 5: Mass Assignment
- `GET /exports/candidates` - 🚩 ACTO 6: Archivo binario
- `POST /api/auth/jwt-login` - Login con JWT
- `POST /api/auth/verify-jwt` - 🚩 ACTO 7: Verificar JWT
- `GET /logs/debug.log` - 🚩 ACTO 8: Logs expuestos
- `POST /api/admin/update-salary` - Modificar salarios
- `POST /api/admin/approve-offer` - Aprobar ofertas

**Dashboards:**
- `/dashboard/student` - Panel de estudiante
- `/dashboard/company` - Panel de empresa (🚩 ACTO 3)
- `/dashboard/coordinator` - Panel de coordinador
- `/dashboard/admin` - Panel de administrador (🚩 ACTO FINAL)

### Frontend

**Tecnologías:**
- HTML5 semántico
- CSS3 con Glassmorphism
- Vanilla JavaScript (sin frameworks)
- Fetch API para llamadas AJAX
- LocalStorage para tracking de flags

**Diseño:**
- Inspirado en la imagen de UdeA
- Colores: #6366f1 (primary), gradientes morados
- Cards con sombras y efectos hover
- Responsive design
- Alerts y badges coloridos

### Base de Datos (Redis/Upstash)

**Colecciones:**
- `student:*` - Estudiantes
- `company:*` - Empresas
- `coordinator:*` - Coordinadores
- `admin:*` - Administradores
- `session:*` - Sesiones de usuario
- `counter:*` - Contadores de IDs
- `offer:*` - Ofertas de trabajo

**Estructura de Usuario:**
```json
{
    "id": "1",
    "name": "Juan Pérez",
    "email": "juan@example.com",
    "password": "hash_sha256",
    "role": "student",
    "created_at": "2024-02-15T10:00:00",
    "cv_path": "1_cv.pdf",
    "salary": "0"
}
```

## 🚩 Mapa de Flags

| Acto | Flag | Vulnerabilidad | Archivo Relacionado |
|------|------|----------------|---------------------|
| 1 | `FLAG{user_enumeration_is_real}` | User Enumeration | `register.html`, `app.py` |
| 2 | `FLAG{stored_xss_persisted}` | Stored XSS | `student_dashboard.html`, `xss_cv.html` |
| 3 | `FLAG{session_hijacked}` | Session Hijacking | `company_dashboard.html` |
| 4 | `FLAG{idor_horizontal}` | IDOR Horizontal | `company_dashboard.html` |
| 5 | `FLAG{mass_assignment_abuse}` | Mass Assignment | `student_dashboard.html` |
| 6 | `FLAG{binary_files_hide_secrets}` | Info Disclosure | `coordinator_dashboard.html`, Excel |
| 7 | `FLAG{jwt_forged_successfully}` | JWT Weak Secret | `coordinator_dashboard.html`, `jwt_forge.py` |
| 8 | `FLAG{logs_are_sensitive}` | Exposed Logs | `app.py` (endpoint `/logs/debug.log`) |
| 9 | `FLAG{internlink_compromised}` | Full Compromise | `admin_dashboard.html` |

## 🎨 Estética y Diseño

### Paleta de Colores

```css
--primary-color: #6366f1     /* Azul/Morado principal */
--primary-dark: #4f46e5      /* Variante oscura */
--secondary-color: #8b5cf6   /* Morado secundario */
--success-color: #10b981     /* Verde éxito */
--error-color: #ef4444       /* Rojo error */
--warning-color: #f59e0b     /* Naranja advertencia */
--info-color: #3b82f6        /* Azul información */
```

### Características de Diseño

- **Glassmorphism:** Fondo difuminado con transparencia
- **Gradientes:** Linear gradients en backgrounds
- **Sombras:** Box-shadows suaves y modernas
- **Bordes redondeados:** Border-radius de 12-24px
- **Transiciones:** Animaciones smooth en hover
- **Iconos:** Emojis como iconos (sin dependencias)

## 🔧 Configuración

### Variables de Entorno (.env)

```env
UPSTASH_REDIS_REST_URL="https://tu-instancia.upstash.io"
UPSTASH_REDIS_REST_TOKEN="tu_token_aqui"
```

### Configuración de Flask (app.py)

```python
SECRET_KEY = 'internlink_secret_2024'
UPLOAD_FOLDER = 'static/uploads'
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
JWT_SECRET = 'internlink2024'  # ¡Débil intencionalmente!
```

## 🧪 Testing del Lab

### Checklist de Verificación

- [ ] `GET /` redirige correctamente
- [ ] Registro de usuario funciona
- [ ] Login funciona con credenciales correctas
- [ ] `/api/check-email` devuelve respuestas distintas
- [ ] Upload de archivo `.pdf` funciona
- [ ] Cookie `session_token` NO tiene HttpOnly
- [ ] `/api/company/candidates?company_id=X` permite IDOR
- [ ] `/api/profile/update` acepta campo `role`
- [ ] `/exports/candidates` devuelve archivo binario
- [ ] `/logs/debug.log` es accesible públicamente
- [ ] JWT con secret `internlink2024` es aceptado
- [ ] Panel admin permite modificar salarios

## 📚 Recursos de Aprendizaje

### Para Estudiantes

1. **START.md** - Comienza aquí
2. **README.md** - Entiende las vulnerabilidades
3. **WALKTHROUGH.md** - Si te atascas

### Para Instructores

1. **prompt.md** - Diseño pedagógico
2. **PROJECT_STRUCTURE.md** - Arquitectura técnica
3. **app.py** - Código comentado

## 🛡️ Seguridad

### Vulnerabilidades Intencionadas

✅ User Enumeration (Sin rate limit)
✅ File Upload sin validación de MIME
✅ Cookie sin HttpOnly
✅ IDOR sin validación de ownership
✅ Mass Assignment sin whitelist
✅ JWT con secret débil
✅ Logs expuestos públicamente
✅ Sin MFA para admin
✅ Sin logging de auditoría

### Protecciones NO Implementadas

❌ CSRF Protection
❌ Rate Limiting
❌ Input Sanitization
❌ SQL Injection (N/A - usamos NoSQL)
❌ XSS Protection
❌ Content Security Policy
❌ HTTPS/TLS
❌ Password Complexity Rules
❌ Account Lockout

## 📊 Estadísticas del Proyecto

- **Líneas de código Python:** ~800 líneas
- **Líneas de HTML:** ~600 líneas
- **Líneas de CSS:** ~500 líneas
- **Líneas de JavaScript:** ~400 líneas
- **Total de endpoints:** 20+
- **Total de templates:** 7
- **Total de vulnerabilidades:** 9
- **Flags totales:** 9

## 🎓 Objetivos de Aprendizaje

Al completar este lab, los estudiantes habrán:

1. ✅ Identificado y explotado enumeración de usuarios
2. ✅ Creado y ejecutado un payload XSS
3. ✅ Robado y usado cookies de sesión
4. ✅ Explotado IDOR para acceso no autorizado
5. ✅ Escalado privilegios vía Mass Assignment
6. ✅ Analizado archivos binarios para encontrar información
7. ✅ Forjado tokens JWT con secrets débiles
8. ✅ Encontrado información sensible en logs
9. ✅ Obtenido acceso total como administrador

---

**Última actualización:** 15 de Febrero de 2024
**Versión:** 1.0
**Estado:** Funcional y listo para uso educativo
