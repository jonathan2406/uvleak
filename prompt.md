NARRATIVA BASE
Eres un estudiante registrado en una plataforma universitaria.

El sistema gestiona:

Estudiantes

Empresas

Coordinadores

Administradores

Tu objetivo es escalar desde un usuario normal hasta administrador, encadenando vulnerabilidades reales.

FLUJO FINAL DEL LAB
ACTO 1 — Registro y Enumeración
Vulnerabilidades:

Enumeración vía /api/check-email

Respuestas distintas según existencia

Sin rate limiting

Flag 1:
FLAG{user_enumeration_is_real}

ACTO 2 — Subida de CV y Stored XSS Automatizado
Cambio importante respecto a la versión anterior.

Contexto
El estudiante puede subir su CV en formato .pdf.

Vulnerabilidad
Validación solo por extensión

No se valida MIME real

Permite subir HTML renombrado como .pdf

Flujo deseado
El estudiante sube un archivo HTML malicioso con extensión .pdf.

El servidor lo almacena.

Existe un proceso automático en backend que “revisa” el CV (simulado).

Ese proceso carga el archivo y ejecuta el JavaScript embebido.

El script malicioso:

Extrae document.cookie

Envía las cookies vía fetch() a webhook.site o requestbin del atacante.

No se simula una empresa manualmente.
Debe existir un mecanismo automatizado (por ejemplo, una ruta interna que renderice el CV como si fuera un navegador headless simulado o simplemente lo sirva como HTML para que el JS se ejecute).

Flag 2:
FLAG{stored_xss_persisted}

ACTO 3 — Robo de sesión y acceso empresa
Vulnerabilidad:

Cookie sin HttpOnly

Cookie en texto plano

Resultado:

El atacante usa la cookie capturada

Accede al panel empresa

Flag 3:
FLAG{session_hijacked}

ACTO 4 — IDOR horizontal
Endpoint:
/api/company/candidates?company_id=

Vulnerabilidad:

No valida ownership

Enumeración de company_id

Resultado:

Acceso a candidatos de otras empresas

Flag 4:
FLAG{idor_horizontal}

ACTO 5 — Mass Assignment
Endpoint:
PUT /api/profile/update

Vulnerabilidad:

Backend acepta cualquier campo enviado

Permite enviar "role": "coordinator"

Resultado:

Escalada silenciosa a coordinador

Flag 5:
FLAG{mass_assignment_abuse}

ACTO 6 — Endpoint binario oculto (.xlsx sin extensión)
Reemplazo total del CSV injection.

Contexto
Existe un endpoint interno accesible como coordinador:

/exports/candidates

Vulnerabilidad:

Sirve un archivo .xlsx

No tiene extensión

Se muestra como contenido binario en navegador

Flujo esperado:

El estudiante visita el endpoint.

Ve contenido ilegible.

Descarga el archivo.

Usa file (Linux/Windows) para identificar tipo.

Cambia extensión a .xlsx.

Lo abre en Excel.

Encuentra información relevante:

Ruta interna

Credencial parcial

Pista hacia el siguiente acto

Flag oculta

Flag 6:
FLAG{binary_files_hide_secrets}

ACTO 7 — Escalada técnica previa a admin
Reemplaza SSRF.

Propuesta coherente:

Configuración insegura de clave JWT
En el archivo Excel hay:

Una pista sobre el JWT_SECRET

O una clave débil tipo: internlink2024

El sistema usa JWT para autenticación de admin.

Vulnerabilidad:

JWT firmado con secret débil

O acepta alg: none

Flujo:

El estudiante obtiene la pista del Excel.

Genera su propio JWT con rol admin.

Reemplaza el token en cookie o header.

Accede al panel admin.

Flag 7:
FLAG{jwt_forged_successfully}

ACTO 8 — Logs expuestos
Endpoint:
/logs/debug.log

Vulnerabilidad:

Accesible públicamente

Contiene:

Credenciales temporales

Stacktrace

Información sensible

Flag 8:
FLAG{logs_are_sensitive}

ACTO FINAL — Manipulación total
Como admin:

Modificar salarios

Aprobar ofertas

Alterar estados

Vulnerabilidad:

Sin verificación adicional

Sin logging real

Flag final:
FLAG{internlink_compromised}

SUPER PROMPT PARA CURSOR
Ahora viene lo importante.

Este prompt está diseñado para que Cursor genere TODO el laboratorio correctamente estructurado.

Copia completo:

Actúa como un desarrollador senior especializado en seguridad ofensiva y en creación de laboratorios educativos tipo CTF.

Debes generar un laboratorio web vulnerable completo llamado "InternLink", construido en Flask (Python), con HTML + JS simple, sin frameworks complejos, usando archivos locales (pueden ser CSV o estructuras en memoria como simulación de base de datos).

El laboratorio debe estar completamente funcional y diseñado como un entorno educativo encadenado, donde cada acto lleva al siguiente. Debe incluir flags en cada acto.

Estructura obligatoria:

Registro y login básico.

Endpoint vulnerable a enumeración:

/api/check-email

Respuestas distintas según existencia.

Subida de CV:

Solo valida extensión ".pdf".

Permite subir HTML renombrado como .pdf.

Debe almacenarse en /static/uploads.

El sistema debe tener un mecanismo automatizado que procese el CV subido y permita que el JavaScript embebido se ejecute (simulación simple suficiente para permitir que el fetch del atacante se dispare).

Cookie sin HttpOnly.

Panel empresa:

Accesible con cookie robada.

Endpoint /api/company/candidates?company_id=

Sin validación de ownership.

Endpoint vulnerable a Mass Assignment:

PUT /api/profile/update

Backend actualiza cualquier campo enviado.

Endpoint binario:

/exports/candidates

Devuelve un archivo .xlsx real.

No mostrar extensión en la URL.

Contenido Excel debe incluir pista del JWT secret y FLAG correspondiente.

Sistema de autenticación JWT:

Implementar validación JWT incorrecta:

aceptar alg none o

usar secret débil (hardcodeado).

Permitir que usuario genere token con rol admin.

Endpoint logs expuestos:

/logs/debug.log

Incluir información sensible simulada.

Panel admin:

Permitir modificar salarios y estados.

Sin validaciones adicionales.

Requisitos adicionales:

Cada acto debe mostrar o permitir obtener una FLAG distinta:

FLAG{user_enumeration_is_real}

FLAG{stored_xss_persisted}

FLAG{session_hijacked}

FLAG{idor_horizontal}

FLAG{mass_assignment_abuse}

FLAG{binary_files_hide_secrets}

FLAG{jwt_forged_successfully}

FLAG{logs_are_sensitive}

FLAG{internlink_compromised}

Mantener código claro y modular.

Incluir README.md expl.

No incluir protecciones reales.

PARA LA BASE DE DATOS, TOMAR EN CUENTA ESTO: SE USA Uso de Redis (Vercel KV) en esta app, en breve:
Qué es: Un Redis al que la app se conecta con KV_REST_API_URL y KV_REST_API_TOKEN (Upstash).
OJO: las cosas de la aplicacion que no te queden claras o sientas que quedan con huecos, deberas razonar en como completarlas correctamente y coherentemente
