# 🚀 Inicio Rápido - InternLink CTF

## Instalación y Ejecución en 3 Pasos

### 1️⃣ Instalar Dependencias

```bash
# Crear entorno virtual (recomendado)
python -m venv venv

# Activar entorno virtual
# Windows PowerShell:
.\venv\Scripts\Activate.ps1
# Windows CMD:
venv\Scripts\activate.bat
# Linux/Mac:
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt
```

### 2️⃣ Verificar Configuración

Asegúrate de que el archivo `.env` existe y contiene:

```env
UPSTASH_REDIS_REST_URL="tu_url_aqui"
UPSTASH_REDIS_REST_TOKEN="tu_token_aqui"
```

### 3️⃣ Ejecutar la Aplicación

```bash
python app.py
```

La aplicación estará disponible en: **http://localhost:5000**

---

## 🎯 Primeros Pasos

1. **Abre tu navegador en:** http://localhost:5000

2. **Regístrate como estudiante:**
   - Click en "Crear cuenta nueva"
   - Completa el formulario
   - Selecciona "Estudiante" como tipo de cuenta

3. **¡Empieza a capturar flags!** 🚩

---

## 📚 Guías Disponibles

- **README.md** - Información general y descripción de vulnerabilidades
- **WALKTHROUGH.md** - Solución paso a paso de todos los actos
- **prompt.md** - Diseño y arquitectura del laboratorio

---

## 🔐 Credenciales Pre-configuradas

### Empresa
- **Email:** empresa@techcorp.com
- **Password:** EmpresaPass123!

### Coordinador
- **Email:** coordinador@internlink.com
- **Password:** CoordPass123!

### Administrador
- **Email:** admin@internlink.com
- **Password:** AdminPass123!

> ⚠️ **Nota:** El objetivo del CTF es **NO** usar estas credenciales directamente, sino escalar privilegios desde una cuenta de estudiante normal.

---

## 🛠️ Solución de Problemas

### Error: "No module named 'flask'"
```bash
pip install -r requirements.txt
```

### Error: "Connection refused" a Redis
- Verifica que las credenciales de Upstash en `.env` sean correctas
- Asegúrate de tener conexión a internet

### Error: "Port 5000 already in use"
Cambia el puerto en `app.py` (última línea):
```python
app.run(debug=True, host='0.0.0.0', port=5001)
```

---

## 📞 Soporte

Si encuentras problemas:
1. Revisa el archivo `logs/debug.log`
2. Verifica la consola donde ejecutaste `python app.py`
3. Abre un issue en el repositorio

---

## ⚠️ Recordatorio de Seguridad

Este es un **laboratorio educativo intencionalmente vulnerable**.

- ❌ NO lo despliegues en internet
- ❌ NO uses estas técnicas sin autorización
- ✅ Úsalo solo para aprendizaje
- ✅ Practica en entornos controlados

---

**¡Buena suerte capturando todos los 9 flags!** 🚩🎉
