"""
Punto de entrada para Vercel - Wrapper para app.py
No modifica las vulnerabilidades intencionales del laboratorio
"""
import sys
import os

# Agregar el directorio raíz al path para importar app.py
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, init_db, create_debug_log

# Inicializar la base de datos en cada invocación serverless
# Esto es necesario porque Vercel no mantiene estado entre invocaciones
try:
    init_db()
    create_debug_log()
except Exception as e:
    # Log del error pero continuar
    print(f"Warning: Error inicializando DB: {e}")

# Exportar la aplicación Flask para Vercel
# Vercel espera una variable llamada 'app' o que se use el patrón de handler
handler = app
