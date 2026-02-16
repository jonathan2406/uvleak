"""
Punto de entrada para Vercel - Wrapper para app.py
No modifica las vulnerabilidades intencionales del laboratorio
"""
import sys
import os

# Agregar el directorio raíz al path para importar app.py
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, init_db, create_debug_log

# Variable de control para inicializar solo una vez
_initialized = False

def initialize():
    """Inicializa la base de datos y logs una sola vez."""
    global _initialized
    if not _initialized:
        try:
            init_db()
            create_debug_log()
            _initialized = True
            print("Inicialización completada exitosamente")
        except Exception as e:
            print(f"Warning: Error inicializando: {e}")
            import traceback
            traceback.print_exc()

# Inicializar al cargar el módulo
initialize()

# Handler para Vercel - Flask app compatible con WSGI
app = app
