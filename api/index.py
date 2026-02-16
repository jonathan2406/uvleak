"""
Punto de entrada para Vercel - Wrapper para app.py
No modifica las vulnerabilidades intencionales del laboratorio
"""
import sys
import os

# Agregar el directorio raíz al path para importar app.py
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, root_dir)

# Asegurar que Flask encuentre templates y static
os.chdir(root_dir)

from app import app as flask_app, init_db, create_debug_log

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
            print(f"✅ Inicialización completada")
            print(f"📁 Root dir: {root_dir}")
            print(f"📄 Templates: {flask_app.template_folder}")
            print(f"🎨 Static: {flask_app.static_folder}")
        except Exception as e:
            print(f"❌ Error inicializando: {e}")
            import traceback
            traceback.print_exc()

# Inicializar al cargar el módulo
initialize()

# Handler para Vercel - Flask WSGI app
app = flask_app
