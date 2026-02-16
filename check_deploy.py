#!/usr/bin/env python3
"""
Script de validación pre-deploy para Vercel
Verifica que todo esté listo para el despliegue
"""
import os
import sys

def check_file(filepath, description):
    """Verifica que un archivo exista."""
    if os.path.exists(filepath):
        print(f"[OK] {description}: OK")
        return True
    else:
        print(f"[X] {description}: NO ENCONTRADO ({filepath})")
        return False

def check_env_vars():
    """Verifica que las variables de entorno necesarias esten en .env"""
    env_path = ".env"
    if not os.path.exists(env_path):
        print(f"[!] Archivo .env no encontrado (las variables deben configurarse en Vercel)")
        return True
    
    required_vars = [
        "CLOUDINARY_URL",
        "UPSTASH_REDIS_REST_URL",
        "UPSTASH_REDIS_REST_TOKEN"
    ]
    
    with open(env_path, 'r') as f:
        content = f.read()
    
    all_found = True
    for var in required_vars:
        if var in content:
            print(f"[OK] Variable {var}: Encontrada en .env")
        else:
            print(f"[X] Variable {var}: NO ENCONTRADA en .env")
            all_found = False
    
    return all_found

def check_requirements():
    """Verifica que requirements.txt tenga las dependencias necesarias."""
    req_path = "requirements.txt"
    if not os.path.exists(req_path):
        print(f"[X] requirements.txt: NO ENCONTRADO")
        return False
    
    required_packages = [
        "Flask",
        "PyJWT",
        "python-dotenv",
        "openpyxl",
        "Werkzeug",
        "upstash-redis",
        "cloudinary"
    ]
    
    with open(req_path, 'r') as f:
        content = f.read().lower()
    
    all_found = True
    for package in required_packages:
        if package.lower() in content:
            print(f"[OK] Paquete {package}: OK")
        else:
            print(f"[X] Paquete {package}: NO ENCONTRADO")
            all_found = False
    
    return all_found

def main():
    print("=" * 60)
    print("VERIFICACION PRE-DEPLOY PARA VERCEL")
    print("=" * 60)
    print()
    
    checks = []
    
    # Archivos principales
    print("[*] Verificando archivos principales...")
    checks.append(check_file("app.py", "Aplicacion principal (app.py)"))
    checks.append(check_file("vercel.json", "Configuracion de Vercel (vercel.json)"))
    checks.append(check_file("api/index.py", "Punto de entrada (api/index.py)"))
    checks.append(check_file("requirements.txt", "Dependencias (requirements.txt)"))
    print()
    
    # Templates
    print("[*] Verificando templates...")
    template_files = [
        "templates/base.html",
        "templates/gate.html",
        "templates/login.html",
        "templates/register.html",
        "templates/student_dashboard.html",
        "templates/company_dashboard.html",
        "templates/coordinator_dashboard.html",
        "templates/admin_dashboard.html"
    ]
    
    for template in template_files:
        checks.append(check_file(template, f"Template {os.path.basename(template)}"))
    print()
    
    # Static
    print("[*] Verificando archivos estaticos...")
    checks.append(check_file("static/css", "Directorio CSS"))
    print()
    
    # Variables de entorno
    print("[*] Verificando variables de entorno...")
    checks.append(check_env_vars())
    print()
    
    # Dependencias
    print("[*] Verificando dependencias...")
    checks.append(check_requirements())
    print()
    
    # Resumen
    print("=" * 60)
    if all(checks):
        print("[OK] TODO LISTO PARA DESPLEGAR EN VERCEL")
        print()
        print("Siguiente paso:")
        print("  1. Sube el codigo a GitHub: git push origin main")
        print("  2. Importa el repo en Vercel: https://vercel.com")
        print("  3. Configura las variables de entorno en Vercel")
        print("  4. Deploy automatico!")
        print()
        print("O usa: vercel --prod")
        return 0
    else:
        print("[ERROR] HAY PROBLEMAS QUE RESOLVER ANTES DE DESPLEGAR")
        print()
        print("Revisa los errores arriba y corrige antes de continuar.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
