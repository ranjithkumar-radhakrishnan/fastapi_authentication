import time
from uuid import uuid4

import jwt
import os

from fastapi import HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from dotenv import load_dotenv

from app.api.core.redis_connection import redis_client

base_path = os.path.dirname(os.path.abspath(__file__))
new_base_path = os.path.dirname(os.path.dirname(base_path))
dotenv_path = os.path.join(new_base_path, '.env')

load_dotenv(dotenv_path)

JWT_SECRET = os.getenv('SECRET')
JWT_ALGORITHM = os.getenv('ALGORITHM')


class JWTManager:
    def __init__(self, secret: str, algorithm: str, expiry_seconds: int = 600):
        self.secret = secret
        self.algorithm = algorithm
        self.expiry_seconds = expiry_seconds

    def sign_token(self, user_id: str, roles: list):
        payload = {
            "userID": user_id,
            "roles": roles,
            "jti": str(uuid4()),
            "expiry": time.time() + self.expiry_seconds
        }
        token = jwt.encode(payload, self.secret, algorithm=self.algorithm)
        return {"access_token": token}

    def decode_token(self, token: str):
        try:
            decoded_token = jwt.decode(token, self.secret, algorithms=self.algorithm)
            if decoded_token.get("expiry", 0) < time.time():
                return None
            return decoded_token
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return {}


class jwtBearer(HTTPBearer):
    def __init__(self, roles = None, auto_Error: bool = True):
        self.roles = roles
        super(jwtBearer, self).__init__(auto_error=auto_Error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(jwtBearer, self).__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(status_code=403, detail="Invalid or Expired token")

            jwt_manager = JWTManager(secret=JWT_SECRET, algorithm=JWT_ALGORITHM)
            payload = jwt_manager.decode_token(credentials.credentials)

            jti = payload.get("jti")
            if not jti:
                raise HTTPException(status_code=403, detail="Invalid token structure")

            if redis_client.get(jti) == "blacklisted":
                raise HTTPException(status_code=403, detail="Token is blacklisted")

            if self.roles:
                has_role = any(role in payload.get('roles', []) for role in self.roles)
                if not has_role:
                    raise HTTPException(status_code=401, detail="Access denied, Unauthorized role")
            return payload
        else:
            raise HTTPException(status_code=403, detail="Invalid or Expired token")
