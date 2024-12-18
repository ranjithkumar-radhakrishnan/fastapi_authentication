from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException

from sqlalchemy.orm import Session

from app.api.core.config import AUTH_METHOD
if AUTH_METHOD == 'API_KEY':
    from app.api.core.api_key_auth import APIKeyAuth
    from app.api.models.user import APIKey
from app.api.core.jwt_auth import jwtBearer, JWTManager, JWT_SECRET, JWT_ALGORITHM
from app.api.core.redis_connection import redis_client
from app.api.models.user import User, Role
from app.api.core.db import get_db
from passlib.context import CryptContext
from fastapi.security import APIKeyHeader, HTTPBearer


router = APIRouter()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

jwt_scheme = HTTPBearer(bearerFormat="JWT", description="JWT Bearer Token")
api_key_scheme = APIKeyHeader(name="X-API-Key", description="API Key Authentication")


@router.post("/signup")
def signup(
        email: str,
        password: str,
        role_ids: list[int] = None,
        db: Session = Depends(get_db),
):
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User with this email already exists.")

    roles = []
    if role_ids:
        roles = db.query(Role).filter(Role.id.in_(role_ids)).all()
        if len(roles) != len(role_ids):
            raise HTTPException(status_code=400, detail="One or more role IDs are invalid.")
    hashed_password = pwd_context.hash(password)

    new_user = User(email=email, hashed_password=hashed_password, roles=roles)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User registered successfully.", "user_id": new_user.id}


@router.post("/login")
def login(email: str, password: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user or not pwd_context.verify(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials.")

    if AUTH_METHOD == 'JWT':
        jwt_manager = JWTManager(secret=JWT_SECRET, algorithm=JWT_ALGORITHM)
        roles = []
        for role in user.roles:
            roles.append(role.name)
        token = jwt_manager.sign_token(user.id, roles)
        return token
    else:
        api_key = APIKeyAuth.generate_api_key(user.id, db)
        return {"message": "Login successful.", "api_key": api_key}


@router.post("/logout")
def logout(
        current_user: dict = Depends(
            APIKeyAuth.validate if AUTH_METHOD == "API_KEY" else jwtBearer()
        ),
        db: Session = Depends(get_db)
):
    try:
        if AUTH_METHOD == "API_KEY":
            api_key = db.query(APIKey).filter(APIKey.user_id == current_user.id).order_by(APIKey.id.desc()).first()
            if api_key:
                api_key.revoked = True
                db.commit()
            return {"message": "API Key Logout successful."}

        elif AUTH_METHOD == "JWT":
            payload = current_user
            jti = payload.get("jti")
            exp = payload.get("expiry")

            ttl = exp - int(datetime.utcnow().timestamp())
            if ttl > 0:
                redis_client.setex(jti, int(ttl), "blacklisted")
            return {"message": "JWT Logout successful."}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
