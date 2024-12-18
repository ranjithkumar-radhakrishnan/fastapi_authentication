import secrets
from datetime import datetime
from typing import List

from fastapi import HTTPException, Security, Depends
from fastapi.security.api_key import APIKeyHeader
from sqlalchemy.orm import Session

from app.api.core.db import get_db
from app.api.models.user import APIKey

API_KEY_NAME = "x-api-key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)


class APIKeyAuth:
    @classmethod
    def validate(cls, allowed_roles: list[str] = None, api_key: str = Security(api_key_header),
                 db: Session = Depends(get_db)):
        if not api_key:
            raise HTTPException(status_code=401, detail="API Key is required.")

        key_record = db.query(APIKey).filter(APIKey.key == api_key, APIKey.revoked == False).first()
        if not key_record or key_record.expiry_date < datetime.utcnow():
            raise HTTPException(status_code=401, detail="Invalid or expired API Key.")

        user = key_record.user

        if allowed_roles:
            for role in user.roles:
                if role.name not in allowed_roles:
                    raise HTTPException(status_code=403, detail="You do not have permission to access this resource.")
        return user

    @classmethod
    def generate_api_key(cls, user_id: int, db: Session):
        api_key = secrets.token_hex(32)
        new_api_key = APIKey(key=api_key, user_id=user_id)
        db.add(new_api_key)
        db.commit()
        return api_key

    @staticmethod
    def roles_required(allowed_roles: List[str]):
        def dependency(api_key: str = Security(api_key_header), db: Session = Depends(get_db)):
            return APIKeyAuth.validate(allowed_roles=allowed_roles, api_key=api_key, db=db)

        return Depends(dependency)
