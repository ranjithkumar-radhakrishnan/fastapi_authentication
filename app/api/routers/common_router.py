from fastapi import APIRouter, Depends

from app.api.core.jwt_auth import jwtBearer
from app.api.models.user import User

router = APIRouter()


# @router.post("/action")
# def admin_action(current_user: User = APIKeyAuth.roles_required(["ADMIN"])):
#     return {"message": "Admin action performed"}

@router.post("/action")
def admin_action(payload: dict = Depends(jwtBearer())):
    print("payload: ", payload)
    return {"message": "Admin action performed"}
