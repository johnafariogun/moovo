from fastapi import APIRouter, Depends

from app import schemas
from app.deps import get_current_active_user
from app.models import User

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=schemas.UserOut)
def read_current_user(current_user: User = Depends(get_current_active_user)):
    return current_user
