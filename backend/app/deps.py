from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy.orm import Session

from .database import get_db
from .models import User, UserRole
from .schemas import TokenData
from .security import decode_token


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)) -> User:
    """Récupère l'utilisateur courant à partir du token JWT."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Identifiants invalides ou token expiré.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_token(token)
        user_id = payload.get("sub")
        role_value = payload.get("role")
        if user_id is None or role_value is None:
            raise credentials_exception
        token_data = TokenData(user_id=int(user_id), role=UserRole(role_value))
    except (JWTError, ValueError):
        raise credentials_exception

    user = db.query(User).get(token_data.user_id)
    if not user or not user.is_active:
        raise credentials_exception
    return user


def require_parent(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != UserRole.PARENT:
        raise HTTPException(status_code=403, detail="Accès réservé aux parents.")
    return current_user


def require_gestionnaire(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != UserRole.GESTIONNAIRE:
        raise HTTPException(status_code=403, detail="Accès réservé aux gestionnaires.")
    return current_user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Accès réservé aux administrateurs.")
    return current_user

