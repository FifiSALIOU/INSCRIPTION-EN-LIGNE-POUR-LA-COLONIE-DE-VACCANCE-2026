from datetime import datetime, timedelta
import os
from typing import Optional

from jose import jwt
from passlib.context import CryptContext

from .models import UserRole


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = os.getenv("SECRET_KEY", "change-me")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))


def hash_password(password: str) -> str:
    """Retourne le hash sécurisé du mot de passe."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Vérifie qu'un mot de passe en clair correspond à son hash."""
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(
    user_id: int,
    role: UserRole,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Crée un JWT contenant l'id utilisateur et son rôle."""
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode = {"sub": str(user_id), "role": role.value, "exp": expire}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    """Décode un JWT et retourne son payload."""
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

