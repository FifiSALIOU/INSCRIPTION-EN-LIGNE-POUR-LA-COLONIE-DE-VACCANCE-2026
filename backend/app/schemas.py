from datetime import datetime, date
from typing import Optional, List

from pydantic import BaseModel, EmailStr, Field

from .models import UserRole, DemandeStatut, SexeEnum, LienParenteEnum


class UserBase(BaseModel):
    matricule: str = Field(..., max_length=20)
    prenom: Optional[str] = Field(None, max_length=100)
    nom: Optional[str] = Field(None, max_length=100)
    email: Optional[EmailStr] = None
    service: Optional[str] = Field(None, max_length=100)


class UserCreate(UserBase):
    password: str = Field(..., min_length=6, max_length=128)
    role: UserRole = UserRole.PARENT


class UserRead(UserBase):
    id: int
    role: UserRole
    is_active: bool
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    user_id: int
    role: UserRole


class LoginRequest(BaseModel):
    identifiant: str
    password: str


class EnfantBase(BaseModel):
    prenom: str
    nom: str
    date_naissance: date
    sexe: SexeEnum
    lien_parente: LienParenteEnum
    est_titulaire: bool = False


class EnfantCreate(EnfantBase):
    pass


class EnfantRead(EnfantBase):
    id: int
    position_liste: Optional[int] = None
    liste_attente: int

    class Config:
        from_attributes = True


class DemandeCreate(BaseModel):
    pass


class DemandeRead(BaseModel):
    id: int
    statut: Optional[DemandeStatut] = None
    motif_refus: Optional[str] = None
    created_at: Optional[datetime] = None
    submitted_at: Optional[datetime] = None
    validated_at: Optional[datetime] = None
    enfants: List[EnfantRead] = []

    class Config:
        from_attributes = True

