from datetime import datetime

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from .database import get_db
from .models import User, DemandeInscription, Enfant, DemandeStatut, UserRole
from .schemas import (
    UserCreate,
    UserRead,
    Token,
    DemandeCreate,
    DemandeRead,
    EnfantCreate,
    EnfantRead,
)
from .security import hash_password, verify_password, create_access_token
from .deps import get_current_user, require_parent, require_gestionnaire


app = FastAPI(
    title="API Colonie de vacances CSS 2026",
    description="Backend FastAPI pour l'inscription en ligne à la colonie de vacances 2026.",
    version="0.1.0",
)


@app.get("/", tags=["général"])
def read_root():
    return {"message": "API Colonie de vacances CSS 2026 - backend opérationnel"}


@app.get("/health", tags=["général"])
def health_check():
    return {"status": "ok"}


@app.get("/users/count", tags=["users"])
def count_users(db: Session = Depends(get_db)):
    """
    Endpoint de test simple pour vérifier la connexion à la base de données.
    Retourne le nombre d'utilisateurs enregistrés dans la table users.
    """
    return {"count": db.query(User).count()}


@app.post("/auth/login", response_model=Token, tags=["auth"])
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    """
    Authentification avec matricule OU email comme username + mot de passe.
    """
    identifiant = form_data.username

    user = (
        db.query(User)
        .filter(
            (User.matricule == identifiant) | (User.email == identifiant)
        )
        .first()
    )

    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identifiants incorrects.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(user_id=user.id, role=user.role)
    return Token(access_token=access_token)


@app.post("/users", response_model=UserRead, status_code=status.HTTP_201_CREATED, tags=["users"])
def create_user(user_in: UserCreate, db: Session = Depends(get_db)):
    """
    Création d'un utilisateur (parent par défaut).
    - Vérifie l'unicité du matricule et de l'email.
    - Hash le mot de passe avant enregistrement.
    """
    # Vérifier l'unicité du matricule
    existing_by_matricule = db.query(User).filter(User.matricule == user_in.matricule).first()
    if existing_by_matricule:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Un utilisateur avec ce matricule existe déjà.",
        )

    # Vérifier l'unicité de l'email si fourni
    if user_in.email:
        existing_by_email = db.query(User).filter(User.email == user_in.email).first()
        if existing_by_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Un utilisateur avec cet email existe déjà.",
            )

    db_user = User(
        matricule=user_in.matricule,
        prenom=user_in.prenom,
        nom=user_in.nom,
        email=user_in.email,
        service=user_in.service,
        role=user_in.role,
        password_hash=hash_password(user_in.password),
        is_active=True,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


# ---------- Demandes ----------


@app.post("/demandes", response_model=DemandeRead, tags=["demandes"])
def create_demande(
    demande_in: DemandeCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_parent),
):
    demande = DemandeInscription(
        user_id=current_user.id,
        statut=DemandeStatut.EN_ATTENTE,
        created_at=datetime.utcnow(),
    )
    db.add(demande)
    db.commit()
    db.refresh(demande)
    return demande


@app.get("/demandes", response_model=list[DemandeRead], tags=["demandes"])
def list_demandes(
    statut: DemandeStatut | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    q = db.query(DemandeInscription)
    if current_user.role == UserRole.PARENT:
        q = q.filter(DemandeInscription.user_id == current_user.id)
    elif statut:
        q = q.filter(DemandeInscription.statut == statut)
    return q.all()


@app.get("/demandes/{demande_id}", response_model=DemandeRead, tags=["demandes"])
def get_demande(
    demande_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    demande = db.query(DemandeInscription).get(demande_id)
    if not demande:
        raise HTTPException(status_code=404, detail="Demande introuvable.")
    if current_user.role == UserRole.PARENT and demande.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Accès interdit à cette demande.")
    return demande


@app.post("/demandes/{demande_id}/valider", response_model=DemandeRead, tags=["demandes"])
def valider_demande(
    demande_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_gestionnaire),
):
    demande = db.query(DemandeInscription).get(demande_id)
    if not demande:
        raise HTTPException(status_code=404, detail="Demande introuvable.")
    demande.statut = DemandeStatut.VALIDEE
    demande.validated_at = datetime.utcnow()
    demande.validated_by = current_user.id
    db.commit()
    db.refresh(demande)
    return demande


@app.post("/demandes/{demande_id}/rejeter", response_model=DemandeRead, tags=["demandes"])
def rejeter_demande(
    demande_id: int,
    motif: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_gestionnaire),
):
    demande = db.query(DemandeInscription).get(demande_id)
    if not demande:
        raise HTTPException(status_code=404, detail="Demande introuvable.")
    demande.statut = DemandeStatut.REJETEE
    demande.motif_refus = motif
    demande.validated_at = datetime.utcnow()
    demande.validated_by = current_user.id
    db.commit()
    db.refresh(demande)
    return demande


# ---------- Enfants ----------


@app.post(
    "/demandes/{demande_id}/enfants",
    response_model=EnfantRead,
    tags=["enfants"],
)
def add_enfant_to_demande(
    demande_id: int,
    enfant_in: EnfantCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_parent),
):
    demande = db.query(DemandeInscription).get(demande_id)
    if not demande:
        raise HTTPException(status_code=404, detail="Demande introuvable.")
    if demande.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Cette demande n'appartient pas au parent connecté.")

    # TODO: règles d'âge, titulaire unique, listes d'attente

    enfant = Enfant(
        demande_id=demande.id,
        prenom=enfant_in.prenom,
        nom=enfant_in.nom,
        date_naissance=enfant_in.date_naissance,
        sexe=enfant_in.sexe,
        lien_parente=enfant_in.lien_parente,
        est_titulaire=enfant_in.est_titulaire,
        liste_attente=0,
    )
    db.add(enfant)
    db.commit()
    db.refresh(enfant)
    return enfant



