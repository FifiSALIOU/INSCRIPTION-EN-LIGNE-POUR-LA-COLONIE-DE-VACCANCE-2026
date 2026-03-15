from datetime import datetime

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from .database import get_db
from .models import User, DemandeInscription, Enfant, DemandeStatut, UserRole, LienParenteEnum
from .schemas import (
    UserCreate,
    UserRead,
    AdminCreateUser,
    UserStatusUpdate,
    Token,
    DemandeCreate,
    DemandeRead,
    DemandeReadWithUser,
    EnfantCreate,
    EnfantRead,
)
from .security import hash_password, verify_password, create_access_token
from .deps import get_current_user, require_parent, require_gestionnaire, require_admin


app = FastAPI(
    title="API Colonie de vacances CSS 2026",
    description="Backend FastAPI pour l'inscription en ligne à la colonie de vacances 2026.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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


@app.get("/me", response_model=UserRead, tags=["auth"])
def me(current_user: User = Depends(get_current_user)):
    """Retourne l'utilisateur connecté."""
    return current_user


@app.get("/users/by-matricule/{matricule}", response_model=UserRead, tags=["users"])
def get_user_by_matricule(
    matricule: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retourne un utilisateur par son matricule.
    Un parent ne peut récupérer que son propre profil (matricule identique au sien).
    """
    matricule_norm = matricule.strip().upper()
    if current_user.role == UserRole.PARENT and matricule_norm != current_user.matricule.strip().upper():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Accès non autorisé à ce matricule.")
    user = db.query(User).filter(func.upper(User.matricule) == matricule_norm).first()
    if not user:
        raise HTTPException(status_code=404, detail="Aucun utilisateur avec ce matricule.")
    return user


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


# ---------- Admin : gestion des utilisateurs ----------


@app.get("/admin/users", response_model=list[UserRead], tags=["admin"])
def admin_list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """
    Liste tous les utilisateurs (parents, gestionnaires, admins).
    Accès réservé à l'ADMIN.
    """
    return db.query(User).all()


@app.post("/admin/users", response_model=UserRead, status_code=status.HTTP_201_CREATED, tags=["admin"])
def admin_create_user(
    user_in: AdminCreateUser,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """
    Création d'un utilisateur par l'ADMIN (quel que soit le rôle).
    - Vérifie l'unicité du matricule et de l'email.
    """
    existing_by_matricule = db.query(User).filter(User.matricule == user_in.matricule).first()
    if existing_by_matricule:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Un utilisateur avec ce matricule existe déjà.",
        )

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


@app.patch("/admin/users/{user_id}", response_model=UserRead, tags=["admin"])
def admin_update_user_status(
    user_id: int,
    payload: UserStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """
    Active ou désactive un compte utilisateur.
    Accès réservé à l'ADMIN.
    """
    user = db.query(User).get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable.")

    user.is_active = payload.is_active
    db.commit()
    db.refresh(user)
    return user


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


@app.get("/demandes", response_model=list[DemandeReadWithUser], tags=["demandes"])
def list_demandes(
    statut: DemandeStatut | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    q = db.query(DemandeInscription).options(joinedload(DemandeInscription.user))
    if current_user.role == UserRole.PARENT:
        q = q.filter(DemandeInscription.user_id == current_user.id)
    elif statut:
        q = q.filter(DemandeInscription.statut == statut)
    demandes = q.all()
    return [
        DemandeReadWithUser(**DemandeRead.model_validate(d).model_dump(), user=d.user)
        for d in demandes
    ]


# ---------- Gestionnaire : vues spécialisées sur les demandes ----------


@app.get("/gestionnaire/demandes/en_attente", response_model=list[DemandeRead], tags=["gestionnaire"])
def gestionnaire_demandes_en_attente(
    service: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_gestionnaire),
):
    """
    Liste les demandes en attente.
    Optionnellement filtrées par service du parent.
    """
    q = db.query(DemandeInscription).join(User, DemandeInscription.user_id == User.id)
    q = q.filter(DemandeInscription.statut == DemandeStatut.EN_ATTENTE)
    if service:
        q = q.filter(User.service == service)
    return q.all()


@app.get("/gestionnaire/demandes/validees", response_model=list[DemandeRead], tags=["gestionnaire"])
def gestionnaire_demandes_validees(
    service: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_gestionnaire),
):
    """
    Liste les demandes validées.
    Optionnellement filtrées par service du parent.
    """
    q = db.query(DemandeInscription).join(User, DemandeInscription.user_id == User.id)
    q = q.filter(DemandeInscription.statut == DemandeStatut.VALIDEE)
    if service:
        q = q.filter(User.service == service)
    return q.all()


@app.get("/gestionnaire/demandes/rejetees", response_model=list[DemandeRead], tags=["gestionnaire"])
def gestionnaire_demandes_rejetees(
    service: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_gestionnaire),
):
    """
    Liste les demandes rejetées.
    Optionnellement filtrées par service du parent.
    """
    q = db.query(DemandeInscription).join(User, DemandeInscription.user_id == User.id)
    q = q.filter(DemandeInscription.statut == DemandeStatut.REJETEE)
    if service:
        q = q.filter(User.service == service)
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

    # ----- Règle d'âge (condition inéluctable) -----
    annee_naissance = enfant_in.date_naissance.year
    if not (2012 <= annee_naissance <= 2019):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inscription rejetée : l'année de naissance doit être comprise entre 2012 et 2019.",
        )

    # ----- Règle titulaire -----
    # On enlève la possibilité de choisir un autre titulaire :
    # - si c'est le 1er enfant de la demande => titulaire
    # - sinon => pas titulaire (suppléant)
    nb_enfants_demande = (
        db.query(Enfant)
        .filter(Enfant.demande_id == demande.id)
        .count()
    )
    est_titulaire = nb_enfants_demande == 0

    # ----- Calcul de liste_attente -----
    if est_titulaire:
        liste_attente = 0  # liste principale
    else:
        if enfant_in.lien_parente == LienParenteEnum.AUTRE:
            liste_attente = 2  # liste d'attente n°2
        else:
            liste_attente = 1  # liste d'attente n°1

    # ----- Calcul de position_liste -----
    nb_deja_dans_liste = (
        db.query(Enfant)
        .filter(
            Enfant.demande_id == demande.id,
            Enfant.liste_attente == liste_attente,
        )
        .count()
    )
    position_liste = nb_deja_dans_liste + 1

    enfant = Enfant(
        demande_id=demande.id,
        prenom=enfant_in.prenom,
        nom=enfant_in.nom,
        date_naissance=enfant_in.date_naissance,
        sexe=enfant_in.sexe,
        lien_parente=enfant_in.lien_parente,
        est_titulaire=est_titulaire,
        liste_attente=liste_attente,
        position_liste=position_liste,
    )
    db.add(enfant)
    db.commit()
    db.refresh(enfant)
    return enfant



