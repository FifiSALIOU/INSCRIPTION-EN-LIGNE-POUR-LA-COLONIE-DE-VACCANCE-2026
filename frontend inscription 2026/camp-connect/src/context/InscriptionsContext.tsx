import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { Inscription, InscriptionStatus, ListType, ParentRelation } from "@/types/app";
import { useAuth } from "@/context/AuthContext";
import { apiRequest, getToken } from "@/lib/api";

export const getNextListType = (
  hasMainChild: boolean,
  relation: ParentRelation | "",
): ListType => {
  if (relation === "autre") return "attente_2";
  if (hasMainChild) return "attente_1";
  return "principale";
};

interface CreateInscriptionInput {
  parentUserId: string;
  parentMatricule: string;
  parentPrenom: string;
  parentNom: string;
  parentService: string;
  childPrenom: string;
  childNom: string;
  childBirthDate: string;
  childSex: "masculin" | "feminin";
  childRelation: ParentRelation;
}

interface InscriptionsContextValue {
  inscriptions: Inscription[];
  hasMainChildForParent: (matricule: string) => boolean;
  getParentInscriptions: (parentUserId: string) => Inscription[];
  createInscription: (input: CreateInscriptionInput) => Promise<{ ok: boolean; message: string; inscription?: Inscription }>;
  reviewInscription: (id: string, status: Exclude<InscriptionStatus, "en_attente">, reviewerUserId: string, motif?: string) => void;
  refetchInscriptions: () => Promise<void>;
}

const listTypeFromListeAttente = (n: number): ListType =>
  n === 0 ? "principale" : n === 1 ? "attente_1" : "attente_2";

const statusFromBackend = (s: string): InscriptionStatus =>
  s === "rejetee" ? "refusee" : (s as InscriptionStatus);

const sexeToFrontend = (s: string): "masculin" | "feminin" =>
  s === "F" ? "feminin" : "masculin";

const lienToFrontend = (s: string): ParentRelation => {
  if (s === "Pere") return "pere";
  if (s === "Mere") return "mere";
  if (s === "Tuteur_legal") return "tuteur_legal";
  return "autre";
};

type DemandeReadUser = {
  id: number;
  matricule: string;
  prenom?: string | null;
  nom?: string | null;
  service?: string | null;
};

type DemandeRead = {
  id: number;
  statut?: string;
  created_at?: string;
  user?: DemandeReadUser;
  enfants: Array<{
    id: number;
    prenom: string;
    nom: string;
    date_naissance: string;
    sexe: string;
    lien_parente: string;
    est_titulaire: boolean;
    liste_attente: number;
  }>;
};

const InscriptionsContext = createContext<InscriptionsContextValue | null>(null);

export const InscriptionsProvider = ({ children }: { children: React.ReactNode }) => {
  const { currentUser } = useAuth();
  const [inscriptions, setInscriptions] = useState<Inscription[]>([]);

  const refetchInscriptions = useCallback(async () => {
    if (!currentUser || !getToken()) return;
    const { data } = await apiRequest<DemandeRead[]>("/demandes", { method: "GET" });
    if (!data || !Array.isArray(data)) {
      setInscriptions([]);
      return;
    }
    const list: Inscription[] = [];
    for (const d of data) {
      const parent = d.user ?? currentUser;
      const parentUserId = String(parent.id);
      const statut = d.statut ? statusFromBackend(d.statut) : "en_attente";
      for (const e of d.enfants || []) {
        list.push({
          id: `${d.id}-${e.id}`,
          parentUserId,
          parentMatricule: parent.matricule,
          parentPrenom: parent.prenom ?? "",
          parentNom: parent.nom ?? "",
          parentService: parent.service ?? "",
          childPrenom: e.prenom,
          childNom: e.nom,
          childBirthDate: e.date_naissance,
          childSex: sexeToFrontend(e.sexe),
          childRelation: lienToFrontend(e.lien_parente),
          isTitulaire: e.est_titulaire,
          listType: listTypeFromListeAttente(e.liste_attente),
          status: statut,
          createdAt: d.created_at ?? new Date().toISOString(),
        });
      }
    }
    setInscriptions(list);
  }, [currentUser]);

  useEffect(() => {
    refetchInscriptions();
  }, [currentUser?.id, refetchInscriptions]);

  const hasMainChildForParent = useCallback(
    (matricule: string) =>
      inscriptions.some((item) => item.parentMatricule === matricule && item.listType === "principale"),
    [inscriptions],
  );

  const getParentInscriptions = useCallback(
    (parentUserId: string) => inscriptions.filter((item) => item.parentUserId === parentUserId),
    [inscriptions],
  );

  const createInscription = useCallback(
    async (input: CreateInscriptionInput): Promise<{ ok: boolean; message: string; inscription?: Inscription }> => {
      const year = Number(input.childBirthDate.split("-")[0]);
      if (!Number.isFinite(year) || year < 2012 || year > 2019) {
        return {
          ok: false,
          message: `Inscription rejetée : année de naissance invalide (${year || "inconnue"}). Doit être entre 2012 et 2019.`,
        };
      }
      const { data: demandes } = await apiRequest<DemandeRead[]>("/demandes", { method: "GET" });
      let demandeId: number | null = null;
      if (demandes && demandes.length > 0) {
        const demandeEnAttente = demandes.find((d) => statusFromBackend(d.statut ?? "en_attente") === "en_attente");
        if (demandeEnAttente) {
          demandeId = demandeEnAttente.id;
        }
      }
      if (demandeId === null) {
        const { data: newDemande, error: errCreate } = await apiRequest<DemandeRead>("/demandes", {
          method: "POST",
          body: JSON.stringify({}),
        });
        if (errCreate || !newDemande) {
          return { ok: false, message: errCreate ?? "Impossible de créer la demande." };
        }
        demandeId = newDemande.id;
      }
      const sexe = input.childSex === "masculin" ? "M" : "F";
      const lien =
        input.childRelation === "pere"
          ? "Pere"
          : input.childRelation === "mere"
            ? "Mere"
            : input.childRelation === "tuteur_legal"
              ? "Tuteur_legal"
              : "Autre";
      const body = {
        prenom: input.childPrenom,
        nom: input.childNom,
        date_naissance: input.childBirthDate,
        sexe,
        lien_parente: lien,
        est_titulaire: false,
      };
      const { data: enfant, error } = await apiRequest<{
        id: number;
        prenom: string;
        nom: string;
        date_naissance: string;
        sexe: string;
        lien_parente: string;
        est_titulaire: boolean;
        liste_attente: number;
      }>(`/demandes/${demandeId}/enfants`, { method: "POST", body: JSON.stringify(body) });
      if (error) return { ok: false, message: error };
      if (!enfant) return { ok: false, message: "Réponse serveur invalide." };
      const listType = listTypeFromListeAttente(enfant.liste_attente);
      const inscription: Inscription = {
        id: `${demandeId}-${enfant.id}`,
        parentUserId: input.parentUserId,
        parentMatricule: input.parentMatricule,
        parentPrenom: input.parentPrenom,
        parentNom: input.parentNom,
        parentService: input.parentService,
        childPrenom: input.childPrenom,
        childNom: input.childNom,
        childBirthDate: input.childBirthDate,
        childSex: input.childSex,
        childRelation: input.childRelation,
        isTitulaire: listType === "principale",
        listType,
        status: "en_attente",
        createdAt: new Date().toISOString(),
      };
      await refetchInscriptions();
      return { ok: true, message: "Demande enregistrée avec succès.", inscription };
    },
    [refetchInscriptions],
  );

  const reviewInscription = useCallback(
    (id: string, status: Exclude<InscriptionStatus, "en_attente">, _reviewerUserId: string, motif?: string) => {
      const parts = id.split("-");
      const demandeId = parts[0];
      if (!demandeId) return;
      const path =
        status === "validee"
          ? `/demandes/${demandeId}/valider`
          : `/demandes/${demandeId}/rejeter?motif=${encodeURIComponent(motif ?? "Refusé")}`;
      apiRequest(path, { method: "POST" }).then(() => {
        refetchInscriptions();
      });
    },
    [refetchInscriptions],
  );

  const value = useMemo<InscriptionsContextValue>(
    () => ({
      inscriptions,
      hasMainChildForParent,
      getParentInscriptions,
      createInscription,
      reviewInscription,
      refetchInscriptions,
    }),
    [inscriptions, hasMainChildForParent, getParentInscriptions, createInscription, reviewInscription, refetchInscriptions],
  );

  return <InscriptionsContext.Provider value={value}>{children}</InscriptionsContext.Provider>;
};

export const useInscriptions = () => {
  const context = useContext(InscriptionsContext);
  if (!context) throw new Error("useInscriptions doit être utilisé dans InscriptionsProvider.");
  return context;
};
