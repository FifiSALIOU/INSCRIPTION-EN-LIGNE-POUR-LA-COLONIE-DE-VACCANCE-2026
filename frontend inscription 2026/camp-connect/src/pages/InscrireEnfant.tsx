import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { ArrowLeft, Save, Baby, User, CheckCircle2, PlusCircle, AlertTriangle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/context/AuthContext";
import { useInscriptions } from "@/context/InscriptionsContext";
import { Badge } from "@/components/ui/badge";
import { LIST_LABELS, RELATION_LABELS, ParentRelation } from "@/types/app";
import { apiRequest } from "@/lib/api";

const InscrireEnfant = () => {
  const { toast } = useToast();
  const navigate = useNavigate();
  const { currentUser } = useAuth();
  const { hasMainChildForParent, createInscription, getParentInscriptions } = useInscriptions();

  const [parentMatricule, setParentMatricule] = useState("");
  const [parentService, setParentService] = useState("");
  const [parentPrenom, setParentPrenom] = useState("");
  const [parentNom, setParentNom] = useState("");
  const [parentUserId, setParentUserId] = useState("");

  const [childPrenom, setChildPrenom] = useState("");
  const [childNom, setChildNom] = useState("");
  const [childBirthDate, setChildBirthDate] = useState("");
  const [childSex, setChildSex] = useState<"masculin" | "feminin" | "">("");
  const [childRelation, setChildRelation] = useState<ParentRelation | "">("");
  const [isLoading, setIsLoading] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [lastResult, setLastResult] = useState<{ ok: boolean; message: string; listType?: string } | null>(null);

  const hasMain = currentUser ? hasMainChildForParent(parentMatricule.trim() || currentUser.matricule) : false;

  useEffect(() => {
    if (currentUser) {
      setParentMatricule(currentUser.matricule);
      setParentService(currentUser.service ?? "");
      setParentPrenom(currentUser.prenom ?? "");
      setParentNom(currentUser.nom ?? "");
      setParentUserId(currentUser.id);
    }
  }, [currentUser?.id]);

  const loadParentByMatricule = async (mat: string) => {
    const trimmed = mat.trim();
    if (!trimmed) {
      setParentService("");
      setParentPrenom("");
      setParentNom("");
      setParentUserId("");
      return;
    }
    const { data, error } = await apiRequest<{ id: number; matricule: string; prenom?: string | null; nom?: string | null; service?: string | null }>(
      `/users/by-matricule/${encodeURIComponent(trimmed)}`,
      { method: "GET" },
    );
    if (error || !data) {
      setParentService("");
      setParentPrenom("");
      setParentNom("");
      setParentUserId("");
      if (error) toast({ title: "Matricule non trouvé", description: error, variant: "destructive" });
      return;
    }
    setParentService(data.service ?? "");
    setParentPrenom(data.prenom ?? "");
    setParentNom(data.nom ?? "");
    setParentUserId(String(data.id));
  };

  if (!currentUser) return null;

  const myInscriptions = getParentInscriptions(parentUserId || currentUser.id);

  const resetChildForm = () => {
    setChildPrenom("");
    setChildNom("");
    setChildBirthDate("");
    setChildSex("");
    setChildRelation("");
    setShowConfirm(false);
    setLastResult(null);
  };

  const handleSubmit = () => {
    if (!parentMatricule.trim() || !parentUserId) {
      toast({ title: "Erreur", description: "Entrez votre matricule et laissez charger vos informations.", variant: "destructive" });
      return;
    }
    if (!childPrenom || !childNom || !childBirthDate || !childSex || !childRelation) {
      toast({ title: "Erreur", description: "Veuillez remplir tous les champs.", variant: "destructive" });
      return;
    }

    setShowConfirm(true);
  };

  const handleConfirm = async () => {
    setIsLoading(true);
    try {
      const result = await createInscription({
        parentUserId: parentUserId || currentUser.id,
        parentMatricule: parentMatricule.trim(),
        parentPrenom: parentPrenom,
        parentNom: parentNom,
        parentService: parentService,
        childPrenom,
        childNom,
        childBirthDate,
        childSex: childSex as "masculin" | "feminin",
        childRelation: childRelation as ParentRelation,
      });
      if (result.ok) {
        toast({ title: "✅ Inscription enregistrée", description: result.message });
        setLastResult({ ok: true, message: result.message, listType: result.inscription?.listType });
      } else {
        toast({ title: "❌ Inscription rejetée", description: result.message, variant: "destructive" });
        setLastResult({ ok: false, message: result.message });
        setShowConfirm(false);
      }
    } finally {
      setIsLoading(false);
    }
  };

  const isTitulaire = !hasMain && childRelation !== "autre";

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <motion.div initial={{ y: -10, opacity: 0 }} animate={{ y: 0, opacity: 1 }}>
        <Button variant="ghost" onClick={() => navigate("/dashboard")} className="mb-2 text-muted-foreground">
          <ArrowLeft className="w-4 h-4 mr-2" /> Retour
        </Button>
        <h1 className="text-2xl lg:text-3xl font-display font-bold">Inscrire un enfant</h1>
        <p className="text-muted-foreground mt-1">Remplissez la fiche d'inscription pour la colonie 2026</p>
      </motion.div>

      {/* Success state: show result and "add another child" */}
      {lastResult?.ok ? (
        <motion.div initial={{ scale: 0.95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }}>
          <Card className="glass-card">
            <CardContent className="p-6 text-center space-y-4">
              <CheckCircle2 className="w-16 h-16 text-success mx-auto" />
              <h2 className="text-xl font-bold">Inscription soumise avec succès !</h2>
              <p className="text-muted-foreground text-sm">{lastResult.message}</p>
              {lastResult.listType && (
                <Badge variant="outline" className="text-sm">{LIST_LABELS[lastResult.listType as keyof typeof LIST_LABELS]}</Badge>
              )}

              <div className="flex flex-col sm:flex-row gap-3 justify-center pt-4">
                <Button onClick={resetChildForm} className="bg-secondary hover:bg-secondary/90 text-secondary-foreground">
                  <PlusCircle className="w-4 h-4 mr-2" /> Inscrire un autre enfant (suppléant)
                </Button>
                <Button variant="outline" onClick={() => navigate("/dashboard/inscriptions")}>
                  Voir mes inscriptions
                </Button>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      ) : (
        <>
          {/* Parent Info : Matricule saisissable, Service/Prénom/Nom chargés depuis la base */}
          <Card className="glass-card">
            <CardHeader>
              <CardTitle className="font-display text-lg flex items-center gap-2">
                <User className="w-5 h-5 text-secondary" /> Informations du Parent
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div className="bg-muted/50 rounded-lg p-3">
                  <p className="text-xs text-muted-foreground">Matricule</p>
                  <Input
                    id="parent-matricule"
                    value={parentMatricule}
                    onChange={(e) => setParentMatricule(e.target.value)}
                    onBlur={() => loadParentByMatricule(parentMatricule)}
                    placeholder="Entrez votre matricule"
                    className="h-8 mt-1 bg-white border border-border shadow-none font-medium placeholder:text-muted-foreground focus-visible:ring-1 focus-visible:ring-secondary"
                  />
                </div>
                <div className="bg-muted/50 rounded-lg p-3">
                  <p className="text-xs text-muted-foreground">Service</p>
                  <p className="font-medium">{parentService || "—"}</p>
                </div>
                <div className="bg-muted/50 rounded-lg p-3">
                  <p className="text-xs text-muted-foreground">Prénom</p>
                  <p className="font-medium">{parentPrenom || "—"}</p>
                </div>
                <div className="bg-muted/50 rounded-lg p-3">
                  <p className="text-xs text-muted-foreground">Nom</p>
                  <p className="font-medium">{parentNom || "—"}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Child Info */}
          <Card className="glass-card">
            <CardHeader>
              <CardTitle className="font-display text-lg flex items-center gap-2">
                <Baby className="w-5 h-5 text-secondary" /> Informations de l'enfant
                {isTitulaire && (
                  <Badge className="ml-2 bg-secondary/10 text-secondary border-secondary/20 text-sm">
                    Enfant titulaire
                  </Badge>
                )}
                {hasMain && childRelation !== "autre" && (
                  <Badge className="ml-2 bg-warning/10 text-warning border-warning/20 text-sm">
                    Liste d'attente N°1 (Suppléant)
                  </Badge>
                )}
                {childRelation === "autre" && (
                  <Badge className="ml-2 bg-muted text-muted-foreground text-sm">
                    Liste d'attente N° 2
                  </Badge>
                )}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <Label>Prénom de l'enfant</Label>
                  <Input value={childPrenom} onChange={(e) => setChildPrenom(e.target.value)} className="bg-background" placeholder="Ex: Ibrahim" />
                </div>
                <div className="space-y-1.5">
                  <Label>Nom de l'enfant</Label>
                  <Input value={childNom} onChange={(e) => setChildNom(e.target.value)} className="bg-background" placeholder="Ex: Hassan" />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <Label>Date de naissance</Label>
                  <Input type="date" value={childBirthDate} onChange={(e) => setChildBirthDate(e.target.value)} className="bg-background" min="2012-01-01" max="2019-12-31" />
                  <p className="text-xs text-muted-foreground">Année entre 2012 et 2019</p>
                </div>
                <div className="space-y-1.5">
                  <Label>Sexe</Label>
                  <Select value={childSex} onValueChange={(val) => setChildSex(val as any)}>
                    <SelectTrigger className="bg-background"><SelectValue placeholder="Choisir..." /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="masculin">Masculin</SelectItem>
                      <SelectItem value="feminin">Féminin</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="space-y-1.5">
                <Label>Lien de parenté</Label>
                <Select value={childRelation} onValueChange={(val) => setChildRelation(val as ParentRelation)}>
                  <SelectTrigger className="bg-background"><SelectValue placeholder="Choisir le lien de parenté..." /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="pere">Père</SelectItem>
                    <SelectItem value="mere">Mère</SelectItem>
                    <SelectItem value="tuteur_legal">Tuteur légal</SelectItem>
                    <SelectItem value="autre">Autre</SelectItem>
                  </SelectContent>
                </Select>
                {childRelation === "autre" && (
                  <div className="mt-2 text-sm text-warning font-medium">
                    Note : L'enfant sera inscrit en liste d'attente N°2
                  </div>
                )}
                {hasMain && childRelation !== "autre" && (
                  <p className="mt-2 text-sm text-warning font-medium">
                    Note : Vous avez déjà un enfant titulaire. Cet enfant sera enregistré comme suppléant.
                  </p>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Previously inscribed children */}
          {myInscriptions.length > 0 && (
            <Card className="glass-card">
              <CardHeader>
                <CardTitle className="font-display text-sm text-muted-foreground">Enfants déjà inscrits ({myInscriptions.length})</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {myInscriptions.map((ins) => (
                  <div key={ins.id} className="flex items-center justify-between rounded-lg bg-muted/50 p-2 text-sm">
                    <span>{ins.childNom} {ins.childPrenom} {ins.isTitulaire && <span className="text-xs font-medium text-secondary">(Titulaire)</span>}</span>
                    <Badge variant="outline" className="text-xs">{LIST_LABELS[ins.listType]}</Badge>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          {/* Confirmation overlay */}
          {showConfirm ? (
            <motion.div initial={{ y: 10, opacity: 0 }} animate={{ y: 0, opacity: 1 }}>
              <Card className="border-secondary/30 glass-card">
                <CardHeader>
                  <CardTitle className="font-display text-lg flex items-center gap-2">
                    <CheckCircle2 className="w-5 h-5 text-secondary" /> Confirmation
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="bg-muted/50 rounded-lg p-4 text-sm space-y-1">
                    <p><span className="text-muted-foreground">Enfant :</span> {childNom} {childPrenom}</p>
                    <p><span className="text-muted-foreground">Né(e) le :</span> {new Date(childBirthDate).toLocaleDateString("fr-FR")}</p>
                    <p><span className="text-muted-foreground">Sexe :</span> {childSex === "masculin" ? "Masculin" : "Féminin"}</p>
                    <p><span className="text-muted-foreground">Lien :</span> {childRelation && RELATION_LABELS[childRelation]}</p>
                  </div>
                  <div className="flex gap-3">
                    <Button variant="outline" onClick={() => setShowConfirm(false)} className="flex-1">Modifier</Button>
                    <Button onClick={handleConfirm} disabled={isLoading} className="flex-1 bg-secondary hover:bg-secondary/90 text-secondary-foreground">
                      {isLoading ? (
                        <div className="flex items-center gap-2">
                          <div className="w-4 h-4 border-2 border-secondary-foreground/30 border-t-secondary-foreground rounded-full animate-spin" />
                          Envoi...
                        </div>
                      ) : (
                        <><Save className="w-4 h-4 mr-2" /> Confirmer</>
                      )}
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          ) : (
            <Button onClick={handleSubmit} className="w-full bg-secondary hover:bg-secondary/90 text-secondary-foreground shadow-lg shadow-secondary/25 h-12">
              Vérifier et soumettre
            </Button>
          )}
        </>
      )}
    </div>
  );
};

export default InscrireEnfant;
