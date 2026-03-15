import { useState } from "react";
import { motion } from "framer-motion";
import { CheckCircle2, XCircle, FileText, Eye } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { useInscriptions } from "@/context/InscriptionsContext";
import { useAuth } from "@/context/AuthContext";
import { LIST_LABELS, RELATION_LABELS, STATUS_BADGE_CLASS, STATUS_LABELS, Inscription } from "@/types/app";

const ListeInscriptions = () => {
  const { inscriptions, reviewInscription } = useInscriptions();
  const { currentUser } = useAuth();
  const [selectedInscription, setSelectedInscription] = useState<Inscription | null>(null);

  const canReview = currentUser?.role === "admin" || currentUser?.role === "super_admin";

  const handleReview = (id: string, status: "validee" | "refusee") => {
    if (!currentUser) return;
    reviewInscription(id, status, currentUser.id);
  };

  return (
    <div className="space-y-6">
      <motion.div initial={{ y: -10, opacity: 0 }} animate={{ y: 0, opacity: 1 }}>
        <h1 className="text-2xl lg:text-3xl font-display font-bold">Liste des inscriptions</h1>
        <p className="text-muted-foreground mt-1">Validation et suivi des demandes reçues.</p>
      </motion.div>

      <Card className="glass-card">
        <CardHeader>
          <CardTitle className="font-display text-lg flex items-center gap-2">
            <FileText className="w-5 h-5 text-secondary" /> Toutes les demandes
          </CardTitle>
        </CardHeader>
        <CardContent>
          {inscriptions.length === 0 ? (
            <p className="text-sm text-muted-foreground">Aucune inscription pour le moment.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Réf.</TableHead>
                  <TableHead>Parent</TableHead>
                  <TableHead>Enfant</TableHead>
                  <TableHead>Naissance</TableHead>
                  <TableHead>Lien</TableHead>
                  <TableHead>Liste</TableHead>
                  <TableHead>Statut</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {inscriptions.map((item) => (
                  <TableRow key={item.id}>
                    <TableCell className="font-mono text-xs">{item.id}</TableCell>
                    <TableCell>
                      <div>
                        <p className="font-medium text-sm">{item.parentNom} {item.parentPrenom}</p>
                        <p className="text-xs text-muted-foreground">{item.parentMatricule} • {item.parentService}</p>
                      </div>
                    </TableCell>
                    <TableCell>{item.childNom} {item.childPrenom}</TableCell>
                    <TableCell>{new Date(item.childBirthDate).toLocaleDateString("fr-FR")}</TableCell>
                    <TableCell>{RELATION_LABELS[item.childRelation]}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-xs">{LIST_LABELS[item.listType]}</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge className={`text-xs ${STATUS_BADGE_CLASS[item.status]}`}>{STATUS_LABELS[item.status]}</Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      {canReview && item.status === "en_attente" ? (
                        <div className="flex justify-end gap-2">
                          <Button size="sm" onClick={() => handleReview(item.id, "validee")} className="bg-success hover:bg-success/90 text-success-foreground">
                            <CheckCircle2 className="w-4 h-4 mr-1" /> Valider
                          </Button>
                          <Button size="sm" variant="outline" onClick={() => handleReview(item.id, "refusee")} className="border-destructive text-destructive hover:bg-destructive/10">
                            <XCircle className="w-4 h-4 mr-1" /> Refuser
                          </Button>
                        </div>
                      ) : (
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => setSelectedInscription(item)}
                          className="text-muted-foreground hover:text-muted-foreground hover:bg-transparent text-xs"
                        >
                          <Eye className="w-3.5 h-3.5 mr-1" /> Voir détails
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Detail Modal */}
      <Dialog open={!!selectedInscription} onOpenChange={() => setSelectedInscription(null)}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle className="font-display">Détails de la demande</DialogTitle>
          </DialogHeader>
          {selectedInscription && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div className="bg-muted/50 rounded-lg p-3">
                  <p className="text-xs text-muted-foreground">Référence</p>
                  <p className="font-mono font-medium">{selectedInscription.id}</p>
                </div>
                <div className="bg-muted/50 rounded-lg p-3">
                  <p className="text-xs text-muted-foreground">Statut</p>
                  <Badge className={`text-xs mt-1 ${STATUS_BADGE_CLASS[selectedInscription.status]}`}>{STATUS_LABELS[selectedInscription.status]}</Badge>
                </div>
                <div className="bg-muted/50 rounded-lg p-3">
                  <p className="text-xs text-muted-foreground">Matricule Parent</p>
                  <p className="font-medium">{selectedInscription.parentMatricule}</p>
                </div>
                <div className="bg-muted/50 rounded-lg p-3">
                  <p className="text-xs text-muted-foreground">Parent</p>
                  <p className="font-medium">{selectedInscription.parentPrenom} {selectedInscription.parentNom}</p>
                </div>
                <div className="bg-muted/50 rounded-lg p-3">
                  <p className="text-xs text-muted-foreground">Service</p>
                  <p className="font-medium">{selectedInscription.parentService}</p>
                </div>
                <div className="bg-muted/50 rounded-lg p-3">
                  <p className="text-xs text-muted-foreground">Enfant</p>
                  <p className="font-medium">{selectedInscription.childPrenom} {selectedInscription.childNom}</p>
                </div>
                <div className="bg-muted/50 rounded-lg p-3">
                  <p className="text-xs text-muted-foreground">Date de naissance</p>
                  <p className="font-medium">{new Date(selectedInscription.childBirthDate).toLocaleDateString("fr-FR")}</p>
                </div>
                <div className="bg-muted/50 rounded-lg p-3">
                  <p className="text-xs text-muted-foreground">Sexe</p>
                  <p className="font-medium">{selectedInscription.childSex === "masculin" ? "Masculin" : "Féminin"}</p>
                </div>
                <div className="bg-muted/50 rounded-lg p-3">
                  <p className="text-xs text-muted-foreground">Lien de parenté</p>
                  <p className="font-medium">{RELATION_LABELS[selectedInscription.childRelation]}</p>
                </div>
                <div className="bg-muted/50 rounded-lg p-3">
                  <p className="text-xs text-muted-foreground">Titulaire</p>
                  <p className="font-medium">{selectedInscription.isTitulaire ? "Oui" : "Non"}</p>
                </div>
                <div className="bg-muted/50 rounded-lg p-3">
                  <p className="text-xs text-muted-foreground">Liste</p>
                  <Badge variant="outline" className="text-xs mt-1">{LIST_LABELS[selectedInscription.listType]}</Badge>
                </div>
                <div className="bg-muted/50 rounded-lg p-3">
                  <p className="text-xs text-muted-foreground">Date de soumission</p>
                  <p className="font-medium">{new Date(selectedInscription.createdAt).toLocaleDateString("fr-FR")}</p>
                </div>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default ListeInscriptions;
