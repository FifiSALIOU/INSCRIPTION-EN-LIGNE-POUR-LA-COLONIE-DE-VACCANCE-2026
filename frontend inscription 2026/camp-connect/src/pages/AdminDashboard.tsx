import { useState } from "react";
import { motion } from "framer-motion";
import { ClipboardCheck, Clock3, XCircle, CheckCircle2, Eye } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { useInscriptions } from "@/context/InscriptionsContext";
import { useAuth } from "@/context/AuthContext";
import { RELATION_LABELS, STATUS_BADGE_CLASS, STATUS_LABELS, LIST_LABELS, Inscription } from "@/types/app";

type TabType = "en_attente" | "validee" | "refusee";

const AdminDashboard = () => {
  const { inscriptions, reviewInscription } = useInscriptions();
  const { currentUser } = useAuth();
  const [activeTab, setActiveTab] = useState<TabType>("en_attente");
  const [selectedInscription, setSelectedInscription] = useState<Inscription | null>(null);

  const pending = inscriptions.filter((i) => i.status === "en_attente");
  const approved = inscriptions.filter((i) => i.status === "validee");
  const rejected = inscriptions.filter((i) => i.status === "refusee");

  const tabs = [
    { key: "en_attente" as TabType, label: "Demandes en attente", count: pending.length, icon: Clock3, tone: "text-warning" },
    { key: "validee" as TabType, label: "Demandes validées", count: approved.length, icon: ClipboardCheck, tone: "text-success" },
    { key: "refusee" as TabType, label: "Demandes refusées", count: rejected.length, icon: XCircle, tone: "text-destructive" },
  ];

  const currentItems = activeTab === "en_attente" ? pending : activeTab === "validee" ? approved : rejected;

  const handleReview = (id: string, status: "validee" | "refusee") => {
    if (!currentUser) return;
    reviewInscription(id, status, currentUser.id);
  };

  return (
    <div className="space-y-6">
      <motion.div initial={{ y: -10, opacity: 0 }} animate={{ y: 0, opacity: 1 }}>
        <h1 className="text-2xl lg:text-3xl font-display font-bold">Espace Gestionnaire</h1>
        <p className="text-muted-foreground mt-1">Gérez la validation des inscriptions et les listes.</p>
      </motion.div>

      {/* KPI Cards - no colored border on active */}
      <div className="grid gap-4 md:grid-cols-3">
        {tabs.map((tab, index) => (
          <motion.div key={tab.key} initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: index * 0.1 }}>
            <Card
              className={`glass-card cursor-pointer transition-all hover:shadow-lg`}
              onClick={() => setActiveTab(tab.key)}
            >
              <CardContent className="p-5 flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">{tab.label}</p>
                  <p className="text-3xl font-bold mt-1">{tab.count}</p>
                </div>
                <tab.icon className={`w-8 h-8 ${tab.tone}`} />
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      {/* Tab Content - Table */}
      <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.3 }}>
        <Card className="glass-card">
          <CardContent className="p-0">
            {/* Tab bar */}
            <div className="flex border-b">
              {tabs.map((tab) => (
                <button
                  key={tab.key}
                  onClick={() => setActiveTab(tab.key)}
                  className={`flex-1 py-3.5 px-4 text-sm font-medium transition-all relative ${
                    activeTab === tab.key
                      ? "text-secondary"
                      : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {tab.label} ({tab.count})
                  {activeTab === tab.key && (
                    <motion.div layoutId="adminTab" className="absolute bottom-0 left-0 right-0 h-0.5 bg-secondary" />
                  )}
                </button>
              ))}
            </div>

            {/* Table */}
            <div className="p-4">
              {currentItems.length === 0 ? (
                <p className="text-sm text-muted-foreground text-center py-8 italic">Aucune demande dans cette catégorie.</p>
              ) : (
                <div className="rounded-lg overflow-hidden border">
                  <Table>
                    <TableHeader>
                      <TableRow className="bg-primary text-primary-foreground hover:bg-primary">
                        <TableHead className="text-primary-foreground font-bold text-xs uppercase tracking-wider">Matricule Parent</TableHead>
                        <TableHead className="text-primary-foreground font-bold text-xs uppercase tracking-wider">Nom Parent</TableHead>
                        <TableHead className="text-primary-foreground font-bold text-xs uppercase tracking-wider">Prénom Enfant</TableHead>
                        <TableHead className="text-primary-foreground font-bold text-xs uppercase tracking-wider">Nom Enfant</TableHead>
                        <TableHead className="text-primary-foreground font-bold text-xs uppercase tracking-wider">Date Naissance</TableHead>
                        <TableHead className="text-primary-foreground font-bold text-xs uppercase tracking-wider">Titulaire</TableHead>
                        <TableHead className="text-primary-foreground font-bold text-xs uppercase tracking-wider">Lien Parenté</TableHead>
                        <TableHead className="text-primary-foreground font-bold text-xs uppercase tracking-wider">Statut</TableHead>
                        <TableHead className="text-primary-foreground font-bold text-xs uppercase tracking-wider">Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {currentItems.map((item) => (
                        <TableRow key={item.id} className="hover:bg-muted/50">
                          <TableCell className="font-mono text-xs">{item.parentMatricule}</TableCell>
                          <TableCell className="text-sm">{item.parentNom}</TableCell>
                          <TableCell className="text-sm">{item.childPrenom}</TableCell>
                          <TableCell className="text-sm">{item.childNom}</TableCell>
                          <TableCell className="text-sm">{new Date(item.childBirthDate).toLocaleDateString("fr-FR")}</TableCell>
                          <TableCell className="text-sm">
                            <span className="inline-flex items-center gap-1.5">
                              <span className="w-4 shrink-0 text-center">{item.isTitulaire ? "✓" : ""}</span>
                              <span>{item.isTitulaire ? "Oui" : "Non"}</span>
                            </span>
                          </TableCell>
                          <TableCell className="text-sm">{RELATION_LABELS[item.childRelation]}</TableCell>
                          <TableCell>
                            <Badge className={`text-xs ${STATUS_BADGE_CLASS[item.status]}`}>{STATUS_LABELS[item.status]}</Badge>
                          </TableCell>
                          <TableCell>
                            {item.status === "en_attente" ? (
                              <div className="flex gap-2">
                                <Button size="sm" onClick={() => handleReview(item.id, "validee")} className="bg-success hover:bg-success/90 text-success-foreground h-8 px-3 text-xs">
                                  <CheckCircle2 className="w-3.5 h-3.5 mr-1" /> Valider
                                </Button>
                                <Button size="sm" variant="outline" onClick={() => handleReview(item.id, "refusee")} className="border-destructive text-destructive hover:bg-destructive/10 h-8 px-3 text-xs">
                                  <XCircle className="w-3.5 h-3.5 mr-1" /> Refuser
                                </Button>
                              </div>
                            ) : (
                              <Button
                                size="sm"
                                variant="ghost"
                                onClick={() => setSelectedInscription(item)}
                                className="text-muted-foreground hover:text-muted-foreground hover:bg-transparent h-8 px-3 text-xs"
                              >
                                <Eye className="w-3.5 h-3.5 mr-1" /> Voir détails
                              </Button>
                            )}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </motion.div>

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

export default AdminDashboard;
