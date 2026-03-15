import { motion } from "framer-motion";
import { AlertTriangle, Download } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useInscriptions } from "@/context/InscriptionsContext";
import { STATUS_BADGE_CLASS, STATUS_LABELS } from "@/types/app";
import { exportToPDF, exportToExcel } from "@/lib/export";

const calculateAge = (birthDate: string) => {
  const birth = new Date(birthDate);
  const now = new Date();
  let age = now.getFullYear() - birth.getFullYear();
  const m = now.getMonth() - birth.getMonth();
  if (m < 0 || (m === 0 && now.getDate() < birth.getDate())) age--;
  return age;
};

const GestionListeAttente2 = () => {
  const { inscriptions } = useInscriptions();
  const items = inscriptions.filter((i) => i.listType === "attente_2");

  const exportData = items.map((item) => ({
    Matricule: item.parentMatricule,
    "Nom du parent": item.parentNom,
    "Prénom du parent": item.parentPrenom,
    Service: item.parentService,
    "Nom de l'enfant": item.childNom,
    "Prénom de l'enfant": item.childPrenom,
    Âge: `${calculateAge(item.childBirthDate)} ans`,
    Sexe: item.childSex === "masculin" ? "M" : "F",
    Statut: STATUS_LABELS[item.status],
  }));

  return (
    <div className="space-y-6">
      <motion.div initial={{ y: -10, opacity: 0 }} animate={{ y: 0, opacity: 1 }}>
        <h1 className="text-2xl lg:text-3xl font-display font-bold">Liste d'attente N°2</h1>
        <p className="text-muted-foreground mt-1">Enfants avec lien de parenté « Autre ».</p>
      </motion.div>

      <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.1 }}>
        <Card className="glass-card">
          <CardHeader className="pb-3 flex flex-row items-center justify-between">
            <CardTitle className="font-display text-lg flex items-center gap-3">
              <Badge className="bg-destructive/10 text-destructive border-destructive/20 px-3 py-1 text-sm font-semibold">
                <AlertTriangle className="w-4 h-4 mr-1.5" />
                Liste d'attente N°2
              </Badge>
              <span className="text-sm font-normal text-muted-foreground">Lien « Autre »</span>
              <Badge variant="outline" className="ml-2">{items.length}</Badge>
            </CardTitle>
            <div className="flex gap-2">
              <Button size="sm" variant="outline" onClick={() => exportToPDF(exportData, "Liste d'attente N°2", ["Matricule", "Nom du parent", "Prénom du parent", "Service", "Nom de l'enfant", "Prénom de l'enfant", "Âge", "Sexe", "Statut"])}>
                <Download className="w-3.5 h-3.5 mr-1.5" /> PDF
              </Button>
              <Button size="sm" variant="outline" onClick={() => exportToExcel(exportData, "Liste_attente_N2")}>
                <Download className="w-3.5 h-3.5 mr-1.5" /> Excel
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            {items.length === 0 ? (
              <p className="text-sm text-muted-foreground italic py-4 text-center">Aucune entrée</p>
            ) : (
              <div className="rounded-lg overflow-hidden border">
                <Table>
                  <TableHeader>
                    <TableRow className="bg-primary text-primary-foreground hover:bg-primary">
                      <TableHead className="text-primary-foreground font-bold text-xs uppercase tracking-wider">Matricule</TableHead>
                      <TableHead className="text-primary-foreground font-bold text-xs uppercase tracking-wider">Nom du parent</TableHead>
                      <TableHead className="text-primary-foreground font-bold text-xs uppercase tracking-wider">Prénom du parent</TableHead>
                      <TableHead className="text-primary-foreground font-bold text-xs uppercase tracking-wider">Service</TableHead>
                      <TableHead className="text-primary-foreground font-bold text-xs uppercase tracking-wider">Nom de l'enfant</TableHead>
                      <TableHead className="text-primary-foreground font-bold text-xs uppercase tracking-wider">Prénom de l'enfant</TableHead>
                      <TableHead className="text-primary-foreground font-bold text-xs uppercase tracking-wider">Âge</TableHead>
                      <TableHead className="text-primary-foreground font-bold text-xs uppercase tracking-wider">Sexe</TableHead>
                      <TableHead className="text-primary-foreground font-bold text-xs uppercase tracking-wider">Statut</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {items.map((item) => (
                      <TableRow key={item.id} className="hover:bg-muted/50">
                        <TableCell className="font-mono text-xs">{item.parentMatricule}</TableCell>
                        <TableCell className="text-sm">{item.parentNom}</TableCell>
                        <TableCell className="text-sm">{item.parentPrenom}</TableCell>
                        <TableCell className="text-sm">{item.parentService}</TableCell>
                        <TableCell className="text-sm font-medium">{item.childNom}</TableCell>
                        <TableCell className="text-sm font-medium">{item.childPrenom}</TableCell>
                        <TableCell className="text-sm">{calculateAge(item.childBirthDate)} ans</TableCell>
                        <TableCell className="text-sm">{item.childSex === "masculin" ? "M" : "F"}</TableCell>
                        <TableCell>
                          <Badge className={`text-xs ${STATUS_BADGE_CLASS[item.status]}`}>{STATUS_LABELS[item.status]}</Badge>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
};

export default GestionListeAttente2;
