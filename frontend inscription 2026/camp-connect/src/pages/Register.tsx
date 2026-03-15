import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { Eye, EyeOff, UserPlus, ArrowLeft } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/context/AuthContext";
import logo from "@/assets/logo.png";

const Register = () => {
  const [formData, setFormData] = useState({
    nom: "",
    prenom: "",
    matricule: "",
    email: "",
    service: "",
    password: "",
    confirmPassword: "",
  });
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();
  const { toast } = useToast();
  const { registerParent } = useAuth();

  const handleChange = (field: string, value: string) => {
    setFormData((prev) => ({ ...prev, [field]: value }));
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (formData.password !== formData.confirmPassword) {
      toast({ title: "Erreur", description: "Les mots de passe ne correspondent pas", variant: "destructive" });
      return;
    }

    setIsLoading(true);
    try {
      const result = await registerParent({
        matricule: formData.matricule,
        prenom: formData.prenom,
        nom: formData.nom,
        email: formData.email,
        service: formData.service,
        password: formData.password,
      });
      if (result.ok) {
        toast({ title: "Compte créé", description: result.message });
        navigate("/login");
      } else {
        toast({ title: "Erreur", description: result.message, variant: "destructive" });
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex">
      <motion.div
        initial={{ x: -50, opacity: 0 }}
        animate={{ x: 0, opacity: 1 }}
        transition={{ duration: 0.6 }}
        className="hidden lg:flex lg:w-2/5 gradient-hero relative overflow-hidden items-center justify-center p-12"
      >
        <div className="absolute top-[-10%] right-[-10%] w-[400px] h-[400px] rounded-full bg-secondary/10" />
        <div className="absolute bottom-[-15%] left-[-10%] w-[300px] h-[300px] rounded-full bg-secondary/5" />

        <div className="relative z-10 text-center max-w-sm">
          <img src={logo} alt="Logo CSS" className="w-28 h-28 mx-auto mb-6 rounded-full shadow-2xl" />
          <h1 className="text-3xl font-display font-bold text-primary-foreground mb-3">Rejoignez-nous</h1>
          <p className="text-primary-foreground/80 mb-8">
            Inscrivez vos enfants à la colonie de vacances 2026 de la CSS
          </p>
          <div className="space-y-3 text-left">
            {[
              "Inscription rapide et sécurisée",
              "Suivi en temps réel de votre dossier",
              "Gestion simplifiée de vos enfants",
            ].map((item, i) => (
              <motion.div
                key={i}
                initial={{ x: -20, opacity: 0 }}
                animate={{ x: 0, opacity: 1 }}
                transition={{ delay: 0.5 + i * 0.15 }}
                className="flex items-center gap-3 text-primary-foreground/90"
              >
                <div className="w-2 h-2 rounded-full bg-secondary flex-shrink-0" />
                <span className="text-sm">{item}</span>
              </motion.div>
            ))}
          </div>
        </div>
      </motion.div>

      <div className="flex-1 flex items-center justify-center p-6 sm:p-8 bg-background overflow-y-auto">
        <motion.div
          initial={{ x: 50, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          transition={{ duration: 0.6, delay: 0.2 }}
          className="w-full max-w-lg"
        >
          <Link to="/login" className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground mb-6">
            <ArrowLeft className="w-4 h-4" />
            Retour à la connexion
          </Link>

          <div className="lg:hidden flex flex-col items-center mb-6">
            <img src={logo} alt="Logo CSS" className="w-16 h-16 rounded-full shadow-lg mb-3" />
          </div>

          <div className="mb-6">
            <h2 className="text-3xl font-display font-bold text-foreground">Créer un compte</h2>
            <p className="text-muted-foreground mt-1">Remplissez vos informations pour commencer</p>
          </div>

          <form onSubmit={handleRegister} className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label htmlFor="matricule">N° Matricule</Label>
                <Input id="matricule" placeholder="CSS-XXXX" value={formData.matricule} onChange={(e) => handleChange("matricule", e.target.value)} required className="h-11 bg-card" />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="service">Service / Direction</Label>
                <Input id="service" placeholder="Ex: Prestations Sociales" value={formData.service} onChange={(e) => handleChange("service", e.target.value)} required className="h-11 bg-card" />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label htmlFor="prenom">Prénom</Label>
                <Input id="prenom" placeholder="Mohamed" value={formData.prenom} onChange={(e) => handleChange("prenom", e.target.value)} required className="h-11 bg-card" />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="nom">Nom</Label>
                <Input id="nom" placeholder="AHMED" value={formData.nom} onChange={(e) => handleChange("nom", e.target.value)} required className="h-11 bg-card" />
              </div>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="email">Adresse email</Label>
              <Input id="email" type="email" placeholder="email@example.com" value={formData.email} onChange={(e) => handleChange("email", e.target.value)} className="h-11 bg-card" />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label htmlFor="password">Mot de passe</Label>
                <div className="relative">
                  <Input id="password" type={showPassword ? "text" : "password"} placeholder="••••••••" value={formData.password} onChange={(e) => handleChange("password", e.target.value)} required className="h-11 bg-card pr-10" />
                  <button type="button" onClick={() => setShowPassword(!showPassword)} className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground">
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="confirmPassword">Confirmer</Label>
                <Input id="confirmPassword" type="password" placeholder="••••••••" value={formData.confirmPassword} onChange={(e) => handleChange("confirmPassword", e.target.value)} required className="h-11 bg-card" />
              </div>
            </div>

            <Button type="submit" disabled={isLoading} className="w-full h-12 bg-secondary hover:bg-secondary/90 text-secondary-foreground font-semibold shadow-lg shadow-secondary/25 mt-2">
              {isLoading ? (
                <div className="flex items-center gap-2">
                  <div className="w-5 h-5 border-2 border-secondary-foreground/30 border-t-secondary-foreground rounded-full animate-spin" />
                  Création en cours...
                </div>
              ) : (
                <div className="flex items-center gap-2">
                  <UserPlus className="w-5 h-5" />
                  Créer mon compte
                </div>
              )}
            </Button>
          </form>

          <p className="mt-6 text-center text-sm text-muted-foreground">
            Déjà inscrit ?{" "}
            <Link to="/login" className="text-secondary hover:text-secondary/80 font-semibold">Se connecter</Link>
          </p>
        </motion.div>
      </div>
    </div>
  );
};

export default Register;
