import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { Eye, EyeOff, LogIn, Users } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/context/AuthContext";
import logo from "@/assets/logo.png";

const Login = () => {
  const [matricule, setMatricule] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();
  const { toast } = useToast();
  const { login } = useAuth();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      const result = await login(matricule, password);
      if (result.ok) {
        toast({ title: "Connexion réussie", description: result.message });
        // Laisser React mettre à jour le contexte (currentUser) avant la redirection,
        // sinon RequireAuth voit encore isAuthenticated === false et renvoie vers /login.
        const target =
          result.role === "admin"
            ? "/dashboard/admin"
            : result.role === "super_admin"
              ? "/dashboard/super-admin"
              : "/dashboard";
        setTimeout(() => navigate(target), 0);
      } else {
        toast({ title: "Erreur", description: result.message, variant: "destructive" });
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex">
      {/* Left Panel - Branding */}
      <motion.div
        initial={{ x: -50, opacity: 0 }}
        animate={{ x: 0, opacity: 1 }}
        transition={{ duration: 0.6 }}
        className="hidden lg:flex lg:w-1/2 gradient-hero relative overflow-hidden items-center justify-center p-12"
      >
        <div className="absolute top-[-10%] right-[-10%] w-[500px] h-[500px] rounded-full bg-secondary/10" />
        <div className="absolute bottom-[-15%] left-[-10%] w-[400px] h-[400px] rounded-full bg-secondary/5" />

        <div className="relative z-10 text-center max-w-lg">
          <motion.img
            initial={{ scale: 0.8, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ delay: 0.3, duration: 0.5 }}
            src={logo}
            alt="Logo CSS"
            className="w-32 h-32 mx-auto mb-8 rounded-full shadow-2xl"
          />
          <motion.h1
            initial={{ y: 20, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            transition={{ delay: 0.4, duration: 0.5 }}
            className="text-4xl font-display font-bold text-primary-foreground mb-4"
          >
            Colonie de Vacances
          </motion.h1>
          <motion.p
            initial={{ y: 20, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            transition={{ delay: 0.5, duration: 0.5 }}
            className="text-lg text-primary-foreground/80 mb-2"
          >
            Édition 2026
          </motion.p>
          <motion.div
            initial={{ y: 20, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            transition={{ delay: 0.6, duration: 0.5 }}
            className="flex items-center justify-center gap-2 text-secondary"
          >
            <Users className="w-5 h-5" />
            <span className="text-sm font-medium">Caisse de Sécurité Sociale</span>
          </motion.div>
        </div>
      </motion.div>

      {/* Right Panel - Login Form */}
      <div className="flex-1 flex items-center justify-center p-6 sm:p-12 bg-background">
        <motion.div
          initial={{ x: 50, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          transition={{ duration: 0.6, delay: 0.2 }}
          className="w-full max-w-md"
        >
          <div className="lg:hidden flex flex-col items-center mb-8">
            <img src={logo} alt="Logo CSS" className="w-20 h-20 rounded-full shadow-lg mb-4" />
            <h2 className="text-xl font-display font-bold text-primary">Colonie de Vacances 2026</h2>
          </div>

          <div className="mb-8">
            <h2 className="text-3xl font-display font-bold text-foreground">Connexion</h2>
            <p className="text-muted-foreground mt-2">Entrez votre matricule et mot de passe</p>
          </div>

          <form onSubmit={handleLogin} className="space-y-5">
            <div className="space-y-2">
              <Label htmlFor="matricule" className="text-sm font-medium">N° Matricule ou E-mail</Label>
              <Input
                id="matricule"
                type="text"
                placeholder="Ex: PARENT001"
                value={matricule}
                onChange={(e) => setMatricule(e.target.value)}
                required
                className="h-12 bg-card border-border focus:ring-2 focus:ring-secondary/50"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="password" className="text-sm font-medium">Mot de passe</Label>
              <div className="relative">
                <Input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  className="h-12 bg-card border-border focus:ring-2 focus:ring-secondary/50 pr-12"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
            </div>

            <Button
              type="submit"
              disabled={isLoading}
              className="w-full h-12 bg-secondary hover:bg-secondary/90 text-secondary-foreground font-semibold text-base shadow-lg shadow-secondary/25 transition-all hover:shadow-xl hover:shadow-secondary/30"
            >
              {isLoading ? (
                <div className="flex items-center gap-2">
                  <div className="w-5 h-5 border-2 border-secondary-foreground/30 border-t-secondary-foreground rounded-full animate-spin" />
                  Connexion en cours...
                </div>
              ) : (
                <div className="flex items-center gap-2">
                  <LogIn className="w-5 h-5" />
                  Se connecter
                </div>
              )}
            </Button>
          </form>

          <div className="mt-8 text-center">
            <p className="text-sm text-muted-foreground">
              Vous n'avez pas de compte ?{" "}
              <Link to="/register" className="text-secondary hover:text-secondary/80 font-semibold">
                Créer un compte
              </Link>
            </p>
          </div>

          <div className="mt-12 text-center">
            <p className="text-xs text-muted-foreground/60">
              © 2026 Caisse de Sécurité Sociale — Tous droits réservés
            </p>
          </div>
        </motion.div>
      </div>
    </div>
  );
};

export default Login;
