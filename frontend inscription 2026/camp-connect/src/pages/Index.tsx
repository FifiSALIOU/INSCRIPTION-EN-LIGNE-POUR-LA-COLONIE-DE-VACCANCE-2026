import { motion } from "framer-motion";
import { ArrowRight, Users, Shield, Calendar, Star, ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { useNavigate } from "react-router-dom";
import logo from "@/assets/logo.png";

const features = [
  { icon: Users, title: "Inscription Simplifiée", description: "Inscrivez vos enfants en quelques clics depuis votre espace personnel" },
  { icon: Shield, title: "Sécurisé & Fiable", description: "Vos données sont protégées et accessibles uniquement par le personnel autorisé" },
  { icon: Calendar, title: "Suivi en Temps Réel", description: "Consultez l'état de vos inscriptions et recevez des notifications instantanées" },
  { icon: Star, title: "Gestion des Listes", description: "Liste principale et listes d'attente gérées automatiquement et de façon équitable" },
];

const Index = () => {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-background">
      {/* Navbar */}
      <nav className="sticky top-0 z-50 bg-card/80 backdrop-blur-lg border-b">
        <div className="container mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <img src={logo} alt="Logo CSS" className="w-10 h-10 rounded-full" />
            <span className="font-bold text-lg text-foreground">CSS Colonie</span>
          </div>
          <div className="flex items-center gap-3">
            <Button variant="ghost" onClick={() => navigate("/login")}>Connexion</Button>
            <Button onClick={() => navigate("/register")} className="bg-secondary hover:bg-secondary/90 text-secondary-foreground">
              S'inscrire
            </Button>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="relative gradient-hero overflow-hidden">
        <div className="absolute inset-0">
          <div className="absolute top-[-20%] right-[-10%] w-[600px] h-[600px] rounded-full bg-secondary/5" />
          <div className="absolute bottom-[-20%] left-[-5%] w-[400px] h-[400px] rounded-full bg-secondary/3" />
        </div>
        <div className="container mx-auto px-4 py-20 lg:py-32 relative z-10">
          <div className="max-w-2xl mx-auto text-center">
            <motion.div initial={{ y: 30, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ duration: 0.7 }}>
              <div className="inline-flex items-center gap-2 bg-secondary/20 text-secondary rounded-full px-4 py-1.5 mb-6 text-sm font-medium">
                <Star className="w-4 h-4" />
                Inscriptions ouvertes — Édition 2026
              </div>
              <h1 className="text-4xl lg:text-6xl font-display font-bold text-primary-foreground leading-tight mb-6">
                Colonie de Vacances <span className="text-secondary">CSS 2026</span>
              </h1>
              <p className="text-lg text-primary-foreground/80 mb-8 max-w-lg mx-auto">
                Offrez à vos enfants des vacances inoubliables. Inscrivez-les dès maintenant à la colonie de vacances de la Caisse de Sécurité Sociale.
              </p>
              <div className="flex flex-col sm:flex-row gap-4 justify-center">
                <Button
                  size="lg"
                  onClick={() => navigate("/register")}
                  className="bg-secondary hover:bg-secondary/90 text-secondary-foreground text-lg px-8 h-14 shadow-xl shadow-secondary/30"
                >
                  Inscrire mon enfant <ArrowRight className="w-5 h-5 ml-2" />
                </Button>
                <Button
                  size="lg"
                  variant="outline"
                  onClick={() => navigate("/login")}
                  className="bg-transparent border-primary-foreground/30 text-primary-foreground hover:bg-primary-foreground/10 h-14 text-lg"
                >
                  J'ai déjà un compte
                </Button>
              </div>
            </motion.div>

            <motion.div
              initial={{ y: 40, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              transition={{ delay: 0.4, duration: 0.6 }}
              className="mt-16 grid grid-cols-3 gap-6"
            >
              {[
                { value: "500+", label: "Enfants chaque année" },
                { value: "15", label: "Jours d'activités" },
                { value: "98%", label: "Parents satisfaits" },
              ].map((s) => (
                <div key={s.label} className="bg-white/10 backdrop-blur-sm rounded-2xl p-4 lg:p-6">
                  <p className="text-2xl lg:text-4xl font-bold text-secondary">{s.value}</p>
                  <p className="text-xs lg:text-sm text-primary-foreground/70 mt-1">{s.label}</p>
                </div>
              ))}
            </motion.div>
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="py-16 lg:py-24 container mx-auto px-4">
        <motion.div initial={{ y: 20, opacity: 0 }} whileInView={{ y: 0, opacity: 1 }} viewport={{ once: true }} className="text-center mb-12">
          <h2 className="text-3xl lg:text-4xl font-display font-bold text-foreground mb-4">
            Pourquoi choisir notre plateforme ?
          </h2>
          <p className="text-muted-foreground max-w-md mx-auto">
            Une solution moderne et intuitive pour gérer les inscriptions à la colonie de vacances
          </p>
        </motion.div>

        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
          {features.map((f, i) => (
            <motion.div key={f.title} initial={{ y: 30, opacity: 0 }} whileInView={{ y: 0, opacity: 1 }} viewport={{ once: true }} transition={{ delay: i * 0.1 }}>
              <Card className="glass-card h-full hover:shadow-xl transition-all group hover:-translate-y-1">
                <CardContent className="p-6">
                  <div className="w-12 h-12 rounded-xl bg-secondary/10 flex items-center justify-center mb-4 group-hover:bg-secondary/20 transition-colors">
                    <f.icon className="w-6 h-6 text-secondary" />
                  </div>
                  <h3 className="font-semibold text-lg mb-2">{f.title}</h3>
                  <p className="text-sm text-muted-foreground">{f.description}</p>
                </CardContent>
              </Card>
            </motion.div>
          ))}
        </div>
      </section>

      {/* CTA */}
      <section className="py-16 lg:py-20">
        <div className="container mx-auto px-4">
          <motion.div initial={{ y: 20, opacity: 0 }} whileInView={{ y: 0, opacity: 1 }} viewport={{ once: true }}>
            <Card className="gradient-accent border-0 overflow-hidden relative">
              <div className="absolute top-[-50%] right-[-10%] w-[400px] h-[400px] rounded-full bg-white/5" />
              <CardContent className="p-8 lg:p-12 relative z-10 flex flex-col lg:flex-row items-center gap-8">
                <div className="flex-1 text-center lg:text-left">
                  <h2 className="text-3xl lg:text-4xl font-display font-bold text-accent-foreground mb-3">
                    Les inscriptions sont ouvertes !
                  </h2>
                  <p className="text-accent-foreground/80 text-lg">
                    Du 15 Juillet au 30 Juillet 2026 — Ne manquez pas cette opportunité unique.
                  </p>
                </div>
                <Button
                  size="lg"
                  onClick={() => navigate("/register")}
                  className="bg-primary hover:bg-primary/90 text-primary-foreground h-14 px-8 text-lg shadow-xl"
                >
                  Commencer l'inscription <ChevronRight className="w-5 h-5 ml-1" />
                </Button>
              </CardContent>
            </Card>
          </motion.div>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-primary text-primary-foreground py-8">
        <div className="container mx-auto px-4 flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <img src={logo} alt="Logo CSS" className="w-8 h-8 rounded-full" />
            <span className="font-semibold">CSS Colonie de Vacances 2026</span>
          </div>
          <p className="text-sm text-primary-foreground/60">
            © 2026 Caisse de Sécurité Sociale — Tous droits réservés
          </p>
        </div>
      </footer>
    </div>
  );
};

export default Index;
