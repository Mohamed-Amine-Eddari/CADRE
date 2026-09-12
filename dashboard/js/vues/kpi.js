/* ==========================================================================
   vues/kpi.js, Bandeau d'indicateurs clés (vue phare pour le jury).
   Chiffres grands, libellés discrets, note contextuelle sous chaque valeur.
   Consomme /api/metriques.
   ========================================================================== */

import { el, monter } from "../dom.js";
import { squelette, etatErreur, enteteSection } from "../ui.js";
import { nombre } from "../format.js";
import { API } from "../api.js";

// Définition déclarative des KPI : chaque entrée sait extraire sa valeur et
// sa note depuis la réponse /api/metriques.
const KPIS = [
  {
    cle: "regles",
    libelle: "Règles produites",
    valeur: (m) => nombre(m.regles_produites),
    note: (m) => "taux de réussite " + fmtPct(m.taux_reussite_pct) + " · " + nombre(m.applicables) + " applicables",
  },
  {
    cle: "temps",
    libelle: "Temps d'ingénierie économisé",
    valeur: (m) => (m.temps_gagne_heures != null ? "~" + nombre(m.temps_gagne_heures) + " h" : "—"),
    note: (m) => "≈ " + nombre(m.temps_gagne_jours_ouvres) + " j-homme · hyp. " + nombre(m.hypothese_heures_par_regle) + " h/règle",
  },
  {
    cle: "couverture",
    libelle: "Tactiques MITRE couvertes",
    valeur: (m) => nombre(m.tactiques_couvertes),
    note: (m) => fmtPct(m.couverture_tactiques_pct) + " du périmètre",
  },
  {
    cle: "fp",
    libelle: "Faux positifs médians",
    valeur: (m) => (m.faux_positifs_median != null ? nombre(m.faux_positifs_median) : "—"),
    note: () => "sur 7 jours, par règle validée",
  },
];

function fmtPct(v) {
  return v == null ? "—" : nombre(Math.round(v)) + " %";
}

export function creerKpi() {
  const grille = el("div", { class: "kpi-grille" });
  const element = el("section", { class: "carte" }, [
    enteteSection("Indicateurs clés", "activity"),
    grille,
  ]);

  function rendre(m) {
    const cartes = KPIS.map((k) =>
      el("div", { class: "kpi" }, [
        el("div", { class: "kpi-val", text: k.valeur(m) }),
        el("div", { class: "kpi-lib", text: k.libelle }),
        el("div", { class: "kpi-note", text: k.note(m) }),
      ]),
    );
    monter(grille, cartes);
  }

  async function rafraichir() {
    // Squelette seulement au premier chargement (grille vide) -- ce
    // panneau est sondé toutes les 9s tant que l'onglet Vue d'ensemble est
    // actif (app.js) ; sans cette garde, la « vue phare pour le jury »
    // clignotait en boucle vers un état de chargement à chaque sondage,
    // même quand les indicateurs n'avaient pas changé. Même patron que
    // toutes les autres vues (jauge/dernier dans vue-ensemble.js, etc.).
    if (!grille.children.length) {
      monter(grille, squelette(1));
      grille.querySelector(".squelette")?.classList.add("squelette-kpi");
    }
    try {
      rendre(await API.metriques());
    } catch {
      monter(grille, etatErreur(rafraichir, "Indicateurs indisponibles (aucun cycle exécuté ?)."));
    }
  }

  return { element, rafraichir };
}
