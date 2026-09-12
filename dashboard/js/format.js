/* ==========================================================================
   format.js, Métadonnées de statut et formatage lisible (dates, nombres).
   La sémantique des 6 statuts finaux du pipeline vit ici, une seule fois.
   ========================================================================== */

// Statut -> libellé FR + classe CSS (la couleur est portée par la classe,
// définie dans composants.css à partir des jetons --st-*).
export const STATUT = {
  VALIDE: { label: "Validée & déployée", cls: "valide" },
  VALIDE_NON_DEPLOYE: { label: "Validée, non déployée", cls: "valide-nd" },
  REJETE: { label: "Rejetée (FN ou trop de FP)", cls: "rejete" },
  ANGLE_MORT: { label: "Angle mort (rien capté)", cls: "angle" },
  ERREUR: { label: "Erreur pipeline", cls: "erreur" },
  NON_APPLICABLE: { label: "Non applicable", cls: "na" },
  EN_COURS: { label: "En cours", cls: "encours" },
  SIMULE: { label: "Simulée", cls: "simule" },
  // Découverte IA (cadre decouvrir --revue) : validée TP/FP mais pas encore
  // déployée dans Kibana tant qu'un humain n'a pas approuvé -- accent
  // ("action vivante"), pas vert (rien n'est déployé) ni gris (pas une erreur).
  EN_ATTENTE_REVUE: { label: "En attente de revue", cls: "encours" },
  // Statuts de dérive (cadre derive / vue "Dérive") -- réutilisent les
  // mêmes classes/couleurs sémantiques que les statuts de cycle ci-dessus,
  // pas de nouvelle teinte : stable = vert (valide), dérive de bruit =
  // ambre (rejete), perte de détection = rouge (angle, même sévérité
  // qu'un angle mort classique).
  STABLE: { label: "Stable", cls: "valide" },
  DERIVE_BRUIT: { label: "Dérive de bruit", cls: "rejete" },
  PERTE_DETECTION: { label: "Perte de détection", cls: "angle" },
  // Verdicts de `cadre valider-regle` (onglet Outils) -- mêmes couleurs que
  // la CLI (couleurs Rich : NON_COMPILABLE/BRUYANTE rouges, SILENCIEUSE
  // ambre, ACTIVE verte). "erreur" (gris) est réservé à ERREUR pipeline --
  // le rouge sémantique existant est "angle" (--st-angle), réutilisé ici.
  NON_COMPILABLE: { label: "Non compilable", cls: "angle" },
  SILENCIEUSE: { label: "Silencieuse (0 correspondance)", cls: "rejete" },
  BRUYANTE: { label: "Bruyante (trop de correspondances)", cls: "angle" },
  ACTIVE: { label: "Active", cls: "valide" },
};

export function metaStatut(statut) {
  return STATUT[statut] || { label: statut || "—", cls: "erreur" };
}

// Libellé court pour cellules denses (matrice, tables).
export function labelCourt(statut) {
  return (
    {
      VALIDE: "Validée",
      VALIDE_NON_DEPLOYE: "Non déployée",
      REJETE: "Rejetée",
      ANGLE_MORT: "Angle mort",
      ERREUR: "Erreur",
      NON_APPLICABLE: "N/A",
      EN_COURS: "En cours",
      SIMULE: "Simulée",
      EN_ATTENTE_REVUE: "En attente de revue",
      STABLE: "Stable",
      DERIVE_BRUIT: "Dérive bruit",
      PERTE_DETECTION: "Perte détection",
      NON_COMPILABLE: "Non compilable",
      SILENCIEUSE: "Silencieuse",
      BRUYANTE: "Bruyante",
      ACTIVE: "Active",
    }[statut] || statut
  );
}

// "2026-08-07T09:12:00" ou "20260807_091200" -> "il y a 2 min".
export function tempsRelatif(valeur) {
  const d = parseDate(valeur);
  if (!d) return "";
  const s = Math.round((Date.now() - d.getTime()) / 1000);
  if (s < 0) return "à l'instant";
  if (s < 60) return "il y a " + s + " s";
  const m = Math.floor(s / 60);
  if (m < 60) return "il y a " + m + " min";
  const h = Math.floor(m / 60);
  if (h < 24) return "il y a " + h + " h";
  const j = Math.floor(h / 24);
  return "il y a " + j + " j";
}

// Horodatage absolu lisible, court.
export function horodatageCourt(valeur) {
  const d = parseDate(valeur);
  if (!d) return String(valeur ?? "");
  const p = (n) => String(n).padStart(2, "0");
  return (
    p(d.getDate()) + "/" + p(d.getMonth() + 1) + " " + p(d.getHours()) + ":" + p(d.getMinutes())
  );
}

function parseDate(valeur) {
  if (!valeur) return null;
  const s = String(valeur);
  // Format horodatage cycle : 20260807_091200
  const m = s.match(/^(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})$/);
  if (m) return new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d;
}

// Nombre lisible (espace fine comme séparateur de milliers, à la française).
export function nombre(n) {
  if (n == null || isNaN(n)) return "—";
  return new Intl.NumberFormat("fr-FR").format(n);
}
