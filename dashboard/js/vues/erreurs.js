/* ==========================================================================
   vues/erreurs.js, Onglet « Erreurs & journaux ». Surface les ERREUR /
   ANGLE_MORT / NON_APPLICABLE du dernier cycle AVEC leur cause lisible (c'est
   là qu'on comprend les échecs), puis le journal serveur filtrable en dessous.
   ========================================================================== */

import { el, monter } from "../dom.js";
import { pastille, squelette, etatVide, etatErreur, th } from "../ui.js";
import { API } from "../api.js";
import { creerLogs } from "./logs.js";

// Statuts « à investiguer » : on les remonte en tête avec leur cause.
const STATUTS_PROBLEME = ["ERREUR", "ANGLE_MORT", "NON_APPLICABLE"];

export function creerErreurs() {
  const zoneProblemes = el("div", {});
  const logs = creerLogs();

  const element = el("div", { class: "vue" }, [
    el("section", { class: "carte" }, [
      el("div", { class: "section-entete" }, [el("h2", { text: "Erreurs & angles morts (dernier cycle)" })]),
      zoneProblemes,
    ]),
    logs.element,
  ]);

  function rendre(detail) {
    const groupes = detail.groupes || {};
    const lignes = [];
    for (const statut of STATUTS_PROBLEME) {
      for (const r of groupes[statut] || []) {
        lignes.push(
          el("tr", {}, [
            el("td", {}, [pastille(statut, { court: true })]),
            el("td", { class: "mono", text: r.technique_mitre || "" }),
            el("td", { text: r.description || "" }),
            el("td", { class: "cell-raison", text: r.raison || r.raison_validation || "—" }),
          ]),
        );
      }
    }
    if (!lignes.length) {
      monter(zoneProblemes, etatVide("Aucune erreur ni angle mort au dernier cycle."));
      return;
    }
    monter(zoneProblemes, [
      el("div", { class: "table-wrap" }, [
        el("table", { class: "table-detail" }, [
          el("thead", {}, [
            el("tr", {}, [th("Statut"), th("Technique"), th("Description"), th("Cause")]),
          ]),
          el("tbody", {}, lignes),
        ]),
      ]),
    ]);
  }

  async function rafraichir() {
    logs.rafraichir();
    if (!zoneProblemes.children.length) monter(zoneProblemes, squelette(3));
    try {
      // Endpoint dédié (pas API.cycles()) : seul cycles[0].horodatage est
      // utilisé ici, pas besoin de l'historique complet.
      const c = (await API.dernierCycle()).cycle;
      if (!c) {
        monter(zoneProblemes, etatVide("Aucun cycle exécuté."));
        return;
      }
      rendre(await API.cycle(c.horodatage));
    } catch {
      monter(zoneProblemes, etatErreur(rafraichir, "Détail indisponible."));
    }
  }

  return { element, rafraichir };
}
