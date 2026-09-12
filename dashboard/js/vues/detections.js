/* ==========================================================================
   vues/detections.js, Onglet « Détections ». Règles produites au dernier
   cycle : statut de validation TP/FP et de déploiement Kibana, par technique.
   La règle Sigma complète + la requête Lucene figurent dans le rapport HTML lié
   (le CSV de cycle ne les porte pas). Consomme /api/cycles et /api/cycles/{id}.
   ========================================================================== */

import { el, monter } from "../dom.js";
import { icone } from "../icones.js";
import { pastille, squelette, etatVide, etatErreur, th } from "../ui.js";
import { nombre } from "../format.js";
import { API } from "../api.js";

// Statuts qui correspondent à une détection produite (une règle a été générée).
// EN_ATTENTE_REVUE (cadre cycle --revue) : la règle a bien été générée et
// validée TP/FP, seul le déploiement Kibana est différé pour revue humaine.
const STATUTS_REGLE = ["VALIDE", "VALIDE_NON_DEPLOYE", "EN_ATTENTE_REVUE", "REJETE"];

export function creerDetections() {
  const zone = el("div", {});
  const element = el("div", { class: "vue" }, [zone]);

  function rendre(detail, horodatage) {
    const groupes = detail.groupes || {};
    const lignes = [];
    for (const statut of STATUTS_REGLE) {
      for (const r of groupes[statut] || []) {
        lignes.push(
          el("tr", {}, [
            el("td", { class: "mono", text: r.technique_mitre || "" }),
            el("td", { text: r.description || r.tactique || "" }),
            el("td", {}, [pastille(statut, { court: true })]),
            el("td", { class: "num", text: r.nb_tp ?? "—" }),
            el("td", { class: "num", text: r.nb_fp ?? "—" }),
            el("td", { class: "cell-raison muet", text: r.raison || "" }),
          ]),
        );
      }
    }
    if (!lignes.length) {
      monter(zone, el("section", { class: "carte" }, [etatVide("Aucune règle produite au dernier cycle.")]));
      return;
    }
    monter(zone, [
      el("section", { class: "carte" }, [
        el("div", { class: "section-entete" }, [
          el("h2", { text: "Règles du cycle " + horodatage }),
          el("a", {
            class: "lien-rapport",
            attrs: { href: "/rapports/cycle_" + horodatage + ".html", target: "_blank", rel: "noopener" },
          }, [icone("external-link", { taille: 12 }), el("span", { text: "Rapport complet (règles Sigma + Lucene)" })]),
        ]),
        el("div", { class: "table-wrap" }, [
          el("table", { class: "table-detail" }, [
            el("thead", {}, [
              el("tr", {}, [th("Technique"), th("Description"), th("Statut"), th("TP"), th("FP"), th("Raison")]),
            ]),
            el("tbody", {}, lignes),
          ]),
        ]),
      ]),
    ]);
  }

  async function rafraichir() {
    if (!zone.children.length) monter(zone, el("section", { class: "carte" }, [squelette(4)]));
    try {
      // Endpoint dédié (pas API.cycles()) : seul cycles[0].horodatage est
      // utilisé ici, pas besoin de l'historique complet.
      const c = (await API.dernierCycle()).cycle;
      if (!c) {
        monter(zone, el("section", { class: "carte" }, [etatVide("Aucun cycle exécuté.")]));
        return;
      }
      rendre(await API.cycle(c.horodatage), c.horodatage);
    } catch {
      monter(zone, el("section", { class: "carte" }, [etatErreur(rafraichir, "Détections indisponibles.")]));
    }
  }

  return { element, rafraichir };
}
