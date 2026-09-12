/* ==========================================================================
   vues/vue-ensemble.js, Onglet « Vue d'ensemble ».
   Bannière de cycle en cours (progression réelle) + indicateurs clés +
   jauge d'avancement du projet (couverture ATT&CK) + résumé du dernier cycle.
   ========================================================================== */

import { el, monter } from "../dom.js";
import { enteteSection, pastille, squelette, etatVide, etatErreur } from "../ui.js";
import { nombre, tempsRelatif } from "../format.js";
import { API } from "../api.js";
import { creerKpi } from "./kpi.js";

export function creerVueEnsemble() {
  const kpi = creerKpi();
  const banniere = el("div", { class: "banniere-cycle", attrs: { hidden: true, role: "status" } });
  const jauge = el("div", { class: "jauges" });
  const dernier = el("div", { class: "dernier-cycle" });

  const element = el("div", { class: "vue" }, [
    banniere,
    kpi.element,
    el("section", { class: "carte" }, [enteteSection("Avancement du projet"), jauge]),
    el("section", { class: "carte" }, [enteteSection("Dernier cycle"), dernier]),
  ]);

  // Largeur des barres via une classe utilitaire (w0..w100 par pas de 5) —
  // 100% CSP-safe (aucun style inline, que du style-src 'self').
  function largeurClasse(pct) {
    return "w" + Math.max(0, Math.min(100, Math.round(pct / 5) * 5));
  }

  async function majBanniere() {
    try {
      const s = await API.cycleStatut();
      const p = s.progression || {};
      if (s.en_cours && p.total) {
        const pct = Math.round((p.faites / p.total) * 100);
        const piste = el("div", { class: "barre-piste" }, [
          el("div", { class: "barre-remplie encours " + largeurClasse(pct) }),
        ]);
        monter(banniere, [
          el("div", { class: "banniere-tete" }, [
            el("span", { class: "pastille st-encours" }, [
              el("span", { class: "pastille-point" }),
              el("span", { text: "Cycle " + (s.mode || "") + " en cours" }),
            ]),
            el("span", {
              class: "banniere-detail",
              text: p.faites + "/" + p.total + " · " + (p.technique || "") + " · étape " + (p.etape || 0) + "/9 " + (p.etape_nom || ""),
            }),
          ]),
          piste,
        ]);
        banniere.hidden = false;
      } else {
        banniere.hidden = true;
      }
    } catch {
      banniere.hidden = true;
    }
  }

  async function majJauge() {
    try {
      const m = (await API.matrice()).resume || {};
      const pctTac = m.tactiques_dans_scope
        ? Math.round((m.tactiques_couvertes / m.tactiques_dans_scope) * 100)
        : 0;
      monter(jauge, [
        ligneJauge("Tactiques couvertes", m.tactiques_couvertes, m.tactiques_dans_scope, pctTac),
        ligneJauge("Techniques validées (cycle réel)", m.techniques_validees, m.techniques_couvertes, m.techniques_couvertes ? Math.round((m.techniques_validees / m.techniques_couvertes) * 100) : 0),
      ]);
    } catch {
      // Échec réseau/backend distinct de "0 technique couverte" (etatVide) --
      // l'utilisateur doit pouvoir réessayer, pas croire que le projet n'a
      // aucune couverture.
      monter(jauge, etatErreur(majJauge, "Couverture indisponible."));
    }
  }

  function ligneJauge(libelle, valeur, total, pct) {
    return el("div", { class: "jauge" }, [
      el("div", { class: "jauge-tete" }, [
        el("span", { class: "jauge-lib", text: libelle }),
        el("span", { class: "jauge-val mono", text: nombre(valeur) + " / " + nombre(total) + " (" + pct + "%)" }),
      ]),
      el("div", { class: "barre-piste" }, [el("div", { class: "barre-remplie " + largeurClasse(pct) })]),
    ]);
  }

  async function majDernier() {
    try {
      // Endpoint dédié (pas API.cycles()) : ne lit que le CSV du dernier
      // cycle côté serveur, pas tout l'historique pour n'en garder qu'un.
      const c = (await API.dernierCycle()).cycle;
      if (!c) {
        monter(dernier, etatVide("Aucun cycle exécuté."));
        return;
      }
      const segs = Object.entries(c.compteurs || {}).map(([st, n]) =>
        el("span", { class: "rep-seg" }, [pastille(st, { court: true }), el("span", { class: "rep-n", text: nombre(n) })]),
      );
      monter(dernier, [
        el("div", { class: "dernier-tete" }, [
          el("span", { class: "mono", text: c.horodatage }),
          el("span", { class: "muet", text: tempsRelatif(c.horodatage) }),
          el("span", { class: "muet", text: nombre(c.total) + " techniques" }),
        ]),
        el("div", { class: "repartition" }, segs),
      ]);
    } catch {
      // Idem majJauge : échec réseau/backend, pas "aucun cycle exécuté".
      monter(dernier, etatErreur(majDernier, "Dernier cycle indisponible."));
    }
  }

  async function rafraichir() {
    if (!jauge.children.length) monter(jauge, squelette(2));
    if (!dernier.children.length) monter(dernier, squelette(2));
    kpi.rafraichir();
    await Promise.all([majBanniere(), majJauge(), majDernier()]);
  }

  return { element, rafraichir };
}
