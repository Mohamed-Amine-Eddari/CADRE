/* ==========================================================================
   vues/derive.js, Onglet « Dérive ». Compare la mesure la plus récente de
   chaque attaque à sa première mesure connue sur les cycles archivés --
   repère qu'une règle déjà validée se dégrade (perte de détection totale,
   ou dérive de bruit) sans attendre qu'elle finisse par échouer en silence.
   Consomme /api/derive (délègue à metriques.detecter_derive_toutes_regles).
   ========================================================================== */

import { el, monter } from "../dom.js";
import { pastille, etatVide, etatErreur, squelette, th } from "../ui.js";
import { nombre } from "../format.js";
import { API } from "../api.js";

// Les plus préoccupants d'abord -- une console SOC surface ce qui a besoin
// d'attention, pas un ordre alphabétique.
const ORDRE_GRAVITE = { PERTE_DETECTION: 0, DERIVE_BRUIT: 1, STABLE: 2 };

export function creerDerive() {
  const zone = el("div", {});
  const element = el("div", { class: "vue" }, [zone]);

  function rendre(derives) {
    const entrees = Object.entries(derives).sort(
      (a, b) => (ORDRE_GRAVITE[a[1].statut] ?? 9) - (ORDRE_GRAVITE[b[1].statut] ?? 9),
    );
    if (!entrees.length) {
      monter(
        zone,
        el("section", { class: "carte" }, [
          etatVide(
            "Pas encore assez d'historique. Une attaque doit avoir été validée dans au moins 2 cycles archivés pour apparaître ici.",
          ),
        ]),
      );
      return;
    }
    const lignes = entrees.map(([id, d]) =>
      el("tr", {}, [
        el("td", { class: "mono", text: id }),
        el("td", {}, [pastille(d.statut)]),
        el("td", { class: "num", text: nombre(d.nb_mesures) }),
        el("td", { class: "num", text: `TP=${d.premiere.nb_tp} FP=${d.premiere.nb_fp}` }),
        el("td", { class: "num", text: `TP=${d.derniere.nb_tp} FP=${d.derniere.nb_fp}` }),
      ]),
    );
    monter(zone, [
      el("section", { class: "carte" }, [
        el("div", { class: "section-entete" }, [
          el("div", { class: "section-titre" }, [el("h2", { text: "Historique de dérive" })]),
        ]),
        el("div", { class: "table-wrap" }, [
          el("table", { class: "table-detail" }, [
            el("thead", {}, [
              el("tr", {}, [
                th("Attaque"),
                th("Statut"),
                th("Mesures"),
                th("Première mesure"),
                th("Dernière mesure"),
              ]),
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
      const { derives } = await API.derive();
      rendre(derives || {});
    } catch {
      monter(zone, el("section", { class: "carte" }, [etatErreur(rafraichir, "Historique de dérive indisponible.")]));
    }
  }

  return { element, rafraichir };
}
