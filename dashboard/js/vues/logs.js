/* ==========================================================================
   vues/logs.js, Journal serveur (flux structuré), filtrable, chasse fixe,
   coloration discrète par niveau. Consomme /api/logs.
   ========================================================================== */

import { el, monter } from "../dom.js";
import { icone } from "../icones.js";
import { squelette, etatVide, etatErreur, enteteSection } from "../ui.js";
import { horodatageCourt } from "../format.js";
import { API } from "../api.js";

// Niveau logger -> classe de coloration discrète (jamais criard).
const NIVEAU_CLS = {
  ERROR: "lvl-err",
  WARN: "lvl-warn",
  SUCCESS: "lvl-ok",
  INFO: "lvl-info",
  DEBUG: "lvl-debug",
};

export function creerLogs() {
  let dernier = [];
  const champFiltre = el("input", {
    class: "champ champ-filtre",
    attrs: { type: "search", placeholder: "Filtrer…", "aria-label": "Filtrer le journal", autocomplete: "off" },
    on: { input: () => rendre(dernier) },
  });
  const flux = el("div", { class: "logs-flux", attrs: { role: "log", "aria-live": "off" } });

  const element = el("section", { class: "carte" }, [
    enteteSection("Journal", "terminal", [el("div", { class: "filtre-wrap" }, [icone("search", { taille: 14, classe: "filtre-ico" }), champFiltre])]),
    flux,
  ]);

  function rendre(evenements) {
    dernier = evenements;
    const q = champFiltre.value.trim().toLowerCase();
    const filtres = q
      ? evenements.filter((e) => JSON.stringify(e).toLowerCase().includes(q))
      : evenements;
    if (!filtres.length) {
      monter(flux, etatVide(q ? "Aucune entrée ne correspond au filtre." : "Journal vide."));
      return;
    }
    // Le plus récent en haut.
    const lignes = filtres
      .slice()
      .reverse()
      .map((e) => {
        const niveau = String(e.niveau || e.level || "INFO").toUpperCase();
        return el("div", { class: "log-ligne " + (NIVEAU_CLS[niveau] || "lvl-info") }, [
          el("span", { class: "log-ts mono", text: horodatageCourt(e.timestamp) }),
          el("span", { class: "log-niveau", text: niveau }),
          el("span", { class: "log-type", text: e.type || "" }),
          el("span", { class: "log-msg", text: e.message || "" }),
        ]);
      });
    monter(flux, lignes);
  }

  async function rafraichir() {
    if (!flux.children.length) monter(flux, squelette(4));
    try {
      const d = await API.logs(60);
      rendre(d.evenements || []);
    } catch {
      monter(flux, etatErreur(rafraichir, "Journal indisponible."));
    }
  }

  return { element, rafraichir };
}
