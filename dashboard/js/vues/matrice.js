/* ==========================================================================
   vues/matrice.js, Matrice MITRE ATT&CK (pièce maîtresse).
   14 tactiques en colonnes, techniques en cellules colorées par le meilleur
   statut réel. Survol = détail ; clic = filtre l'historique sur la technique
   (via un CustomEvent, sans couplage direct entre vues). Consomme /api/matrice.
   ========================================================================== */

import { el, monter } from "../dom.js";
import { squelette, etatErreur, enteteSection } from "../ui.js";
import { nombre } from "../format.js";
import { API } from "../api.js";

// État de couverture d'une technique -> classe + libellé (charte : le sens
// passe par la couleur sémantique, jamais par l'accent de marque).
const ETATS = {
  validee: { cls: "mat-validee", lib: "validée par un cycle réel" },
  testee: { cls: "mat-testee", lib: "testée, pas encore validée" },
  couverte: { cls: "mat-couverte", lib: "au catalogue, jamais exécutée" },
};

export function creerMatrice() {
  const resume = el("p", { class: "matrice-resume", attrs: { role: "status" } });
  const grille = el("div", { class: "matrice", attrs: { role: "list", "aria-label": "Matrice ATT&CK" } });
  const legende = el("div", { class: "matrice-legende" }, [
    legendeItem("mat-validee", "validée"),
    legendeItem("mat-testee", "testée"),
    legendeItem("mat-couverte", "au catalogue"),
    legendeItem("mat-angle", "angle mort"),
    legendeItem("mat-hors", "hors périmètre"),
  ]);
  const element = el("section", { class: "carte carte-matrice" }, [
    enteteSection("Matrice MITRE ATT&CK", "layers", [legende]),
    resume,
    grille,
  ]);

  function rendre(data) {
    const m = data.resume || {};
    resume.textContent =
      nombre(m.techniques_couvertes) +
      " techniques couvertes sur " +
      nombre(m.tactiques_couvertes) +
      "/" +
      nombre(m.tactiques_dans_scope) +
      " tactiques dans le périmètre (" +
      nombre(m.techniques_validees) +
      " déjà validées par un cycle réel).";

    const colonnes = (data.colonnes || []).map((col) => {
      const cellules = (col.techniques || []).map((t) => celluleTechnique(t));
      let corps;
      if (col.hors_scope) {
        corps = el("div", { class: "mat-note", text: "Précède l'accès à la cible, hors périmètre." });
      } else if (!cellules.length) {
        corps = el("div", { class: "mat-note mat-angle-note", text: "Angle mort, aucune attaque." });
      } else {
        corps = el("div", { class: "mat-cells" }, cellules);
      }
      return el(
        "div",
        { class: "mat-col" + (col.hors_scope ? " est-hors" : ""), attrs: { role: "listitem" } },
        [
          el("div", { class: "mat-tete" }, [
            el("span", { class: "mat-tac", text: col.nom }),
            el("span", { class: "mat-cpt", text: (col.id_mitre || "") + " · " + nombre(col.nb) }),
          ]),
          corps,
        ],
      );
    });
    monter(grille, colonnes);
  }

  function celluleTechnique(t) {
    const meta = ETATS[t.etat] || ETATS.couverte;
    const attaques = Array.isArray(t.attaques) ? t.attaques.join(", ") : "";
    const detail =
      t.technique + ", " + (t.nom || "") + "\n" + nombre(t.nb_attaques) + " attaque(s) : " + attaques + "\nÉtat : " + meta.lib;
    return el(
      "button",
      {
        class: "mat-cell " + meta.cls,
        title: detail, // le DOM échappe l'attribut : sûr
        attrs: { type: "button", "aria-label": t.technique + ", " + meta.lib },
        on: {
          click: () =>
            document.dispatchEvent(new CustomEvent("cadre:technique", { detail: { technique: t.technique } })),
        },
      },
      [
        el("span", { class: "mat-cell-id", text: t.technique }),
        t.nb_attaques > 1 ? el("span", { class: "mat-cell-nb", text: "×" + nombre(t.nb_attaques) }) : null,
      ],
    );
  }

  async function rafraichir() {
    if (!grille.children.length) monter(grille, squelette(4));
    try {
      rendre(await API.matrice());
    } catch {
      monter(grille, etatErreur(rafraichir, "Matrice indisponible."));
    }
  }

  return { element, rafraichir };
}

function legendeItem(cls, texte) {
  return el("span", { class: "leg-item" }, [
    el("span", { class: "leg-pastille " + cls, attrs: { "aria-hidden": "true" } }),
    el("span", { text: texte }),
  ]);
}
