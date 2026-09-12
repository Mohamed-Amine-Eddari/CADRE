/* ==========================================================================
   dom.js, Helpers DOM SÛRS (protection XSS structurelle)
   --------------------------------------------------------------------------
   Règle absolue du projet : AUCUNE donnée dynamique n'entre dans le DOM via
   innerHTML. Tout passe par createElement + textContent. Ces helpers rendent
   ce style aussi court qu'une template literal, sans jamais interpréter de
   HTML. `innerHTML` n'apparaît nulle part dans js/, c'est une invariante
   testée (voir tests/test_dashboard.py).
   ========================================================================== */

/**
 * Crée un élément. `options.text` est posé en textContent (jamais interprété).
 * Les enfants peuvent être des nœuds ou des chaînes (converties en TextNode).
 *
 * el("span", { class: "x", text: donneeUtilisateur })  // sûr par construction
 */
export function el(tag, options = {}, ...enfants) {
  const noeud = document.createElement(tag);
  const { text, class: cls, className, attrs, dataset, on, title } = options;
  if (cls || className) noeud.className = cls || className;
  if (title != null) noeud.title = String(title); // attribut, échappé par le DOM
  if (text != null) noeud.textContent = String(text); // JAMAIS innerHTML
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v != null && v !== false) noeud.setAttribute(k, v === true ? "" : String(v));
    }
  }
  if (dataset) {
    for (const [k, v] of Object.entries(dataset)) noeud.dataset[k] = String(v);
  }
  if (on) {
    for (const [evt, fn] of Object.entries(on)) noeud.addEventListener(evt, fn);
  }
  for (const enfant of enfants.flat()) {
    if (enfant == null || enfant === false) continue;
    noeud.append(enfant.nodeType ? enfant : document.createTextNode(String(enfant)));
  }
  return noeud;
}

/** Pose une valeur texte de façon sûre (équivaut à textContent). */
export function texte(noeud, valeur) {
  noeud.textContent = valeur == null ? "" : String(valeur);
}

/** Vide un conteneur (sans innerHTML = ""). */
export function vider(noeud) {
  while (noeud.firstChild) noeud.removeChild(noeud.firstChild);
}

/** Remplace le contenu d'un conteneur par de nouveaux nœuds. */
export function monter(cible, ...noeuds) {
  vider(cible);
  for (const n of noeuds.flat()) if (n != null && n !== false) cible.append(n);
}

/** Fragment de plusieurs nœuds (pour un append unique). */
export function frag(...noeuds) {
  const f = document.createDocumentFragment();
  for (const n of noeuds.flat()) if (n != null && n !== false) f.append(n);
  return f;
}

/** Raccourci de sélection. */
export function $(sel, racine = document) {
  return racine.querySelector(sel);
}

/**
 * Bouton « copier » réutilisable pour les valeurs techniques (Lucene, Sigma,
 * command_line…). La valeur n'est jamais interprétée : elle est copiée telle
 * quelle dans le presse-papier.
 */
export function boutonCopier(valeur, libelle = "Copier") {
  const btn = el("button", {
    class: "btn-copier",
    attrs: { type: "button", "aria-label": libelle, title: libelle },
    on: {
      click: async () => {
        try {
          await navigator.clipboard.writeText(valeur);
          btn.classList.add("est-copie");
          setTimeout(() => btn.classList.remove("est-copie"), 1200);
        } catch {
          /* presse-papier indisponible : on ignore silencieusement */
        }
      },
    },
  });
  // icône posée par l'appelant (import icones.js) pour éviter un cycle d'import
  btn.dataset.copier = "1";
  return btn;
}
