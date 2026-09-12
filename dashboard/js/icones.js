/* ==========================================================================
   icones.js, Jeu d'icônes linéaires (style Feather/Lucide) créées en SVG
   via createElementNS. AUCUN emoji, AUCUNE image distante. `currentColor`
   hérite de la couleur du texte → l'icône prend le sens de son contexte.
   ========================================================================== */

const NS = "http://www.w3.org/2000/svg";

// Chaque icône = liste de sous-éléments {t: tag, ...attributs}.
const DEFS = {
  check: [{ t: "path", d: "M20 6 9 17l-5-5" }],
  x: [{ t: "path", d: "M18 6 6 18M6 6l12 12" }],
  "alert-triangle": [
    { t: "path", d: "M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" },
    { t: "path", d: "M12 9v4" },
    { t: "path", d: "M12 17h.01" },
  ],
  octagon: [
    { t: "path", d: "M7.9 2h8.2L22 7.9v8.2L16.1 22H7.9L2 16.1V7.9L7.9 2Z" },
    { t: "path", d: "M15 9l-6 6M9 9l6 6" },
  ],
  "slash-circle": [
    { t: "circle", cx: 12, cy: 12, r: 10 },
    { t: "path", d: "m4.9 4.9 14.2 14.2" },
  ],
  clock: [
    { t: "circle", cx: 12, cy: 12, r: 9 },
    { t: "path", d: "M12 7v5l3 2" },
  ],
  database: [
    { t: "ellipse", cx: 12, cy: 5, rx: 8, ry: 3 },
    { t: "path", d: "M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5" },
    { t: "path", d: "M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3" },
  ],
  layers: [
    { t: "path", d: "m12 2 9 5-9 5-9-5 9-5Z" },
    { t: "path", d: "m3 12 9 5 9-5" },
    { t: "path", d: "m3 17 9 5 9-5" },
  ],
  monitor: [
    { t: "rect", x: 2, y: 3, width: 20, height: 14, rx: 2 },
    { t: "path", d: "M8 21h8M12 17v4" },
  ],
  play: [{ t: "path", d: "M6 4v16l14-8L6 4Z" }],
  zap: [{ t: "path", d: "M13 2 3 14h9l-1 8 10-12h-9l1-8Z" }],
  rotate: [
    { t: "path", d: "M21 12a9 9 0 1 1-2.6-6.4" },
    { t: "path", d: "M21 3v6h-6" },
  ],
  copy: [
    { t: "rect", x: 9, y: 9, width: 12, height: 12, rx: 2 },
    { t: "path", d: "M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" },
  ],
  "external-link": [
    { t: "path", d: "M15 3h6v6" },
    { t: "path", d: "M10 14 21 3" },
    { t: "path", d: "M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" },
  ],
  download: [
    { t: "path", d: "M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" },
    { t: "path", d: "m7 10 5 5 5-5" },
    { t: "path", d: "M12 15V3" },
  ],
  chevron: [{ t: "path", d: "m9 6 6 6-6 6" }],
  activity: [{ t: "path", d: "M22 12h-4l-3 9L9 3l-3 9H2" }],
  shield: [{ t: "path", d: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z" }],
  terminal: [
    { t: "path", d: "m4 17 6-6-6-6" },
    { t: "path", d: "M12 19h8" },
  ],
  search: [
    { t: "circle", cx: 11, cy: 11, r: 7 },
    { t: "path", d: "m21 21-4.3-4.3" },
  ],
  dot: [{ t: "circle", cx: 12, cy: 12, r: 4 }],
  outils: [
    {
      t: "path",
      d: "M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76Z",
    },
  ],
};

/**
 * Construit une icône SVG. `nom` doit exister dans DEFS.
 * L'icône est décorative (aria-hidden) : le sens est porté par le texte à côté.
 */
export function icone(nom, { taille = 16, classe } = {}) {
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", String(taille));
  svg.setAttribute("height", String(taille));
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  if (classe) svg.setAttribute("class", classe);
  for (const spec of DEFS[nom] || DEFS.dot) {
    const { t, ...attrs } = spec;
    const enfant = document.createElementNS(NS, t);
    for (const [k, v] of Object.entries(attrs)) enfant.setAttribute(k, String(v));
    svg.append(enfant);
  }
  return svg;
}

// Icône par statut du pipeline (sémantique cohérente d'un bout à l'autre).
export const ICONE_STATUT = {
  VALIDE: "check",
  VALIDE_NON_DEPLOYE: "check",
  REJETE: "alert-triangle",
  ANGLE_MORT: "octagon",
  ERREUR: "x",
  NON_APPLICABLE: "slash-circle",
  EN_COURS: "clock",
  SIMULE: "activity",
};
