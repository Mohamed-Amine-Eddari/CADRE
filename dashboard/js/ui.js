/* ==========================================================================
   ui.js, Blocs d'interface réutilisables (construits avec les helpers sûrs).
   Pastille de statut, carte de section, et les 3 états standard de chaque vue
   (chargement / vide / erreur). Aucune couleur en dur : classes + jetons CSS.
   ========================================================================== */

import { el } from "./dom.js";
import { icone, ICONE_STATUT } from "./icones.js";
import { metaStatut, labelCourt } from "./format.js";

/** Pastille sémantique : point coloré + libellé. Couleur = statut. */
export function pastille(statut, { court = false } = {}) {
  const meta = metaStatut(statut);
  return el("span", { class: "pastille st-" + meta.cls }, [
    el("span", { class: "pastille-point", attrs: { "aria-hidden": "true" } }),
    el("span", { class: "pastille-txt", text: court ? labelCourt(statut) : meta.label }),
  ]);
}

/** Puce d'état santé (vert/rouge) pour la barre système. */
export function puceSante(ok, { inconnu = false } = {}) {
  const cls = inconnu ? "inconnu" : ok ? "ok" : "ko";
  return el("span", { class: "puce puce-" + cls, attrs: { "aria-hidden": "true" } });
}

/** En-tête de section : titre + zone d'actions optionnelle.
 * Pas d'icône décorative de titre (style outil de SOC, les icônes sont
 * réservées à la navigation et aux actions, jamais à la décoration). Le 2e
 * argument est ignoré (compat. avec les appels existants). */
export function enteteSection(titre, _iconeNom, actions) {
  return el("div", { class: "section-entete" }, [
    el("div", { class: "section-titre" }, [el("h2", { text: titre })]),
    actions ? el("div", { class: "section-actions" }, actions) : null,
  ]);
}

/** Carte de section (surface + bordure). */
export function carte(...enfants) {
  return el("section", { class: "carte" }, enfants);
}

/** Squelette de chargement (pas de spinner générique). */
export function squelette(lignes = 3) {
  const rangs = [];
  for (let i = 0; i < lignes; i++) {
    rangs.push(el("div", { class: "squelette-ligne", attrs: { "aria-hidden": "true" } }));
  }
  return el("div", { class: "squelette", attrs: { "aria-busy": "true", "aria-label": "Chargement" } }, rangs);
}

/** État vide : message utile + action suggérée facultative. */
export function etatVide(message, action) {
  return el("div", { class: "etat-vide", attrs: { role: "status" } }, [
    icone("search", { taille: 20, classe: "etat-ico" }),
    el("p", { text: message }),
    action || null,
  ]);
}

/** État erreur : message clair + bouton réessayer. */
export function etatErreur(onRetry, message = "Impossible de charger ces données.") {
  return el("div", { class: "etat-erreur", attrs: { role: "alert" } }, [
    icone("alert-triangle", { taille: 20, classe: "etat-ico" }),
    el("p", { text: message }),
    onRetry
      ? el("button", { class: "btn btn-secondaire", text: "Réessayer", attrs: { type: "button" }, on: { click: onRetry } })
      : null,
  ]);
}

/** Icône de statut (cohérente avec la sémantique). */
export function iconeStatut(statut, taille = 14) {
  return icone(ICONE_STATUT[statut] || "dot", { taille, classe: "ico-statut" });
}

/** En-tête de colonne de tableau (scope="col" pour les lecteurs d'écran). */
export function th(t) {
  return el("th", { attrs: { scope: "col" }, text: t });
}

/** Badge libellé/valeur d'attaque, masqué si la valeur est absente. */
export function badge(libelle, valeur, critique = false) {
  if (!valeur) return null;
  return el("span", { class: "attaque-badge" }, [
    el("span", { class: "muet", text: libelle + " : " }),
    el("span", { class: critique ? "badge-crit" : "badge-opt", text: valeur }),
  ]);
}
