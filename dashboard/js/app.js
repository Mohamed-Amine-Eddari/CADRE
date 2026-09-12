/* ==========================================================================
   app.js, Console à onglets. Une seule fenêtre visible à la fois (fini le
   défilement unique). Monte les vues, gère la navigation, câble le polling
   (barre d'état + onglet actif + progression de cycle live). Tout en
   addEventListener, aucun gestionnaire inline (CSP stricte).
   ========================================================================== */

import { $, el, monter } from "./dom.js";
import { icone } from "./icones.js";
import { sondeur } from "./etat.js";
import { etatErreur } from "./ui.js";
import { creerBarreEtat } from "./vues/barre-etat.js";
import { creerVueEnsemble } from "./vues/vue-ensemble.js";
import { creerMatrice } from "./vues/matrice.js";
import { creerCatalogue } from "./vues/catalogue.js";
import { creerLanceur } from "./vues/lanceur.js";
import { creerDecouverte } from "./vues/decouverte.js";
import { creerRevue } from "./vues/revue.js";
import { creerDetections } from "./vues/detections.js";
import { creerHistorique } from "./vues/historique.js";
import { creerDerive } from "./vues/derive.js";
import { creerErreurs } from "./vues/erreurs.js";
import { creerSysteme } from "./vues/systeme.js";
import { creerOutils } from "./vues/outils.js";

const ONGLETS = [
  { id: "ensemble", label: "Vue d'ensemble", ico: "activity", creer: creerVueEnsemble },
  { id: "attaques", label: "Attaques", ico: "layers", creer: creerMatrice },
  { id: "catalogue", label: "Catalogue", ico: "search", creer: creerCatalogue },
  { id: "cycle", label: "Cycle", ico: "play", creer: creerLanceur },
  { id: "decouverte", label: "Découverte IA", ico: "zap", creer: creerDecouverte },
  { id: "revue", label: "Revue", ico: "check", creer: creerRevue },
  { id: "detections", label: "Détections", ico: "shield", creer: creerDetections },
  { id: "historique", label: "Historique", ico: "clock", creer: creerHistorique },
  { id: "derive", label: "Dérive", ico: "monitor", creer: creerDerive },
  { id: "journaux", label: "Erreurs & journaux", ico: "terminal", creer: creerErreurs },
  { id: "systeme", label: "Système", ico: "database", creer: creerSysteme },
  { id: "outils", label: "Outils", ico: "outils", creer: creerOutils },
];

function demarrer() {
  const barre = creerBarreEtat();
  monter($("#slot-barre"), barre.element);

  const nav = $("#nav-onglets");
  const contenu = $("#app");
  const vues = {};
  let actif = null;

  for (const o of ONGLETS) {
    // Une vue qui lève à l'initialisation ne doit pas empêcher le montage
    // des onglets suivants ni laisser tout le dashboard blanc et silencieux
    // (avant ce garde-fou, une seule exception ici cassait les 12 onglets).
    let vue;
    try {
      vue = o.creer();
    } catch (err) {
      console.error(`Échec du montage de l'onglet « ${o.label} »`, err);
      vue = { element: etatErreur(null, `L'onglet « ${o.label} » n'a pas pu se charger.`), rafraichir: () => {} };
    }
    vues[o.id] = vue;
    vue.element.hidden = true;
    vue.element.setAttribute("role", "tabpanel");
    contenu.append(vue.element);

    const btn = el(
      "button",
      {
        class: "onglet",
        attrs: { type: "button", role: "tab", "aria-selected": "false" },
        dataset: { onglet: o.id },
        on: { click: () => activer(o.id) },
      },
      [icone(o.ico, { taille: 18, classe: "onglet-ico" }), el("span", { class: "onglet-label", text: o.label })],
    );
    nav.append(btn);
  }

  function activer(id) {
    for (const o of ONGLETS) {
      const estActif = o.id === id;
      vues[o.id].element.hidden = !estActif;
      const btn = nav.querySelector('[data-onglet="' + o.id + '"]');
      if (btn) {
        btn.classList.toggle("est-actif", estActif);
        btn.setAttribute("aria-selected", estActif ? "true" : "false");
      }
    }
    actif = id;
    vues[id].rafraichir();
    contenu.focus();
  }

  activer("ensemble");

  // Polling : barre d'état (toujours), onglet actif (cadence), et le statut de
  // cycle en continu (progression live du diagramme, même hors onglet Cycle).
  sondeur(barre.rafraichir, 5000).demarrer();
  sondeur(() => actif && vues[actif].rafraichir(), 9000).demarrer();
  sondeur(vues.cycle.rafraichir, 2000).demarrer();

  // Fin de cycle -> rafraîchir les vues agrégées.
  document.addEventListener("cadre:cycle-termine", () => {
    ["ensemble", "attaques", "catalogue", "revue", "detections", "historique", "journaux", "derive"].forEach(
      (id) => vues[id].rafraichir(),
    );
  });
  // Navigation croisée (clic technique dans la matrice -> onglet Historique).
  document.addEventListener("cadre:aller-onglet", (e) => activer(e.detail.onglet));
  document.addEventListener("cadre:technique", () => activer("historique"));
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", demarrer);
} else {
  demarrer();
}
