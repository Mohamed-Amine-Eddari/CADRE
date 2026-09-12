/* ==========================================================================
   vues/barre-etat.js, Barre de santé de la stack (Elasticsearch/Kibana/VM).
   Auto-rafraîchie pendant le démarrage à froid : les puces passent au vert au
   fur et à mesure. Consomme /api/statut.
   ========================================================================== */

import { el, monter } from "../dom.js";
import { icone } from "../icones.js";
import { puceSante } from "../ui.js";
import { API } from "../api.js";

const SERVICES = [
  { cle: "elasticsearch", nom: "Elasticsearch", ico: "database" },
  { cle: "kibana", nom: "Kibana", ico: "layers" },
  { cle: "vm", nom: "VM cible", ico: "monitor" },
];

export function creerBarreEtat() {
  const zone = el("div", { class: "barre-services" });
  const element = el("div", { class: "barre-etat", attrs: { role: "status", "aria-live": "polite" } }, [
    el("div", { class: "barre-marque" }, [
      // Emplacement logo : rempli par assets/logo-... si présent (voir app.js).
      el("span", { class: "logo-slot" }, [el("span", { class: "logo-repli", text: "CADRE" })]),
      el("div", { class: "marque-txt" }, [
        el("span", { class: "marque-nom", text: "CADRE" }),
        el("span", { class: "marque-auteur", text: "Continuous Adversary-Driven Rule Engineering" }),
      ]),
    ]),
    zone,
  ]);

  function rendre(data) {
    const services = SERVICES.map((s) => {
      const etat = (data && data[s.cle]) || {};
      const inconnu = etat.ok == null;
      return el(
        "div",
        {
          class: "service" + (etat.ok ? " est-ok" : inconnu ? " est-inconnu" : " est-ko"),
          title: etat.detail || "",
        },
        [
          puceSante(!!etat.ok, { inconnu }),
          icone(s.ico, { taille: 15, classe: "service-ico" }),
          el("span", { class: "service-nom", text: s.nom }),
        ],
      );
    });
    monter(zone, services);
  }

  async function rafraichir() {
    try {
      rendre(await API.statut());
    } catch {
      rendre(null); // toutes puces "inconnu" plutôt qu'un crash
    }
  }

  return { element, rafraichir };
}
