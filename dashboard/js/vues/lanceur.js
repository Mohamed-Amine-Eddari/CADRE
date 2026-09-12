/* ==========================================================================
   vues/lanceur.js, Lanceur de cycle + timeline des 9 étapes du pipeline.
   Mode simulé/réel, confirmation obligatoire en réel, verrou anti-concurrence,
   suivi live via /api/cycle/statut. Émet `cadre:cycle-termine` à la fin d'un
   cycle pour que les autres vues se rafraîchissent.
   Consomme /api/catalogue (liste blanche techniques), /api/cycle/{statut,lancer}.
   ========================================================================== */

import { el, monter, texte } from "../dom.js";
import { icone } from "../icones.js";
import { enteteSection } from "../ui.js";
import { API } from "../api.js";

const ETAPES = [
  "Exécution (WinRM)",
  "Indexation (Elastic)",
  "Anonymisation",
  "Règle Sigma",
  "Compilation Lucene",
  "Validation TP",
  "Validation FP",
  "Déploiement Kibana",
  "Rapport",
];

export function creerLanceur() {
  let techniquesConnues = new Set(); // liste blanche côté client (le serveur revalide)
  let derniereEnCours = false;

  // --- Contrôles --------------------------------------------------------
  const radioSimule = radio("mode", "simule", "Simulé", true);
  const radioReel = radio("mode", "reel", "Réel", false);

  const champTech = el("input", {
    class: "champ",
    attrs: {
      type: "text",
      id: "champ-techniques",
      placeholder: "Techniques (ex. T1059.001 T1136.001), vide = tout le catalogue",
      "aria-label": "Techniques MITRE à exécuter",
      autocomplete: "off",
      spellcheck: "false",
    },
  });
  const listeTech = el("datalist", { attrs: { id: "liste-techniques" } });
  champTech.setAttribute("list", "liste-techniques");

  const caseParallele = el("input", { attrs: { type: "checkbox", id: "cycle-parallele" } });
  const labelParallele = el("label", { class: "radio-pilule", attrs: { for: "cycle-parallele" } }, [
    caseParallele,
    el("span", { text: "Parallèle (plus rapide, lots isolés)" }),
  ]);

  const caseConfirm = el("input", {
    attrs: { type: "checkbox", id: "confirm-reel" },
    // Enveloppé (pas `majBouton` directement) : un handler DOM reçoit
    // l'Event en premier argument, un objet toujours truthy -- passé tel
    // quel à `majBouton(enCours = derniereEnCours)` plus bas, il forçait
    // `bouton.disabled = true` à chaque coche, quel que soit l'état réel
    // de la case. Effet limité ici par le sondage continu de l'onglet
    // Cycle (2s, app.js, actif même hors de cet onglet) qui recorrige
    // l'affichage sous 2s -- mais le bouton restait faussement bloqué
    // pendant cette fenêtre après chaque clic sur la case.
    on: { change: () => majBouton() },
  });
  const blocConfirm = el("label", { class: "confirm-reel", attrs: { for: "confirm-reel", hidden: true } }, [
    caseConfirm,
    el("span", { text: "Je confirme le lancement d'une " }),
    el("strong", { text: "attaque réelle" }),
    el("span", { text: " sur la VM de labo." }),
  ]);

  const bouton = el("button", { class: "btn btn-primaire", attrs: { type: "button" } }, [
    icone("play", { taille: 16 }),
    el("span", { text: "Lancer le cycle" }),
  ]);
  bouton.addEventListener("click", lancer);

  const statutLigne = el("div", { class: "lanceur-statut", attrs: { role: "status", "aria-live": "polite" } });

  radioSimule.input.addEventListener("change", majMode);
  radioReel.input.addEventListener("change", majMode);

  // --- Timeline ---------------------------------------------------------
  const timeline = el("ol", { class: "timeline", attrs: { "aria-label": "Étapes du pipeline" } });
  ETAPES.forEach((nom, i) => {
    timeline.append(
      el("li", { class: "tl-etape", dataset: { i } }, [
        el("span", { class: "tl-puce", attrs: { "aria-hidden": "true" }, text: String(i + 1) }),
        el("span", { class: "tl-nom", text: nom }),
      ]),
    );
  });

  const element = el("section", { class: "carte" }, [
    enteteSection("Lancer un cycle", "play"),
    el("div", { class: "lanceur-grille" }, [
      el("div", { class: "champ-mode", attrs: { role: "radiogroup", "aria-label": "Mode d'exécution" } }, [
        radioSimule.label,
        radioReel.label,
      ]),
      el("div", { class: "champ-wrap" }, [champTech, listeTech]),
      labelParallele,
      bouton,
    ]),
    blocConfirm,
    statutLigne,
    el("div", { class: "timeline-wrap" }, [timeline]),
  ]);

  // --- Logique ----------------------------------------------------------
  function majMode() {
    const reel = radioReel.input.checked;
    blocConfirm.hidden = !reel;
    if (!reel) caseConfirm.checked = false;
    majBouton();
  }

  function majBouton(enCours = derniereEnCours) {
    const reel = radioReel.input.checked;
    const bloque = enCours || (reel && !caseConfirm.checked);
    bouton.disabled = bloque;
    bouton.classList.toggle("est-reel", reel);
  }

  function majTimeline(etape, mode) {
    // Progression RÉELLE : le backend expose l'étape courante (1-9) via
    // /api/cycle/statut. Étapes < courante = faites (✓), = courante = en cours,
    // > courante = à venir. mode "ok" → tout fait ; "erreur" → étape en échec.
    timeline.querySelectorAll(".tl-etape").forEach((li, idx) => {
      const n = idx + 1;
      li.classList.remove("est-fait", "est-courant", "est-echec");
      if (mode === "ok") {
        li.classList.add("est-fait");
      } else if (n < etape) {
        li.classList.add("est-fait");
      } else if (n === etape) {
        li.classList.add(mode === "erreur" ? "est-echec" : "est-courant");
      }
    });
  }

  async function lancer() {
    const reel = radioReel.input.checked;
    const mode = reel ? "reel" : "simulation"; // le backend attend "simulation"|"reel"
    const saisie = champTech.value.trim();
    const techniques = saisie ? saisie.split(/[\s,]+/).filter(Boolean) : null;

    // Validation liste blanche côté client (le serveur revalide de toute façon).
    if (techniques && techniquesConnues.size) {
      const inconnues = techniques.filter((t) => !techniquesConnues.has(t));
      if (inconnues.length) {
        afficherStatut("Technique(s) inconnue(s) : " + inconnues.join(", "), "ko");
        return;
      }
    }

    bouton.disabled = true;
    try {
      const r = await API.lancerCycle({
        mode,
        techniques,
        confirmer: reel ? caseConfirm.checked : false,
        parallele: caseParallele.checked,
      });
      if (r.lance) {
        afficherStatut("Cycle " + mode + " démarré…", "info");
        majTimeline(1, "actif");
      } else {
        afficherStatut(r.raison || "Lancement refusé.", "ko");
        majBouton();
      }
    } catch (e) {
      // Message générique côté UI ; le détail reste dans le log serveur.
      const msg = e.corps && e.corps.erreur ? e.corps.erreur : "Lancement impossible.";
      afficherStatut(msg, "ko");
      majBouton();
    }
  }

  function afficherStatut(message, ton = "info") {
    monter(statutLigne, el("span", { class: "statut-ton statut-" + ton, text: message }));
  }

  async function rafraichir() {
    // Charge la liste blanche une seule fois (pour le datalist + validation).
    if (!techniquesConnues.size) {
      try {
        const cat = await API.catalogue();
        const techs = [...new Set((cat.attaques || []).map((a) => a.technique_mitre).filter(Boolean))].sort();
        techniquesConnues = new Set(techs);
        monter(listeTech, techs.map((t) => el("option", { attrs: { value: t } })));
      } catch {
        /* datalist optionnel */
      }
    }
    // Suivi de l'état du cycle.
    try {
      const s = await API.cycleStatut();
      const enCours = !!s.en_cours;
      const p = s.progression || {};
      const etape = p.etape || 0;
      if (enCours) {
        afficherStatut(
          "Cycle " + (s.mode || "") + ", " + (p.faites ?? 0) + "/" + (p.total ?? "?") +
            (p.technique ? " · " + p.technique : "") +
            " · étape " + etape + "/9" + (p.etape_nom ? " " + p.etape_nom : ""),
          "info",
        );
        majTimeline(etape, "actif");
      } else if (s.erreur) {
        afficherStatut("Dernier cycle en erreur : " + s.erreur, "ko");
        majTimeline(9, "erreur");
      } else if (s.termine_a) {
        afficherStatut("Dernier cycle terminé.", "ok");
        majTimeline(9, "ok");
      }
      derniereEnCours = enCours;
      majBouton(enCours);
      // Transition « en cours -> terminé » : prévenir les autres vues.
      if (!enCours && rafraichir._etait) {
        document.dispatchEvent(new CustomEvent("cadre:cycle-termine"));
      }
      rafraichir._etait = enCours;
    } catch {
      /* on garde l'affichage précédent */
    }
  }

  return { element, rafraichir };
}

function radio(name, value, libelle, coche) {
  const input = el("input", { attrs: { type: "radio", name, value, id: "mode-" + value, checked: coche } });
  const label = el("label", { class: "radio-pilule", attrs: { for: "mode-" + value } }, [
    input,
    el("span", { text: libelle }),
  ]);
  return { input, label };
}
