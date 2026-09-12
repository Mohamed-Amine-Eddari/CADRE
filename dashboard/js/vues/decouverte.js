/* ==========================================================================
   vues/decouverte.js, Onglet « Découverte IA ». Décrire une attaque en
   langage naturel (+ technique MITRE optionnelle) pour que l'agent IA la
   génère, la filtre (garde-fou anti-destruction), l'exécute et la valide
   TP/FP -- toujours réel (pas de mode simulation ici), confirmation
   explicite obligatoire, comme `cadre decouvrir` en CLI.
   Consomme /api/decouverte/{statut,lancer}.
   ========================================================================== */

import { el, monter } from "../dom.js";
import { icone } from "../icones.js";
import { pastille, squelette, etatVide, enteteSection } from "../ui.js";
import { sondeur } from "../etat.js";
import { API } from "../api.js";

const EXEMPLE_DESCRIPTION = "Pass the Hash";

export function creerDecouverte() {
  let sondeurLocal = null;

  const champDescription = el("textarea", {
    class: "champ decouverte-desc",
    attrs: {
      rows: "3",
      placeholder: EXEMPLE_DESCRIPTION,
      "aria-label": "Nom ou description de l'attaque à générer",
      spellcheck: "true",
    },
    // Enveloppé (pas `majBouton` directement) : un handler DOM reçoit
    // l'Event en premier argument, un objet toujours truthy -- passé tel
    // quel à `majBouton(bloqueExterne = false)`, il forçait
    // `bouton.disabled = true` à CHAQUE frappe, quels que soient la
    // description saisie et l'état de la case de confirmation. Le bouton
    // ne se réactivait qu'au prochain rafraîchissement périodique de
    // l'onglet (jusqu'à 9s, voir app.js) -- jamais instantanément.
    on: { input: () => majBouton() },
  });

  const champTechnique = el("input", {
    class: "champ",
    attrs: {
      type: "text",
      placeholder: "Technique MITRE (optionnel), ex. T1053.005",
      "aria-label": "Technique MITRE imposée",
      autocomplete: "off",
      spellcheck: "false",
    },
  });

  const caseRevue = el("input", { attrs: { type: "checkbox", id: "decouverte-revue" } });
  const labelRevue = el("label", { class: "radio-pilule", attrs: { for: "decouverte-revue" } }, [
    caseRevue,
    el("span", { text: "Envoyer en revue avant déploiement" }),
  ]);

  const caseConfirm = el("input", {
    attrs: { type: "checkbox", id: "decouverte-confirm" },
    // Même correctif que champDescription ci-dessus : sans l'enveloppe,
    // cocher la case désactivait le bouton au lieu de l'activer.
    on: { change: () => majBouton() },
  });
  const blocConfirm = el("label", { class: "confirm-reel", attrs: { for: "decouverte-confirm" } }, [
    caseConfirm,
    el("span", { text: "Je confirme le lancement d'une " }),
    el("strong", { text: "attaque réelle générée par l'IA" }),
    el("span", { text: " sur la VM de labo." }),
  ]);

  const bouton = el("button", { class: "btn btn-primaire", attrs: { type: "button" } }, [
    icone("zap", { taille: 16 }),
    el("span", { text: "Lancer la découverte" }),
  ]);
  bouton.addEventListener("click", lancer);

  const statutLigne = el("div", { class: "lanceur-statut", attrs: { role: "status", "aria-live": "polite" } });
  const zoneResultat = el("div", { class: "cycle-detail" });

  const element = el("section", { class: "carte" }, [
    enteteSection("Découverte IA", "zap"),
    el("p", { class: "muet", text: "Décrivez une attaque en langage naturel (ou son nom) -- l'agent IA la génère, l'exécute réellement sur la VM et la valide, exactement comme le catalogue natif." }),
    champDescription,
    el("div", { class: "lanceur-grille decouverte-grille" }, [
      champTechnique,
      labelRevue,
      bouton,
    ]),
    blocConfirm,
    statutLigne,
    zoneResultat,
  ]);

  function majBouton(bloqueExterne = false) {
    const descriptionVide = !champDescription.value.trim();
    bouton.disabled = bloqueExterne || descriptionVide || !caseConfirm.checked;
  }
  majBouton();

  async function lancer() {
    bouton.disabled = true;
    monter(zoneResultat, squelette(2));
    try {
      const r = await API.lancerDecouverte({
        description: champDescription.value.trim(),
        technique: champTechnique.value.trim() || null,
        revue: caseRevue.checked,
        confirmer: caseConfirm.checked,
      });
      if (!r.lance) {
        afficherStatut(r.raison || "Lancement refusé.", "ko");
        majBouton();
        monter(zoneResultat, []);
        return;
      }
      afficherStatut("Génération et exécution en cours (peut prendre jusqu'à 7 minutes sur ce matériel)…", "info");
      demarrerSuivi(/* emettreEvenement */ true);
    } catch (e) {
      const msg = e.corps && e.corps.erreur ? e.corps.erreur : "Lancement impossible.";
      afficherStatut(msg, "ko");
      majBouton();
      monter(zoneResultat, []);
    }
  }

  function afficherStatut(message, ton = "info") {
    monter(statutLigne, el("span", { class: "statut-ton statut-" + ton, text: message }));
  }

  function rendreResultat(resultat) {
    if (!resultat) {
      monter(zoneResultat, []);
      return;
    }
    const decouvertes = resultat.decouvertes || [];
    const refusees = resultat.refusees || [];
    const echecs = resultat.echecs || [];

    if (!decouvertes.length && !refusees.length && !echecs.length) {
      monter(zoneResultat, el("section", { class: "carte" }, [etatVide("Aucun résultat.")]));
      return;
    }

    const groupes = [];
    if (decouvertes.length) {
      groupes.push(
        groupeResultat(
          "Découverte" + (decouvertes.length > 1 ? "s" : ""),
          decouvertes.map((d) =>
            el("div", { class: "decouverte-item" }, [
              pastille(d.statut),
              el("div", {}, [
                el("div", {}, [
                  el("span", { class: "mono", text: d.id }),
                  el("span", { text: " — " + d.nom }),
                ]),
                el("div", { class: "muet" }, [
                  el("span", { class: "mono", text: d.technique_mitre || "" }),
                  d.rule_id_stable
                    ? el("span", {}, [
                        el("span", { text: " · en attente d'approbation : " }),
                        el(
                          "button",
                          {
                            class: "lien-attaque mono",
                            attrs: { type: "button" },
                            on: {
                              click: () =>
                                document.dispatchEvent(
                                  new CustomEvent("cadre:aller-onglet", { detail: { onglet: "revue" } }),
                                ),
                            },
                          },
                          [el("span", { text: d.rule_id_stable })],
                        ),
                      ])
                    : null,
                ]),
              ]),
            ]),
          ),
        ),
      );
    }
    if (refusees.length) {
      groupes.push(
        groupeResultat(
          "Refusée" + (refusees.length > 1 ? "s" : "") + " (filtre anti-destruction)",
          refusees.map((r) =>
            el("div", { class: "decouverte-item" }, [
              el("span", { class: "badge-crit", text: "refusée" }),
              el("div", {}, [
                el("div", { text: r.description }),
                el("div", { class: "muet", text: r.motif_refus }),
              ]),
            ]),
          ),
        ),
      );
    }
    if (echecs.length) {
      groupes.push(
        groupeResultat(
          "Échec" + (echecs.length > 1 ? "s" : ""),
          echecs.map((e) =>
            el("div", { class: "decouverte-item" }, [
              el("span", { class: "badge-opt", text: "échec" }),
              el("div", {}, [
                el("div", { text: e.description }),
                el("div", { class: "cell-raison muet", text: e.raison }),
              ]),
            ]),
          ),
        ),
      );
    }
    monter(zoneResultat, groupes);
  }

  function groupeResultat(titre, items) {
    return el("div", { class: "detail-groupe" }, [
      el("div", { class: "detail-groupe-tete" }, [el("span", { text: titre })]),
      el("div", { class: "decouverte-liste" }, items),
    ]);
  }

  // Sondeur DÉDIÉ (pas le poller global de app.js, qui ne concerne que
  // l'onglet Cycle) : une découverte réelle prend de l'ordre de la minute,
  // pas besoin d'un intervalle agressif. `sondeurLocal` est remis à `null`
  // dès l'arrêt pour que `rafraichir()` puisse en redémarrer un si une
  // découverte est relancée depuis un autre onglet/fenêtre pendant que
  // cette vue est inactive -- sinon un sondeur arrêté mais toujours "vrai"
  // empêcherait à tort tout nouveau suivi. `detruire()` (pas `stopper()`)
  // pour retirer aussi le listener `visibilitychange` -- sinon chaque
  // découverte lancée en laisse un permanent sur `document`.
  function demarrerSuivi(emettreEvenement) {
    if (sondeurLocal) sondeurLocal.detruire();
    sondeurLocal = sondeur(
      async () => {
        const s = await API.decouverteStatut();
        if (!s.en_cours) {
          sondeurLocal.detruire();
          sondeurLocal = null;
          majBouton();
          if (s.erreur) {
            afficherStatut("Erreur : " + s.erreur, "ko");
          } else {
            afficherStatut("Découverte terminée.", "ok");
            rendreResultat(s.resultat);
            if (emettreEvenement) document.dispatchEvent(new CustomEvent("cadre:cycle-termine"));
          }
        }
      },
      1800,
      {
        // ~18s d'échecs consécutifs (réseau/backend injoignable) avant
        // d'abandonner le suivi -- sans ça le bouton reste désactivé et le
        // message figé sur "en cours" indéfiniment, jusqu'à 2-3 minutes
        // sans aucun retour à l'utilisateur, seul un F5 le débloquant.
        maxEchecsConsecutifs: 10,
        onEchecPersistant: () => {
          sondeurLocal = null;
          majBouton();
          afficherStatut("Suivi interrompu (connexion au serveur perdue) -- la découverte a peut-être abouti, vérifiez l'onglet Historique.", "ko");
        },
      },
    );
    sondeurLocal.demarrer();
  }

  async function rafraichir() {
    try {
      const s = await API.decouverteStatut();
      majBouton(!!s.en_cours);
      if (s.en_cours) {
        afficherStatut("Découverte en cours…", "info");
        if (!sondeurLocal) demarrerSuivi(false);
      } else if (s.resultat) {
        rendreResultat(s.resultat);
      } else if (s.erreur) {
        afficherStatut("Erreur : " + s.erreur, "ko");
      }
    } catch {
      /* on garde l'affichage précédent */
    }
  }

  return { element, rafraichir };
}
