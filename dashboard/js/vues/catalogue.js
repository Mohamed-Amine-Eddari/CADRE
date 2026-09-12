/* ==========================================================================
   vues/catalogue.js, Catalogue d'attaques : liste triée par nom, clic ->
   fiche détail inline (description + payload + métadonnées). Bouton
   "Lancer cette attaque" (simulé/réel + confirmation) sur la fiche --
   cible CETTE attaque précise par ID exact (pas toutes celles qui
   partagent la même technique MITRE, voir /api/attaque/lancer).
   Consomme /api/catalogue, /api/catalogue/{id}, /api/attaque/lancer,
   /api/cycle/statut.
   ========================================================================== */

import { el, monter, boutonCopier } from "../dom.js";
import { icone } from "../icones.js";
import { squelette, etatVide, etatErreur, enteteSection, th, badge } from "../ui.js";
import { sondeur } from "../etat.js";
import { API } from "../api.js";

export function creerCatalogue() {
  let attaques = [];
  let idOuvert = null;
  // Sondeur de suivi de lancement, remonté au niveau de la vue (pas de
  // creerBlocLancement) : sans ça, rouvrir un détail pendant qu'un
  // lancement précédent est encore suivi abandonne ce sondeur en arrière-
  // plan, impossible à arrêter depuis l'UI (fuite + double rafraîchissement
  // global fantôme à sa terminaison).
  let sondeurLancement = null;

  const corpsTable = el("tbody");
  const zoneDetail = el("div", { class: "cycle-detail attaque-detail-zone" });
  const resumeStats = el("p", { class: "muet", attrs: { role: "status" } });
  const zoneDoublons = el("div", {});

  const table = el("table", { class: "table-cycles" }, [
    el("thead", {}, [
      el("tr", {}, [th("Nom"), th("Technique"), th("Tactique"), th("Plateforme"), th("Risque")]),
    ]),
    corpsTable,
  ]);

  const element = el("section", { class: "carte" }, [
    enteteSection("Catalogue d'attaques", "search"),
    resumeStats,
    zoneDoublons,
    el("div", { class: "table-wrap" }, [table]),
    zoneDetail,
  ]);

  function rendreStats(s) {
    if (!s) {
      monter(resumeStats, []);
      monter(zoneDoublons, []);
      return;
    }
    resumeStats.textContent =
      s.total + " attaques · " + s.tactiques_uniques + " tactiques · " +
      s.techniques_uniques + " techniques uniques";
    const doublons = s.regles_similaires || [];
    if (!doublons.length) {
      monter(zoneDoublons, []);
      return;
    }
    monter(
      zoneDoublons,
      el("div", { class: "detail-groupe" }, [
        el("div", { class: "detail-groupe-tete" }, [
          el("span", {
            text:
              doublons.length +
              " groupe" +
              (doublons.length > 1 ? "s" : "") +
              " de règles à logique dupliquée détecté" +
              (doublons.length > 1 ? "s" : ""),
          }),
        ]),
        el(
          "ul",
          { class: "decouverte-liste" },
          doublons.map((groupe) =>
            el("li", { class: "decouverte-item" }, [
              el("span", { class: "badge-opt", text: "doublon" }),
              el("span", { class: "mono", text: groupe.join(" ≡ ") }),
            ]),
          ),
        ),
      ]),
    );
  }

  function rendreListe() {
    if (!attaques.length) {
      monter(
        corpsTable,
        el("tr", {}, [el("td", { attrs: { colspan: 5 } }, [etatVide("Aucune attaque au catalogue.")])]),
      );
      return;
    }
    const triees = [...attaques].sort((a, b) => a.nom.localeCompare(b.nom));
    const rangs = triees.map((a) => {
      const btnNom = el(
        "button",
        { class: "lien-attaque", attrs: { type: "button" } },
        [el("span", { text: a.nom })],
      );
      const tr = el(
        "tr",
        { class: "ligne-cycle", dataset: { attaqueId: a.id } },
        [
          el("td", {}, [btnNom]),
          el("td", { class: "mono", text: a.technique_mitre || "" }),
          el("td", { text: a.tactique_mitre || "" }),
          el("td", { text: a.plateforme || "" }),
          el("td", {}, [el("span", { class: a.niveau_risque === "high" ? "badge-crit" : "badge-opt", text: a.niveau_risque || "" })]),
        ],
      );
      const ouvrir = () => ouvrirDetail(a.id, tr);
      btnNom.addEventListener("click", ouvrir);
      return tr;
    });
    monter(corpsTable, rangs);
  }

  async function ouvrirDetail(id, tr) {
    corpsTable.querySelectorAll("tr.est-ouvert").forEach((r) => r.classList.remove("est-ouvert"));
    tr.classList.add("est-ouvert");
    idOuvert = id;
    // Abandonner tout suivi de lancement en cours d'un détail précédemment
    // ouvert -- sinon il continue de tourner en arrière-plan, orphelin.
    if (sondeurLancement) {
      sondeurLancement.detruire();
      sondeurLancement = null;
    }
    monter(zoneDetail, squelette(3));
    try {
      const d = await API.detailAttaque(id);
      // La réponse peut arriver après qu'un autre détail a été ouvert
      // entre-temps (requête plus lente dépassée par une plus rapide) --
      // ne jamais écraser un panneau qui ne correspond plus à la ligne
      // surlignée dans le tableau.
      if (id !== idOuvert) return;
      rendreDetail(d);
    } catch {
      if (id !== idOuvert) return;
      monter(zoneDetail, etatErreur(() => ouvrirDetail(id, tr), "Détail de l'attaque indisponible."));
    }
  }

  function rendreDetail(d) {
    const payloadContient = d.commande && d.commande.includes("{CIBLE_IP}");
    const payload = el("div", { class: "attaque-payload mono", text: d.commande || "" });
    const btnCopier = boutonCopier(d.commande || "", "Copier le payload");
    btnCopier.append(icone("copy", { taille: 12 }));

    const meta = el("div", { class: "attaque-meta" }, [
      badge("Technique", d.technique_mitre),
      badge("Tactique", d.tactique_mitre),
      badge("Plateforme", d.plateforme),
      badge("Risque", d.niveau_risque, d.niveau_risque === "high"),
      badge("Origine", d.origine_execution === "kali" ? "réseau (Kali)" : "cible directe"),
    ]);

    const blocs = [
      el("div", { class: "detail-entete", text: d.nom }),
      el("p", { text: d.description || "" }),
      meta,
      el("div", { class: "detail-groupe" }, [
        el("div", { class: "detail-groupe-tete" }, [el("span", { text: "Payload (commande exécutée)" })]),
        el("div", { class: "payload-wrap" }, [payload, btnCopier]),
        payloadContient
          ? el("p", { class: "muet", text: "{CIBLE_IP} est substitué par l'IP réelle de la cible au moment de l'exécution -- ce n'est pas encore la commande finale exacte." })
          : null,
      ]),
      creerBlocLancement(d),
    ];
    monter(zoneDetail, blocs);
  }

  // --- Lancement d'une attaque unique ------------------------------------
  function creerBlocLancement(d) {
    const radioSimule = radio("mode-attaque", "simule", "Simulé", true);
    const radioReel = radio("mode-attaque", "reel", "Réel", false);
    // Enveloppé (pas `majBouton` directement) : un handler DOM reçoit
    // l'Event en premier argument, un objet toujours truthy -- passé tel
    // quel à `majBouton(bloqueExterne = false)` plus bas, il forçait
    // `bouton.disabled = true` à chaque coche, quel que soit l'état réel
    // de la case. Ici, rien ne le corrige jamais tout seul (pas de sondage
    // périodique sur ce panneau après sa création) : le bouton restait
    // bloqué jusqu'à ce que l'utilisateur bascule le mode Simulé/Réel.
    const caseConfirm = el("input", { attrs: { type: "checkbox" }, on: { change: () => majBouton() } });
    const blocConfirm = el(
      "label",
      { class: "confirm-reel", attrs: { hidden: true } },
      [caseConfirm, el("span", { text: "Je confirme le lancement d'une " }), el("strong", { text: "attaque réelle" }), el("span", { text: " sur la VM de labo." })],
    );
    const bouton = el("button", { class: "btn btn-primaire", attrs: { type: "button" } }, [
      icone("play", { taille: 16 }),
      el("span", { text: "Lancer cette attaque" }),
    ]);
    const statutLigne = el("div", { class: "lanceur-statut", attrs: { role: "status", "aria-live": "polite" } });

    function majMode() {
      const reel = radioReel.input.checked;
      blocConfirm.hidden = !reel;
      if (!reel) caseConfirm.checked = false;
      majBouton();
    }
    function majBouton(bloqueExterne = false) {
      const reel = radioReel.input.checked;
      bouton.disabled = bloqueExterne || (reel && !caseConfirm.checked);
    }
    radioSimule.input.addEventListener("change", majMode);
    radioReel.input.addEventListener("change", majMode);

    async function verifierDejaEnCours() {
      try {
        const s = await API.cycleStatut();
        majBouton(!!s.en_cours);
      } catch {
        /* on garde l'état courant du bouton */
      }
    }
    verifierDejaEnCours();

    bouton.addEventListener("click", async () => {
      const reel = radioReel.input.checked;
      const mode = reel ? "reel" : "simulation";
      bouton.disabled = true;
      try {
        const r = await API.lancerAttaque({ id: d.id, mode, confirmer: reel ? caseConfirm.checked : false });
        if (!r.lance) {
          afficherStatut(r.raison || "Lancement refusé.", "ko");
          majBouton();
          return;
        }
        afficherStatut("Attaque " + mode + " démarrée…", "info");
        if (sondeurLancement) sondeurLancement.detruire();
        // Sondeur DÉDIÉ (pas le poller global 2s de l'onglet Cycle) : une
        // attaque unique en simulation peut se terminer en quelques
        // centaines de ms, plus vite que le prochain tick global -- sans
        // ça le bouton resterait bloqué "en cours" indéfiniment. Seuil
        // d'échecs consécutifs : si le réseau/backend devient injoignable
        // pendant le suivi, redonner la main plutôt que de laisser le
        // bouton désactivé indéfiniment (seul un F5 le débloquait avant).
        sondeurLancement = sondeur(
          async () => {
            const s = await API.cycleStatut();
            if (!s.en_cours) {
              sondeurLancement.detruire();
              sondeurLancement = null;
              majBouton();
              afficherStatut(s.erreur ? "Erreur : " + s.erreur : "Terminé.", s.erreur ? "ko" : "ok");
              document.dispatchEvent(new CustomEvent("cadre:cycle-termine"));
            }
          },
          700,
          {
            maxEchecsConsecutifs: 8,
            onEchecPersistant: () => {
              sondeurLancement = null;
              majBouton();
              afficherStatut("Suivi interrompu (connexion au serveur perdue) -- l'attaque a peut-être abouti, vérifiez l'onglet Historique.", "ko");
            },
          },
        );
        sondeurLancement.demarrer();
      } catch (e) {
        const msg = e.corps && e.corps.erreur ? e.corps.erreur : "Lancement impossible.";
        afficherStatut(msg, "ko");
        majBouton();
      }
    });

    function afficherStatut(message, ton = "info") {
      monter(statutLigne, el("span", { class: "statut-ton statut-" + ton, text: message }));
    }

    return el("div", { class: "detail-groupe attaque-lancement" }, [
      el("div", { class: "detail-groupe-tete" }, [el("span", { text: "Lancer cette attaque" })]),
      el("div", { class: "lanceur-grille" }, [
        el("div", { class: "champ-mode", attrs: { role: "radiogroup", "aria-label": "Mode d'exécution" } }, [radioSimule.label, radioReel.label]),
        bouton,
      ]),
      blocConfirm,
      statutLigne,
    ]);
  }

  async function rafraichir() {
    if (!corpsTable.children.length) monter(corpsTable, el("tr", {}, [el("td", { attrs: { colspan: 5 } }, [squelette(3)])]));
    try {
      const d = await API.catalogue();
      attaques = d.attaques || [];
      rendreListe();
      if (idOuvert) {
        const tr = corpsTable.querySelector('[data-attaque-id="' + idOuvert + '"]');
        if (tr) tr.classList.add("est-ouvert");
      }
    } catch {
      monter(corpsTable, el("tr", {}, [el("td", { attrs: { colspan: 5 } }, [etatErreur(rafraichir, "Catalogue indisponible.")])]));
    }
    // Indépendant de la liste ci-dessus : un échec ne doit pas empêcher
    // d'afficher le catalogue lui-même, juste laisser le résumé vide.
    try {
      rendreStats(await API.stats());
    } catch {
      rendreStats(null);
    }
  }

  return { element, rafraichir };
}

function radio(name, value, libelle, coche) {
  const input = el("input", { attrs: { type: "radio", name, value, checked: coche } });
  const label = el("label", { class: "radio-pilule" }, [input, el("span", { text: libelle })]);
  return { input, label };
}
