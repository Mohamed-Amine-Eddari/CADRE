/* ==========================================================================
   vues/revue.js, Onglet « Revue ». Règles générées par l'IA (Découverte IA,
   case « Envoyer en revue avant déploiement ») validées TP/FP mais PAS
   encore déployées dans Kibana -- un humain doit approuver ou rejeter
   chaque entrée. Équivalent de `cadre revue lister/approuver/rejeter`,
   jusqu'ici seulement accessible en CLI alors que le dashboard peut déjà
   CRÉER ces entrées (Découverte IA).
   Consomme /api/revue, /api/revue/{approuver,rejeter}.
   ========================================================================== */

import { el, monter } from "../dom.js";
import { icone } from "../icones.js";
import { squelette, etatVide, etatErreur, enteteSection, pastille } from "../ui.js";
import { API } from "../api.js";

export function creerRevue() {
  const zoneListe = el("div", {});
  // rule_id_stable -> noeud DOM, UNIQUEMENT le temps d'une action Approuver/
  // Rejeter en vol. Le sondeur global (app.js) rafraîchit cet onglet toutes
  // les 9s en reconstruisant zoneListe au complet -- sans cette protection,
  // un poll pendant "Revalidation et déploiement en cours…" écrasait le
  // bouton désactivé/le message de statut d'une opération encore active
  // (mirroring l'isolation zoneDetail de catalogue.js, structurée différemment
  // ici car chaque entrée EST son propre bloc actionnable, pas une liste +
  // un détail partagé séparé).
  const noeudsEnCours = new Map();

  const element = el("section", { class: "carte" }, [
    enteteSection("Revue", "check"),
    el("p", {
      class: "muet",
      text: "Règles générées par l'IA, déjà validées TP/FP, en attente d'une décision humaine avant déploiement dans Kibana. Approuver déploie réellement -- ce n'est jamais simulé.",
    }),
    zoneListe,
  ]);

  function creerEntree(e) {
    const statutLigne = el("div", { class: "lanceur-statut", attrs: { role: "status", "aria-live": "polite" } });

    const boutonApprouver = el("button", {
      class: "btn btn-primaire",
      attrs: { type: "button", disabled: true },
    }, [
      icone("check", { taille: 14 }),
      el("span", { text: "Approuver et déployer" }),
    ]);
    const boutonRejeter = el("button", { class: "btn btn-secondaire", attrs: { type: "button" } }, [
      icone("x", { taille: 14 }),
      el("span", { text: "Rejeter" }),
    ]);
    // Même patron que catalogue.js/lanceur.js/decouverte.js/outils.js : un
    // déploiement RÉEL (jamais simulé ici) exige une confirmation explicite
    // -- jusqu'ici un simple clic sur "Approuver et déployer" suffisait.
    const caseConfirm = el("input", {
      attrs: { type: "checkbox" },
      on: { change: majBoutonApprouver },
    });
    function majBoutonApprouver() {
      boutonApprouver.disabled = !caseConfirm.checked;
    }
    const blocConfirm = el("label", { class: "confirm-reel" }, [
      caseConfirm,
      el("span", { text: "Je confirme le " }),
      el("strong", { text: "déploiement réel" }),
      el("span", { text: " de cette règle dans Kibana." }),
    ]);
    // `forcer` existe déjà côté API (approuverRevue(ruleId, forcer)) mais
    // n'était jamais exposé dans cet onglet -- seul moyen d'y accéder était
    // la CLI (`cadre revue approuver <id> --forcer`).
    const caseForcer = el("input", { attrs: { type: "checkbox", id: "revue-forcer-" + e.rule_id_stable } });
    const labelForcer = el(
      "label",
      { class: "radio-pilule", attrs: { for: "revue-forcer-" + e.rule_id_stable } },
      [caseForcer, el("span", { text: "Forcer (déployer même si la revalidation échoue)" })],
    );

    function afficherStatut(message, ton = "info") {
      monter(statutLigne, el("span", { class: "statut-ton statut-" + ton, text: message }));
    }

    const noeud = el("div", { class: "detail-groupe" }, [
      el("div", { class: "detail-groupe-tete" }, [
        pastille("EN_ATTENTE_REVUE"),
        el("span", { class: "mono", text: e.rule_id_stable }),
        el("span", { text: " — " + e.nom_regle }),
      ]),
      el("div", { class: "attaque-meta" }, [
        el("span", { class: "attaque-badge" }, [
          el("span", { class: "muet", text: "Technique : " }),
          el("span", { class: "badge-opt", text: e.technique_mitre }),
        ]),
        el("span", { class: "attaque-badge" }, [
          el("span", { class: "muet", text: "TP/FP dernière validation : " }),
          el("span", { class: "badge-opt", text: e.nb_tp + " / " + e.nb_fp }),
        ]),
      ]),
      el("p", { class: "muet", text: e.description || "" }),
      el("div", { class: "lanceur-grille" }, [
        el("span", { class: "mono muet", text: e.chemin_regle_sigma }),
        labelForcer,
      ]),
      blocConfirm,
      el("div", { class: "lanceur-grille" }, [boutonApprouver, boutonRejeter]),
      statutLigne,
    ]);

    boutonApprouver.addEventListener("click", async () => {
      if (!caseConfirm.checked) return; // bouton normalement déjà désactivé dans ce cas
      noeudsEnCours.set(e.rule_id_stable, noeud);
      boutonApprouver.disabled = true;
      boutonRejeter.disabled = true;
      afficherStatut("Revalidation et déploiement en cours…", "info");
      try {
        const r = await API.approuverRevue(e.rule_id_stable, caseForcer.checked);
        noeudsEnCours.delete(e.rule_id_stable);
        if (r.deploye) {
          afficherStatut(
            "Déployée -- TP=" + r.nb_tp + " FP=" + r.nb_fp + (r.force ? " (forcé)" : ""),
            "ok",
          );
          rafraichir();
        } else {
          afficherStatut(
            "Non déployée (" + (r.statut || "?") + ") : " + (r.raison || "raison inconnue"),
            "ko",
          );
          majBoutonApprouver();
          boutonRejeter.disabled = false;
        }
      } catch (err) {
        noeudsEnCours.delete(e.rule_id_stable);
        const msg = err.corps && err.corps.erreur ? err.corps.erreur : "Approbation impossible.";
        afficherStatut(msg, "ko");
        majBoutonApprouver();
        boutonRejeter.disabled = false;
      }
    });

    boutonRejeter.addEventListener("click", async () => {
      noeudsEnCours.set(e.rule_id_stable, noeud);
      boutonApprouver.disabled = true;
      boutonRejeter.disabled = true;
      try {
        await API.rejeterRevue(e.rule_id_stable);
        noeudsEnCours.delete(e.rule_id_stable);
        afficherStatut("Rejetée -- rien n'a été déployé.", "ok");
        rafraichir();
      } catch (err) {
        noeudsEnCours.delete(e.rule_id_stable);
        const msg = err.corps && err.corps.erreur ? err.corps.erreur : "Rejet impossible.";
        afficherStatut(msg, "ko");
        majBoutonApprouver();
        boutonRejeter.disabled = false;
      }
    });

    return noeud;
  }

  async function rafraichir() {
    if (!zoneListe.children.length) monter(zoneListe, squelette(2));
    try {
      const r = await API.revues();
      const entrees = r.revues || [];
      if (!entrees.length) {
        monter(
          zoneListe,
          etatVide("Aucune règle en attente de revue. Une entrée apparaît ici quand une découverte IA est lancée avec « Envoyer en revue avant déploiement »."),
        );
        return;
      }
      monter(zoneListe, entrees.map((e) => noeudsEnCours.get(e.rule_id_stable) || creerEntree(e)));
    } catch {
      monter(zoneListe, etatErreur(rafraichir, "File de revue indisponible."));
    }
  }

  return { element, rafraichir };
}
