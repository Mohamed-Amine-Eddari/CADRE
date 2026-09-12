/* ==========================================================================
   vues/outils.js, Onglet « Outils ». Cinq opérations de maintenance jusqu'ici
   réservées à la CLI, regroupées ici avec la MÊME logique serveur (jamais
   simulées) :
     1. Raffiner une attaque (ajuster valeur_detection/seuil_fp_max sans
        dupliquer la règle) -- `cadre raffiner`.
     2. Exporter le catalogue au format Sigma partageable -- `cadre export-sigma`.
     3. Lire / éditer / repousser une règle DÉJÀ déployée dans Kibana --
        `cadre regle lire/editer/pousser`.
     4. Ingérer Atomic Red Team (aperçu filtré, puis import optionnel au
        catalogue personnel) -- `cadre atomic [--import]`.
     5. Valider une règle Sigma EXTERNE (ex. SigmaHQ) sur la télémétrie
        réelle -- `cadre valider-regle`.
   Consomme /api/raffiner, /api/export-sigma, /api/regle/*, /api/atomic/*,
   /api/valider-regle.
   ========================================================================== */

import { el, monter, boutonCopier } from "../dom.js";
import { icone } from "../icones.js";
import { enteteSection, pastille } from "../ui.js";
import { API } from "../api.js";

export function creerOutils() {
  let idsConnus = new Set(); // liste blanche côté client pour les datalists (le serveur revalide)
  const listeIds = el("datalist", { attrs: { id: "outils-liste-ids" } });

  const element = el("div", { class: "vue" }, [
    listeIds,
    sectionRaffiner(),
    sectionExportSigma(),
    sectionRegleKibana(),
    sectionAtomic(),
    sectionValiderRegle(),
  ]);

  function statutLigne() {
    return el("div", { class: "lanceur-statut", attrs: { role: "status", "aria-live": "polite" } });
  }

  function afficherStatut(zone, message, ton = "info") {
    monter(zone, el("span", { class: "statut-ton statut-" + ton, text: message }));
  }

  function messageErreur(e, repli) {
    return e && e.corps && e.corps.erreur ? e.corps.erreur : repli;
  }

  // --- 1. Raffiner une attaque -------------------------------------------
  function sectionRaffiner() {
    const champId = el("input", {
      class: "champ",
      attrs: {
        type: "text",
        list: "outils-liste-ids",
        placeholder: "ID attaque, ex. CADRE-CRE-006",
        "aria-label": "ID de l'attaque à raffiner",
        autocomplete: "off",
        spellcheck: "false",
      },
    });
    const champValeur = el("input", {
      class: "champ",
      attrs: {
        type: "text",
        placeholder: "Nouvelle valeur de détection (optionnel)",
        "aria-label": "Nouvelle valeur de détection",
        autocomplete: "off",
        spellcheck: "false",
      },
    });
    const champSeuil = el("input", {
      class: "champ",
      attrs: {
        type: "number",
        min: "1",
        placeholder: "Nouveau seuil FP max (optionnel)",
        "aria-label": "Nouveau seuil de faux positifs",
      },
    });
    const caseReinit = el("input", { attrs: { type: "checkbox", id: "outils-raffiner-reinit" } });
    const labelReinit = el(
      "label",
      { class: "radio-pilule", attrs: { for: "outils-raffiner-reinit" } },
      [caseReinit, el("span", { text: "Réinitialiser (retirer le raffinement existant)" })],
    );
    const bouton = el("button", { class: "btn btn-primaire", attrs: { type: "button" } }, [
      el("span", { text: "Appliquer" }),
    ]);
    const statut = statutLigne();

    caseReinit.addEventListener("change", () => {
      champValeur.disabled = caseReinit.checked;
      champSeuil.disabled = caseReinit.checked;
    });

    bouton.addEventListener("click", async () => {
      const attaqueId = champId.value.trim().toUpperCase();
      if (!attaqueId) {
        afficherStatut(statut, "ID d'attaque requis.", "ko");
        return;
      }
      const corps = { attaque_id: attaqueId, reinitialiser: caseReinit.checked };
      if (!caseReinit.checked) {
        if (champValeur.value.trim()) corps.valeur_detection = champValeur.value.trim();
        if (champSeuil.value.trim()) corps.seuil_fp_max = Number(champSeuil.value);
      }
      bouton.disabled = true;
      try {
        const r = await API.raffiner(corps);
        if (r.retire) afficherStatut(statut, "Raffinement retiré -- " + attaqueId + ".", "ok");
        else afficherStatut(statut, "Raffinement enregistré -- effectif au prochain cycle.", "ok");
      } catch (e) {
        afficherStatut(statut, messageErreur(e, "Échec du raffinement."), "ko");
      } finally {
        bouton.disabled = false;
      }
    });

    return el("section", { class: "carte" }, [
      enteteSection("Raffiner une attaque", "outils"),
      el("p", {
        class: "muet",
        text: "Ajuste la valeur de détection ou le seuil de faux positifs d'une attaque EXISTANTE, sans dupliquer sa règle Kibana (rule_id stable).",
      }),
      el("div", { class: "lanceur-grille" }, [champId, champValeur, champSeuil, bouton]),
      labelReinit,
      statut,
    ]);
  }

  // --- 2. Export Sigma -----------------------------------------------------
  function sectionExportSigma() {
    const champOutput = el("input", {
      class: "champ",
      attrs: {
        type: "text",
        placeholder: "./regles_sigma_export",
        "aria-label": "Répertoire d'export",
        autocomplete: "off",
        spellcheck: "false",
      },
    });
    const bouton = el("button", { class: "btn btn-primaire", attrs: { type: "button" } }, [
      el("span", { text: "Exporter" }),
    ]);
    const statut = statutLigne();
    const zoneResultat = el("div", { class: "detail-groupe" });

    bouton.addEventListener("click", async () => {
      bouton.disabled = true;
      monter(zoneResultat, []);
      try {
        const r = await API.exporterSigma(champOutput.value.trim() || undefined);
        afficherStatut(statut, r.nb + " règle(s) exportée(s) dans " + r.repertoire + ".", "ok");
        const formats = r.formats || [];
        monter(
          zoneResultat,
          el("p", { class: "muet mono", text: formats.map((f) => f.fichier).join(", ") || "" }),
        );
      } catch (e) {
        afficherStatut(statut, messageErreur(e, "Échec de l'export."), "ko");
      } finally {
        bouton.disabled = false;
      }
    });

    return el("section", { class: "carte" }, [
      enteteSection("Exporter au format Sigma", "outils"),
      el("p", {
        class: "muet",
        text: "Écrit une règle .yml par attaque du catalogue (+ index.md, + formats multi-SIEM prêts à l'emploi) -- pour contribution ou import dans un autre outil.",
      }),
      el("div", { class: "lanceur-grille" }, [champOutput, bouton]),
      statut,
      zoneResultat,
    ]);
  }

  // --- 3. Règle déployée (Kibana) : lire / éditer / pousser ---------------
  function sectionRegleKibana() {
    const champRuleId = el("input", {
      class: "champ",
      attrs: {
        type: "text",
        list: "outils-liste-ids",
        placeholder: "ID règle Kibana, ex. CADRE-CRE-006",
        "aria-label": "ID de la règle déployée",
        autocomplete: "off",
        spellcheck: "false",
      },
    });
    const boutonCharger = el("button", { class: "btn btn-secondaire", attrs: { type: "button" } }, [
      el("span", { text: "Charger" }),
    ]);
    const zoneInfo = el("div", { class: "attaque-meta" });
    const zoneContenu = el("textarea", {
      class: "champ decouverte-desc",
      attrs: {
        rows: "10",
        placeholder: "Chargez d'abord une règle -- son YAML éditable apparaît ici.",
        "aria-label": "YAML Sigma édité",
        spellcheck: "false",
        disabled: true,
      },
    });
    const selectPipeline = el(
      "select",
      { class: "champ", attrs: { "aria-label": "Pipeline pySigma" } },
      [
        el("option", { attrs: { value: "ecs_windows" }, text: "ECS Windows" }),
        el("option", { attrs: { value: "aucun" }, text: "Aucun (Linux)" }),
      ],
    );
    const caseForcer = el("input", { attrs: { type: "checkbox", id: "outils-regle-forcer" } });
    const labelForcer = el("label", { class: "radio-pilule", attrs: { for: "outils-regle-forcer" } }, [
      caseForcer,
      el("span", { text: "Forcer (déployer même si la revalidation échoue)" }),
    ]);
    // Même patron que catalogue.js/lanceur.js/decouverte.js : un déploiement
    // RÉEL (pas de mode simulé possible ici) exige une confirmation
    // explicite, distincte de "Forcer" -- jusqu'ici un simple clic sur
    // "Pousser vers Kibana" suffisait à écraser une règle vivante en prod.
    const caseConfirm = el("input", { attrs: { type: "checkbox" }, on: { change: majBoutonPousser } });
    const blocConfirm = el("label", { class: "confirm-reel" }, [
      caseConfirm,
      el("span", { text: "Je confirme le déploiement " }),
      el("strong", { text: "réel" }),
      el("span", { text: " de cette règle dans Kibana." }),
    ]);
    const boutonPousser = el("button", {
      class: "btn btn-primaire",
      attrs: { type: "button", disabled: true },
    }, [el("span", { text: "Pousser vers Kibana" })]);

    function majBoutonPousser() {
      boutonPousser.disabled = !ruleIdCharge || !caseConfirm.checked;
    }
    const statut = statutLigne();
    let cheminCharge = null;
    // ID RÉELLEMENT chargé (capturé au succès de "Charger"), distinct de
    // `champRuleId.value` qui peut changer sous les pieds de l'utilisateur
    // avant qu'il ne clique "Pousser". Sans cette capture, "Pousser" relisait
    // le champ EN DIRECT : si l'ID était modifié après un chargement réussi
    // (sans recliquer "Charger"), le YAML de l'ancienne règle partait vers
    // l'ID Kibana réel de la nouvelle -- écrasement silencieux d'une règle de
    // détection en production par la logique d'une autre technique MITRE.
    let ruleIdCharge = null;

    function invaliderChargementSiIdChange() {
      if (ruleIdCharge !== null && champRuleId.value.trim() !== ruleIdCharge) {
        ruleIdCharge = null;
        cheminCharge = null;
        zoneContenu.disabled = true;
        zoneContenu.value = "";
        majBoutonPousser();
        afficherStatut(statut, "ID modifié -- rechargez avant de pousser.", "info");
      }
    }
    champRuleId.addEventListener("input", invaliderChargementSiIdChange);

    boutonCharger.addEventListener("click", async () => {
      const ruleId = champRuleId.value.trim();
      if (!ruleId) {
        afficherStatut(statut, "ID de règle requis.", "ko");
        return;
      }
      boutonCharger.disabled = true;
      monter(zoneInfo, []);
      try {
        const [infos, edition] = await Promise.all([
          API.lireRegle(ruleId),
          API.preparerEditionRegle(ruleId),
        ]);
        monter(zoneInfo, [
          badgeMeta("Nom Kibana", infos.regle && infos.regle.name),
          badgeMeta("Activée", infos.regle && String(!!infos.regle.enabled)),
          badgeMeta("Index", infos.regle && (infos.regle.index || []).join(", ")),
        ]);
        zoneContenu.disabled = false;
        zoneContenu.value = edition.contenu;
        cheminCharge = edition.chemin;
        ruleIdCharge = ruleId;
        majBoutonPousser();
        afficherStatut(statut, "Règle chargée -- éditez le YAML puis poussez.", "ok");
      } catch (e) {
        zoneContenu.disabled = true;
        zoneContenu.value = "";
        cheminCharge = null;
        ruleIdCharge = null;
        majBoutonPousser();
        afficherStatut(statut, messageErreur(e, "Règle introuvable dans Kibana."), "ko");
      } finally {
        boutonCharger.disabled = false;
      }
    });

    boutonPousser.addEventListener("click", async () => {
      if (!ruleIdCharge || !caseConfirm.checked) return; // bouton normalement déjà désactivé dans ce cas
      boutonPousser.disabled = true;
      try {
        const r = await API.pousserRegle({
          rule_id: ruleIdCharge,
          contenu: zoneContenu.value,
          fichier: cheminCharge,
          pipeline: selectPipeline.value,
          forcer: caseForcer.checked,
        });
        if (r.deploye) {
          afficherStatut(
            statut,
            "Déployée -- TP=" + r.nb_tp + " FP=" + r.nb_fp + (r.force ? " (forcé)" : ""),
            "ok",
          );
        } else {
          afficherStatut(statut, (r.statut || "?") + " : " + r.raison, "ko");
        }
      } catch (e) {
        afficherStatut(statut, messageErreur(e, "Échec du déploiement."), "ko");
      } finally {
        majBoutonPousser();
      }
    });

    return el("section", { class: "carte" }, [
      enteteSection("Éditer une règle déployée", "outils"),
      el("p", {
        class: "muet",
        text: "Édition encadrée d'une règle DÉJÀ vivante dans Kibana : le YAML édité est revalidé (TP/FP) avant tout redéploiement -- jamais un simple remplacement aveugle.",
      }),
      el("div", { class: "lanceur-grille" }, [champRuleId, boutonCharger]),
      zoneInfo,
      zoneContenu,
      el("div", { class: "lanceur-grille" }, [selectPipeline, labelForcer]),
      blocConfirm,
      el("div", { class: "lanceur-grille" }, [boutonPousser]),
      statut,
    ]);
  }

  function badgeMeta(libelle, valeur) {
    return el("span", { class: "attaque-badge" }, [
      el("span", { class: "muet", text: libelle + " : " }),
      el("span", { class: "badge-opt", text: valeur || "—" }),
    ]);
  }

  // --- 4. Atomic Red Team : aperçu / import --------------------------------
  function sectionAtomic() {
    const champRepo = el("input", {
      class: "champ",
      attrs: {
        type: "text",
        placeholder: "Répertoire du dépôt (optionnel, défaut : exemples embarqués)",
        "aria-label": "Répertoire Atomic Red Team",
        autocomplete: "off",
        spellcheck: "false",
      },
    });
    const selectPlateforme = el(
      "select",
      { class: "champ", attrs: { "aria-label": "Filtrer par plateforme" } },
      [
        el("option", { attrs: { value: "" }, text: "Toutes plateformes" }),
        el("option", { attrs: { value: "windows" }, text: "Windows" }),
        el("option", { attrs: { value: "linux" }, text: "Linux" }),
      ],
    );
    const champTechniques = el("input", {
      class: "champ",
      attrs: {
        type: "text",
        placeholder: "Techniques MITRE, séparées par des virgules (optionnel)",
        "aria-label": "Filtrer par technique MITRE",
        autocomplete: "off",
        spellcheck: "false",
      },
    });
    const boutonApercu = el("button", { class: "btn btn-secondaire", attrs: { type: "button" } }, [
      el("span", { text: "Aperçu" }),
    ]);
    const boutonImporter = el("button", { class: "btn btn-primaire", attrs: { type: "button" } }, [
      el("span", { text: "Importer au catalogue" }),
    ]);
    const statut = statutLigne();
    const zoneResultat = el("div", { class: "decouverte-liste" });

    function parametres() {
      const techniques = champTechniques.value
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean);
      return {
        repo: champRepo.value.trim() || undefined,
        platform: selectPlateforme.value || undefined,
        techniques,
      };
    }

    function rendreApercu(r) {
      const retenus = r.retenus || [];
      const refuses = r.refuses || [];
      monter(
        zoneResultat,
        retenus
          .map((b) =>
            el("div", { class: "decouverte-item" }, [
              el("span", { class: "badge-opt", text: "retenu" }),
              el("div", {}, [
                el("div", {}, [
                  el("span", { class: "mono", text: b.id }),
                  el("span", { text: " — " + b.nom }),
                ]),
                el("div", { class: "muet mono", text: b.technique_mitre + " · " + b.plateforme }),
              ]),
            ]),
          )
          .concat(
            refuses.map((rf) =>
              el("div", { class: "decouverte-item" }, [
                el("span", { class: "badge-crit", text: "refusé" }),
                el("div", {}, [
                  el("div", { text: rf.nom }),
                  el("div", { class: "muet", text: rf.technique + " · " + rf.motif }),
                ]),
              ]),
            ),
          ),
      );
    }

    boutonApercu.addEventListener("click", async () => {
      boutonApercu.disabled = true;
      monter(zoneResultat, []);
      try {
        const r = await API.apercuAtomic(parametres());
        afficherStatut(
          statut,
          (r.retenus || []).length + " retenu(s), " + (r.refuses || []).length +
            " refusé(s) sur " + r.total_lus + " lu(s).",
          "ok",
        );
        rendreApercu(r);
      } catch (e) {
        afficherStatut(statut, messageErreur(e, "Aperçu impossible."), "ko");
      } finally {
        boutonApercu.disabled = false;
      }
    });

    boutonImporter.addEventListener("click", async () => {
      boutonImporter.disabled = true;
      try {
        const r = await API.importerAtomic(parametres());
        afficherStatut(
          statut,
          r.ajoutes + " ajouté(s) au catalogue personnel" +
            (r.deja_presents ? ", " + r.deja_presents + " déjà présent(s)" : "") + ".",
          "ok",
        );
        rendreApercu(r);
      } catch (e) {
        afficherStatut(statut, messageErreur(e, "Import impossible."), "ko");
      } finally {
        boutonImporter.disabled = false;
      }
    });

    return el("section", { class: "carte" }, [
      enteteSection("Atomic Red Team", "outils"),
      el("p", {
        class: "muet",
        text: "Ingère des tests Atomic Red Team comme source d'attaques -- filtrés par le même garde-fou anti-destruction que la Découverte IA. L'aperçu ne persiste rien ; l'import les ajoute au catalogue personnel.",
      }),
      el("div", { class: "lanceur-grille" }, [champRepo, selectPlateforme, champTechniques]),
      el("div", { class: "lanceur-grille" }, [boutonApercu, boutonImporter]),
      statut,
      zoneResultat,
    ]);
  }

  // --- 5. Valider une règle Sigma externe -----------------------------------
  function sectionValiderRegle() {
    const zoneContenu = el("textarea", {
      class: "champ decouverte-desc",
      attrs: {
        rows: "8",
        placeholder: "Collez ici le YAML d'une règle Sigma externe (ex. SigmaHQ) à valider sur votre télémétrie.",
        "aria-label": "YAML Sigma à valider",
        spellcheck: "false",
      },
    });
    const champJours = el("input", {
      class: "champ",
      attrs: { type: "number", min: "1", placeholder: "Fenêtre (jours), défaut 7", "aria-label": "Fenêtre d'analyse en jours" },
    });
    const champSeuil = el("input", {
      class: "champ",
      attrs: { type: "number", min: "1", placeholder: "Seuil de bruit, défaut 100", "aria-label": "Seuil de bruit" },
    });
    const bouton = el("button", { class: "btn btn-primaire", attrs: { type: "button" } }, [
      el("span", { text: "Valider" }),
    ]);
    const statut = statutLigne();
    const zoneResultat = el("div", { class: "detail-groupe" });

    bouton.addEventListener("click", async () => {
      const contenu = zoneContenu.value.trim();
      if (!contenu) {
        afficherStatut(statut, "Collez d'abord un YAML Sigma.", "ko");
        return;
      }
      bouton.disabled = true;
      monter(zoneResultat, []);
      try {
        const r = await API.validerRegle({
          contenu,
          jours: champJours.value.trim() ? Number(champJours.value) : undefined,
          seuil: champSeuil.value.trim() ? Number(champSeuil.value) : undefined,
        });
        monter(statut, []);
        const lignes = [
          el("div", { class: "detail-groupe-tete" }, [
            pastille(r.verdict),
            r.hits != null ? el("span", { class: "muet", text: r.hits + " correspondance(s)" }) : null,
          ]),
        ];
        if (r.requete_lucene) {
          const btn = boutonCopier(r.requete_lucene, "Copier la requête Lucene");
          btn.append(icone("copy", { taille: 12 }));
          lignes.push(el("div", { class: "mono muet" }, [r.requete_lucene, btn]));
        }
        if (r.detail) lignes.push(el("p", { class: "muet", text: r.detail }));
        monter(zoneResultat, lignes);
      } catch (e) {
        afficherStatut(statut, messageErreur(e, "Validation impossible."), "ko");
      } finally {
        bouton.disabled = false;
      }
    });

    return el("section", { class: "carte" }, [
      enteteSection("Valider une règle Sigma externe", "outils"),
      el("p", {
        class: "muet",
        text: "Valide une règle Sigma qui n'est PAS issue de CADRE (ex. téléchargée sur SigmaHQ) contre votre télémétrie réelle : compile, compte les correspondances, et rend un verdict (active / silencieuse / bruyante / non compilable).",
      }),
      zoneContenu,
      el("div", { class: "lanceur-grille" }, [champJours, champSeuil, bouton]),
      statut,
      zoneResultat,
    ]);
  }

  async function rafraichir() {
    // Charge la liste blanche des IDs une seule fois (datalists ID attaque
    // / rule_id) -- même patron que lanceur.js pour les techniques MITRE.
    if (idsConnus.size) return;
    try {
      const cat = await API.catalogue();
      const ids = (cat.attaques || []).map((a) => a.id).sort();
      idsConnus = new Set(ids);
      monter(listeIds, ids.map((id) => el("option", { attrs: { value: id } })));
    } catch {
      /* datalist optionnelle */
    }
  }

  return { element, rafraichir };
}
