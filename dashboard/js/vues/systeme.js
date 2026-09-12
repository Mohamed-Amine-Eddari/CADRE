/* ==========================================================================
   vues/systeme.js, Onglet « Système ». Santé de la stack (pré-vol) + état des
   secrets (masqués : présence seulement, jamais la valeur). Consomme
   /api/verifier et /api/secrets.
   ========================================================================== */

import { el, monter } from "../dom.js";
import { enteteSection, puceSante, squelette, etatErreur } from "../ui.js";
import { API } from "../api.js";

export function creerSysteme() {
  const sante = el("div", { class: "sante-liste" });
  const secrets = el("div", { class: "secrets-liste" });
  let derniereListe = [];
  // Une seule clé éditée à la fois — jamais deux formulaires ouverts en
  // même temps (évite toute confusion sur quelle valeur part où).
  let cleEnEdition = null;
  let messageEdition = null; // { cle, texte, ok } — retour bref après un enregistrement

  const element = el("div", { class: "vue" }, [
    el("section", { class: "carte" }, [enteteSection("Santé de la stack"), sante]),
    el("section", { class: "carte" }, [
      enteteSection("Secrets configurés"),
      el("p", {
        class: "aide muet",
        text: "Présence uniquement, aucune valeur n'est exposée. Configurez ce que vous voulez, laissez le reste tel quel.",
      }),
      secrets,
    ]),
  ]);

  async function majSante() {
    try {
      const d = await API.verifier();
      const items = (d.points || []).map((p) =>
        el("div", { class: "sante-item" + (p.ok ? " est-ok" : p.optionnel ? " est-opt" : " est-ko") }, [
          puceSante(!!p.ok, { inconnu: p.optionnel && !p.ok }),
          el("span", { class: "sante-nom", text: p.nom }),
          el("span", { class: "sante-detail muet", text: p.detail || "" }),
          p.optionnel ? el("span", { class: "badge-opt", text: "optionnel" }) : null,
        ]),
      );
      monter(sante, items.length ? items : etatErreur(majSante));
    } catch {
      monter(sante, etatErreur(majSante, "Vérification indisponible."));
    }
  }

  function retourPour(s) {
    return messageEdition && messageEdition.cle === s.cle
      ? el("span", {
          class: "secret-retour" + (messageEdition.ok ? " est-ok" : " est-ko"),
          text: messageEdition.texte,
        })
      : null;
  }

  function rendreSecretLigne(s) {
    if (cleEnEdition === s.cle) {
      // Mode édition : champ masqué pour les secrets critiques (mots de
      // passe), texte visible pour IP/utilisateur — plus pratique à
      // relire en tapant, et non sensible.
      const champ = el("input", {
        class: "champ champ-secret",
        attrs: {
          type: s.critique ? "password" : "text",
          placeholder: s.critique ? "Nouvelle valeur (masquée)" : "Nouvelle valeur",
          "aria-label": "Nouvelle valeur pour " + s.cle,
          autocomplete: "new-password",
          spellcheck: "false",
        },
      });
      const boutonSauver = el("button", { class: "btn btn-primaire", attrs: { type: "button" } }, [
        el("span", { text: "Enregistrer" }),
      ]);
      const boutonAnnuler = el("button", { class: "btn btn-secondaire", attrs: { type: "button" } }, [
        el("span", { text: "Annuler" }),
      ]);
      boutonAnnuler.addEventListener("click", () => {
        champ.value = ""; // jamais laisser une saisie annulée trainer, même localement
        cleEnEdition = null;
        rendreSecrets(derniereListe);
      });
      boutonSauver.addEventListener("click", async () => {
        const valeur = champ.value;
        if (!valeur) return;
        boutonSauver.disabled = true;
        boutonAnnuler.disabled = true;
        try {
          await API.definirSecret(s.cle, valeur);
          champ.value = ""; // effacé immédiatement après l'envoi, succès ou non
          messageEdition = { cle: s.cle, texte: "Enregistré.", ok: true };
          cleEnEdition = null;
          await majSecrets(); // re-vérifie l'état réel auprès du serveur, pas supposé
        } catch {
          champ.value = "";
          messageEdition = { cle: s.cle, texte: "Échec de l'enregistrement — réessayez.", ok: false };
          boutonSauver.disabled = false;
          boutonAnnuler.disabled = false;
          // Sans ce re-rendu, le message restait invisible : on reste en
          // mode édition (cleEnEdition inchangé sur un échec, exprès --
          // l'utilisateur ne doit pas avoir à recliquer "Configurer" pour
          // réessayer), mais le sondage périodique (majSecrets, gelé tant
          // que cleEnEdition est actif) ne redessine plus rien tout seul.
          rendreSecrets(derniereListe);
        }
      });
      champ.addEventListener("keydown", (e) => {
        if (e.key === "Enter") boutonSauver.click();
        if (e.key === "Escape") boutonAnnuler.click();
      });
      return el("div", { class: "secret-item secret-item-edition" }, [
        puceSante(!!s.configure, { inconnu: !s.configure }),
        el("span", { class: "secret-cle mono", text: s.cle }),
        champ,
        boutonSauver,
        boutonAnnuler,
        retourPour(s),
      ]);
    }

    const boutonConfigurer = el("button", { class: "btn-secret-toggle", attrs: { type: "button" } }, [
      el("span", { text: s.configure ? "Modifier" : "Configurer" }),
    ]);
    boutonConfigurer.addEventListener("click", () => {
      cleEnEdition = s.cle;
      messageEdition = null;
      rendreSecrets(derniereListe);
    });
    return el("div", { class: "secret-item" }, [
      puceSante(!!s.configure, { inconnu: !s.configure }),
      el("span", { class: "secret-cle mono", text: s.cle }),
      el("span", { class: "secret-lib muet", text: s.libelle || "" }),
      s.critique ? el("span", { class: "badge-crit", text: "critique" }) : null,
      el("span", { class: "secret-etat", text: s.configure ? "configuré" : "manquant" }),
      boutonConfigurer,
      retourPour(s),
    ]);
  }

  function rendreSecrets(liste) {
    const items = liste.map(rendreSecretLigne);
    monter(secrets, items.length ? items : el("p", { class: "muet", text: "Aucun secret attendu." }));
  }

  async function majSecrets() {
    // Le rafraîchissement périodique (toutes les 9s, app.js) ne doit
    // jamais reconstruire la liste pendant qu'un champ est en cours
    // d'édition -- `rendreSecretLigne` recrée l'<input> à chaque rendu, ce
    // qui effacerait silencieusement toute saisie en cours (aucune valeur
    // tapée n'est conservée entre deux rendus). On gèle tout le panneau
    // secrets tant qu'une édition est active plutôt que de perdre la
    // saisie de l'utilisateur.
    if (cleEnEdition) return;
    try {
      const d = await API.secrets();
      derniereListe = d.secrets || d || [];
      rendreSecrets(derniereListe);
    } catch {
      monter(secrets, etatErreur(majSecrets, "Secrets indisponibles."));
    }
  }

  async function rafraichir() {
    if (!sante.children.length) monter(sante, squelette(3));
    await Promise.all([majSante(), majSecrets()]);
  }

  return { element, rafraichir };
}
