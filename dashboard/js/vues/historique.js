/* ==========================================================================
   vues/historique.js, Historique des cycles (table dense) + détail au clic.
   Détail = résultats groupés par statut (technique, TP, FP, raison, EventID)
   + liens vers les rapports complets (HTML/CSV/MD/Navigator) où figure la
   règle Sigma générée. Écoute `cadre:technique` (clic matrice) pour surligner.
   Chaque ligne d'attaque est elle-même cliquable -> fiche complète (payload +
   métadonnées), même contenu que la fiche du Catalogue (/api/catalogue/{id}) --
   le CSV de cycle porte l'id exact de l'attaque exécutée.
   Consomme /api/cycles, /api/cycles/{id}, /api/catalogue/{id}.
   ========================================================================== */

import { el, monter, boutonCopier } from "../dom.js";
import { icone } from "../icones.js";
import { pastille, squelette, etatVide, etatErreur, enteteSection, th, badge } from "../ui.js";
import { horodatageCourt, tempsRelatif, nombre } from "../format.js";
import { API } from "../api.js";

const LIENS = [
  { suffixe: ".html", label: "HTML", cle: "html_disponible", nomFichier: (h) => "cycle_" + h + ".html" },
  { suffixe: ".md", label: "MD", cle: "markdown_disponible", nomFichier: (h) => "cycle_" + h + ".md" },
  { suffixe: ".csv", label: "CSV", cle: null, nomFichier: (h) => "cycle_" + h + ".csv" },
  { suffixe: ".pdf", label: "PDF", cle: "pdf_disponible", nomFichier: (h) => "cycle_" + h + ".pdf", telecharger: true },
  { suffixe: ".json", label: "Navigator", cle: "navigator_disponible", nomFichier: (h) => "cycle_" + h + "_navigator.json" },
];

export function creerHistorique() {
  let techniqueSurlignee = null;
  let horodatageOuvert = null;
  let idAttaqueOuverte = null;
  const corpsTable = el("tbody");
  const zoneDetail = el("div", { class: "cycle-detail" });
  const zoneAttaqueDetail = el("div", { class: "cycle-detail attaque-detail-zone" });

  const table = el("table", { class: "table-cycles" }, [
    el("thead", {}, [
      el("tr", {}, [
        th("Cycle"),
        th("Total"),
        th("Répartition"),
        th("Rapports"),
      ]),
    ]),
    corpsTable,
  ]);

  const element = el("section", { class: "carte" }, [
    enteteSection("Historique des cycles", "clock"),
    el("div", { class: "table-wrap" }, [table]),
    zoneDetail,
    zoneAttaqueDetail,
  ]);

  document.addEventListener("cadre:technique", (e) => {
    techniqueSurlignee = e.detail?.technique || null;
    element.scrollIntoView({ behavior: "smooth", block: "start" });
    // Ouvre le cycle le plus récent et surligne la technique.
    const premier = corpsTable.querySelector("tr.ligne-cycle");
    if (premier) premier.click();
  });

  function rendreListe(cycles) {
    if (!cycles.length) {
      monter(corpsTable, el("tr", {}, [el("td", { attrs: { colspan: 4 } }, [etatVide("Aucun cycle exécuté pour l'instant.")])]));
      return;
    }
    const rangs = cycles.map((c) => {
      const repartition = el("div", { class: "repartition" },
        Object.entries(c.compteurs || {}).map(([st, n]) =>
          el("span", { class: "rep-seg", title: st + " : " + n }, [pastille(st, { court: true }), el("span", { class: "rep-n", text: nombre(n) })]),
        ),
      );
      const liens = el("div", { class: "cycle-liens" },
        LIENS.filter((l) => l.cle === null || c[l.cle]).map((l) =>
          el(
            "a",
            {
              class: "lien-rapport",
              attrs: {
                href: "/rapports/" + l.nomFichier(c.horodatage),
                target: l.telecharger ? null : "_blank",
                download: l.telecharger ? true : null,
                rel: "noopener",
                title: (l.telecharger ? "Télécharger " : "Ouvrir ") + l.label,
              },
              on: { click: (ev) => ev.stopPropagation() },
            },
            [icone(l.telecharger ? "download" : "external-link", { taille: 12 }), el("span", { text: l.label })],
          ),
        ),
      );
      // Réapplique le surlignage "ouvert" après un rafraîchissement
      // périodique (l'onglet est resondé toutes les 9s, app.js) : sans ça,
      // `monter(corpsTable, rangs)` juste en dessous reconstruit toutes les
      // lignes à neuf et perdait silencieusement la mise en évidence de la
      // ligne dont le détail reste pourtant affiché sous le tableau -- même
      // patron déjà corrigé côté catalogue.js (idOuvert).
      const classes = "ligne-cycle" + (c.horodatage === horodatageOuvert ? " est-ouvert" : "");
      const tr = el("tr", { class: classes, attrs: { tabindex: "0", role: "button", "aria-label": "Détail du cycle " + horodatageCourt(c.horodatage) } }, [
        el("td", {}, [el("span", { class: "cycle-h", text: horodatageCourt(c.horodatage) }), el("span", { class: "cycle-rel", text: tempsRelatif(c.horodatage) })]),
        el("td", { class: "num", text: nombre(c.total) }),
        el("td", {}, [repartition]),
        el("td", {}, [liens]),
      ]);
      const ouvrir = () => ouvrirDetail(c.horodatage, tr);
      tr.addEventListener("click", ouvrir);
      tr.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); ouvrir(); }
      });
      return tr;
    });
    monter(corpsTable, rangs);
  }

  async function ouvrirDetail(horodatage, tr) {
    corpsTable.querySelectorAll("tr.est-ouvert").forEach((r) => r.classList.remove("est-ouvert"));
    tr.classList.add("est-ouvert");
    horodatageOuvert = horodatage;
    // Un autre cycle s'ouvre : la fiche attaque affichée (si une l'était)
    // appartenait à une ligne qui n'est plus visible -- ne pas la laisser
    // orpheline sous un cycle différent.
    idAttaqueOuverte = null;
    monter(zoneAttaqueDetail, []);
    monter(zoneDetail, squelette(2));
    try {
      const d = await API.cycle(horodatage);
      // Une réponse plus lente pour un clic précédent peut arriver après
      // qu'un autre cycle a déjà été ouvert -- ne jamais écraser le
      // panneau avec des données qui ne correspondent plus à la ligne
      // surlignée.
      if (horodatage !== horodatageOuvert) return;
      rendreDetail(d);
    } catch {
      if (horodatage !== horodatageOuvert) return;
      monter(zoneDetail, etatErreur(() => ouvrirDetail(horodatage, tr), "Détail du cycle indisponible."));
    }
  }

  function rendreDetail(d) {
    const sections = [];
    for (const [statut, lignes] of Object.entries(d.groupes || {})) {
      if (!lignes.length) continue;
      const rangs = lignes.map((li) => {
        const eids = li.event_ids_attendus || "";
        const classes = [
          "ligne-attaque-historique",
          techniqueSurlignee && li.technique_mitre === techniqueSurlignee ? "est-surligne" : "",
        ].filter(Boolean).join(" ");
        const tr = el(
          "tr",
          {
            class: classes,
            attrs: li.id
              ? { tabindex: "0", role: "button", "aria-label": "Détail de l'attaque " + (li.technique_mitre || li.id) }
              : {},
          },
          [
            el("td", { class: "mono", text: li.technique_mitre || "" }),
            el("td", { text: li.description || li.tactique || "" }),
            el("td", { class: "num", text: li.nb_tp ?? "—" }),
            el("td", { class: "num", text: li.nb_fp ?? "—" }),
            el("td", {}, eids ? [el("code", { class: "mono", text: eids }), boutonCopierIco(eids)] : [el("span", { class: "muet", text: "—" })]),
            el("td", { class: "cell-raison", text: li.raison || "" }),
          ],
        );
        // Pas d'id (ligne historique très ancienne, avant que le CSV ne le
        // porte) : ligne non cliquable plutôt qu'un clic qui échoue toujours.
        if (li.id) {
          const ouvrir = () => ouvrirDetailAttaque(li.id, tr);
          tr.addEventListener("click", (ev) => {
            if (ev.target.closest("button")) return; // ne pas intercepter le bouton "Copier"
            ouvrir();
          });
          tr.addEventListener("keydown", (ev) => {
            if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); ouvrir(); }
          });
        }
        return tr;
      });
      sections.push(
        el("div", { class: "detail-groupe" }, [
          el("div", { class: "detail-groupe-tete" }, [pastille(statut), el("span", { class: "muet", text: "(" + lignes.length + ")" })]),
          el("div", { class: "table-wrap" }, [
            el("table", { class: "table-detail" }, [
              el("thead", {}, [el("tr", {}, [th("Technique"), th("Description"), th("TP"), th("FP"), th("EventID"), th("Raison")])]),
              el("tbody", {}, rangs),
            ]),
          ]),
        ]),
      );
    }
    monter(zoneDetail, el("div", { class: "detail-entete", text: "Cycle du " + horodatageCourt(d.horodatage) + " · " + nombre(d.total) + " attaque(s)" }), sections.length ? sections : etatVide("Cycle vide."));
  }

  async function ouvrirDetailAttaque(id, tr) {
    zoneDetail.querySelectorAll("tr.est-ouvert-attaque").forEach((r) => r.classList.remove("est-ouvert-attaque"));
    tr.classList.add("est-ouvert-attaque");
    idAttaqueOuverte = id;
    monter(zoneAttaqueDetail, squelette(3));
    zoneAttaqueDetail.scrollIntoView({ behavior: "smooth", block: "nearest" });
    try {
      const d = await API.detailAttaque(id);
      // Une réponse plus lente pour un clic précédent peut arriver après
      // qu'une autre attaque (ou un autre cycle) a déjà été ouverte --
      // ne jamais écraser un panneau qui ne correspond plus à la ligne
      // surlignée.
      if (id !== idAttaqueOuverte) return;
      rendreDetailAttaque(d);
    } catch (e) {
      if (id !== idAttaqueOuverte) return;
      const messageIntrouvable = e.corps && e.corps.erreur === "attaque introuvable";
      monter(
        zoneAttaqueDetail,
        messageIntrouvable
          ? etatVide("Cette attaque n'existe plus dans le catalogue (supprimée ou modifiée depuis ce cycle).")
          : etatErreur(() => ouvrirDetailAttaque(id, tr), "Détail de l'attaque indisponible."),
      );
    }
  }

  function rendreDetailAttaque(d) {
    // Même fiche que le Catalogue (payload + métadonnées) -- l'utilisateur a
    // explicitement demandé CETTE attaque exécutée à CE cycle précis.
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

    monter(zoneAttaqueDetail, [
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
    ]);
  }

  async function rafraichir() {
    if (!corpsTable.children.length) monter(corpsTable, el("tr", {}, [el("td", { attrs: { colspan: 4 } }, [squelette(3)])]));
    try {
      const d = await API.cycles();
      rendreListe(d.cycles || []);
    } catch {
      monter(corpsTable, el("tr", {}, [el("td", { attrs: { colspan: 4 } }, [etatErreur(rafraichir, "Historique indisponible.")])]));
    }
  }

  return { element, rafraichir };
}

function boutonCopierIco(valeur) {
  const b = boutonCopier(valeur, "Copier");
  b.append(icone("copy", { taille: 12 }));
  return b;
}
