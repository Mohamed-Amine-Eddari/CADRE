/* ==========================================================================
   api.js, Accès aux endpoints du backend CADRE.
   --------------------------------------------------------------------------
   Toute requête porte l'en-tête custom `X-CADRE-Local: 1`. C'est un garde-fou
   CSRF : une page tierce malveillante ne peut PAS ajouter cet en-tête sur une
   « simple request » sans déclencher un pré-vol CORS que le serveur refuse.
   Le serveur exige cet en-tête (+ Origin/Host loopback) sur toute action POST.
   ========================================================================== */

const ENTETE_LOCAL = { "X-CADRE-Local": "1" };

export class ErreurApi extends Error {
  constructor(statut, chemin, corps) {
    super("HTTP " + statut + " sur " + chemin);
    this.statut = statut;
    this.chemin = chemin;
    this.corps = corps || {};
  }
}

// Session expirée/absente en cours d'usage (cookie de connexion périmé, ou
// verrouillage anti-brute-force) -- retour à "/" plutôt qu'un plantage
// silencieux de la vue en cours : le serveur y sert alors la page de
// connexion (voir dashboard.py::_exiger_auth). Un seul rechargement, pas de
// boucle : la page de connexion elle-même n'appelle jamais l'API sondée ici.
function gererSessionExpiree(statut) {
  if (statut === 401) {
    window.location.href = "/";
  }
}

export async function apiGet(chemin) {
  const r = await fetch(chemin, { headers: ENTETE_LOCAL, cache: "no-store" });
  if (!r.ok) {
    gererSessionExpiree(r.status);
    throw new ErreurApi(r.status, chemin);
  }
  return r.json();
}

export async function apiPost(chemin, corps) {
  const r = await fetch(chemin, {
    method: "POST",
    headers: { ...ENTETE_LOCAL, "Content-Type": "application/json" },
    body: JSON.stringify(corps || {}),
    cache: "no-store",
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    gererSessionExpiree(r.status);
    throw new ErreurApi(r.status, chemin, data);
  }
  return data;
}

// Raccourcis typés (un par endpoint consommé par les vues).
export const API = {
  statut: () => apiGet("/api/statut"),
  verifier: () => apiGet("/api/verifier"),
  metriques: () => apiGet("/api/metriques"),
  derive: () => apiGet("/api/derive"),
  matrice: () => apiGet("/api/matrice"),
  catalogue: () => apiGet("/api/catalogue"),
  stats: () => apiGet("/api/stats"),
  detailAttaque: (id) => apiGet("/api/catalogue/" + encodeURIComponent(id)),
  cycles: () => apiGet("/api/cycles"),
  cycle: (id) => apiGet("/api/cycles/" + encodeURIComponent(id)),
  dernierCycle: () => apiGet("/api/cycle/dernier"),
  cycleStatut: () => apiGet("/api/cycle/statut"),
  logs: (n = 40) => apiGet("/api/logs?n=" + n),
  secrets: () => apiGet("/api/secrets"),
  definirSecret: (cle, valeur) => apiPost("/api/secrets", { cle, valeur }),
  lancerCycle: (corps) => apiPost("/api/cycle/lancer", corps),
  lancerAttaque: (corps) => apiPost("/api/attaque/lancer", corps),
  decouverteStatut: () => apiGet("/api/decouverte/statut"),
  lancerDecouverte: (corps) => apiPost("/api/decouverte/lancer", corps),
  revues: () => apiGet("/api/revue"),
  approuverRevue: (ruleId, forcer = false) =>
    apiPost("/api/revue/approuver", { rule_id: ruleId, forcer }),
  rejeterRevue: (ruleId) => apiPost("/api/revue/rejeter", { rule_id: ruleId }),
  raffiner: (corps) => apiPost("/api/raffiner", corps),
  exporterSigma: (output) => apiPost("/api/export-sigma", { output }),
  lireRegle: (ruleId) => apiGet("/api/regle/" + encodeURIComponent(ruleId)),
  preparerEditionRegle: (ruleId, fichier) =>
    apiGet(
      "/api/regle/" +
        encodeURIComponent(ruleId) +
        "/editer" +
        (fichier ? "?fichier=" + encodeURIComponent(fichier) : ""),
    ),
  pousserRegle: (corps) => apiPost("/api/regle/pousser", corps),
  apercuAtomic: ({ repo, platform, techniques } = {}) => {
    const qs = new URLSearchParams();
    if (repo) qs.set("repo", repo);
    if (platform) qs.set("platform", platform);
    if (techniques && techniques.length) qs.set("technique", techniques.join(","));
    const suffixe = qs.toString();
    return apiGet("/api/atomic/apercu" + (suffixe ? "?" + suffixe : ""));
  },
  importerAtomic: (corps) => apiPost("/api/atomic/importer", corps),
  validerRegle: (corps) => apiPost("/api/valider-regle", corps),
};
