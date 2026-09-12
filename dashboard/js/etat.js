/* ==========================================================================
   etat.js, Sondeur de polling léger.
   Appelle une fonction async à intervalle régulier, sans chevauchement, et se
   met en pause quand l'onglet est masqué (économie + pas de charge inutile).

   `onEchecPersistant` (optionnel) : les sondeurs GLOBAUX toujours actifs
   (bandeau de santé, vue active, cycle -- app.js) doivent réessayer
   indéfiniment, c'est le comportement historique. Mais un sondeur PAR ACTION
   (lancer une attaque/découverte, catalogue.js/decouverte.js) ne doit pas
   laisser un bouton désactivé indéfiniment si le réseau/backend est
   injoignable de façon répétée -- sans ce callback, rien ne redonne jamais
   la main à l'utilisateur (seul un F5 le pouvait). Désactivé par défaut
   (comportement inchangé pour tout appelant existant) ; un sondeur qui le
   fournit s'arrête et prévient l'appelant après N échecs consécutifs.
   ========================================================================== */

export function sondeur(fn, intervalleMs, { maxEchecsConsecutifs = Infinity, onEchecPersistant } = {}) {
  let timer = null;
  let enCours = false;
  let arrete = true;
  let echecsConsecutifs = 0;

  async function tick() {
    if (enCours) return; // pas de chevauchement si la réponse traîne
    enCours = true;
    try {
      await fn();
      echecsConsecutifs = 0;
    } catch {
      /* l'appelant gère l'affichage d'erreur ; le sondeur, lui, continue
         -- sauf si un seuil d'échecs consécutifs est fourni (voir plus haut). */
      echecsConsecutifs += 1;
      if (echecsConsecutifs >= maxEchecsConsecutifs) {
        stopper();
        if (onEchecPersistant) onEchecPersistant();
      }
    } finally {
      enCours = false;
    }
  }

  function planifier() {
    clearInterval(timer);
    timer = setInterval(tick, intervalleMs);
  }

  function demarrer() {
    if (!arrete) return;
    arrete = false;
    echecsConsecutifs = 0;
    tick();
    planifier();
  }

  function stopper() {
    arrete = true;
    clearInterval(timer);
  }

  // Pause automatique quand l'onglet passe en arrière-plan. Retiré par
  // `detruire()` -- sans ça, chaque sondeur créé pour une seule action
  // (catalogue.js/decouverte.js en créent un nouveau à chaque clic) laisse
  // un listener `visibilitychange` permanent sur `document`, même après
  // `stopper()` : fuite mémoire non bornée sur une session longue.
  function surVisibilite() {
    if (document.hidden) clearInterval(timer);
    else if (!arrete) {
      tick();
      planifier();
    }
  }
  document.addEventListener("visibilitychange", surVisibilite);

  function detruire() {
    stopper();
    document.removeEventListener("visibilitychange", surVisibilite);
  }

  return { demarrer, stopper, tick, detruire };
}
