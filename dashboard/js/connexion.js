/* ==========================================================================
   connexion.js — soumission du formulaire de connexion.
   --------------------------------------------------------------------------
   `form-action 'none'` dans la CSP interdit une soumission de formulaire
   classique : la validation se fait donc en `fetch`, avec le même en-tête
   `X-CADRE-Local` que tout autre POST du dashboard (cf. api.js) — la
   connexion suit exactement la même garde CSRF que le reste de l'app.
   ========================================================================== */

const form = document.getElementById("form-connexion");
const champMdp = document.getElementById("champ-mdp");
const zoneErreur = document.getElementById("connexion-erreur");
const bouton = document.getElementById("bouton-connexion");

// Régression (constatée en test réel, reproduite précisément) : un
// gestionnaire de mots de passe du navigateur pré-remplit ce champ, invisible
// puisque masqué par le type "password". Un utilisateur qui tape alors sans
// l'avoir remarqué obtient une valeur CONCATÉNÉE (ex. "bonmdpbonmdp") --
// "même le bon mot de passe échoue", sans rien à l'écran pour l'expliquer.
// Piste initialement tentée et écartée : vider au `focus` du champ. Ne
// fonctionne PAS ici, car `autofocus` (attribut HTML) déclenche l'événement
// `focus` DÈS le chargement de la page, avant que l'autofill n'ait injecté
// sa valeur -- le nettoyage arrive trop tôt, et rien ne reste pour nettoyer
// l'autofill qui suit.
// Fix retenu : détection standard de l'autofill via le pseudo-sélecteur CSS
// `:-webkit-autofill` (connexion.css), qui s'applique exactement au moment
// où Chromium/Edge injecte la valeur -- une micro-animation CSS sans effet
// visuel déclenche alors un événement `animationstart` détectable ici, quel
// que soit l'instant réel de l'autofill.
function viderChampMotDePasse() {
  champMdp.value = "";
}
viderChampMotDePasse();
window.addEventListener("pageshow", viderChampMotDePasse);
champMdp.addEventListener("animationstart", (evenement) => {
  if (evenement.animationName === "cadre-detection-autofill") {
    viderChampMotDePasse();
  }
});

function afficherErreur(message) {
  zoneErreur.textContent = message;
  zoneErreur.hidden = false;
}

function masquerErreur() {
  zoneErreur.hidden = true;
  zoneErreur.textContent = "";
}

form.addEventListener("submit", async (evenement) => {
  evenement.preventDefault();
  masquerErreur();
  bouton.disabled = true;
  bouton.textContent = "Connexion…";

  try {
    const reponse = await fetch("/api/login", {
      method: "POST",
      headers: { "X-CADRE-Local": "1", "Content-Type": "application/json" },
      body: JSON.stringify({ mot_de_passe: champMdp.value }),
      cache: "no-store",
    });
    const data = await reponse.json().catch(() => ({}));

    if (reponse.ok) {
      // Session posée (cookie) -- recharge sur "/" : le serveur sert
      // maintenant l'application réelle plutôt que cette page.
      window.location.href = "/";
      return;
    }

    if (reponse.status === 429) {
      afficherErreur(data.erreur || "Trop de tentatives — réessayez dans quelques minutes.");
    } else {
      afficherErreur(data.erreur || "Mot de passe incorrect.");
    }
  } catch {
    afficherErreur("Connexion au serveur impossible. Réessayez.");
  } finally {
    bouton.disabled = false;
    bouton.textContent = "Se connecter";
    champMdp.value = "";
    champMdp.focus();
  }
});
