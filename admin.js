// Astralbum – page d'administration (migration 0098).
// Connexion Google (compte admin@astralbum.com) puis code à 6 chiffres (Google Authenticator), comme l'exige le
// serveur pour chaque action. La page n'utilise aucune bibliothèque extérieure : seulement l'API de Supabase
// (connexion et fonctions du serveur), avec la clé publique « anon », la même que celle de l'application.
// Sécurité : tout ce qui vient du serveur ou des joueurs est affiché comme du texte (jamais comme du HTML) ; la
// session est gardée dans l'onglet seulement (fermée avec lui), 8 heures au plus, et 30 minutes sans activité.
'use strict';

(() => {
  // La page refuse d'être affichée à l'intérieur d'un autre site (piège au clic).
  if (window.top !== window.self) {
    document.documentElement.textContent = '';
    return;
  }

  const CONFIG = window.ASTRALBUM_ADMIN || {};
  const SERVEUR = String(CONFIG.url || '');
  const CLE = String(CONFIG.cle || '');
  const COMPTE_ADMIN = String(CONFIG.compte || 'admin@astralbum.com');
  const STOCKAGE = window.sessionStorage;
  const DUREE_CODE_MS = 8 * 3600 * 1000;
  const INACTIVITE_MS = 30 * 60 * 1000;
  const SUPPORT = 'support@astralbum.com';

  const contenu = document.getElementById('contenu');
  const zoneMessage = document.getElementById('message');

  // ─── Affichage (uniquement du texte) ──────────────────────────────────────────────────────────────────────

  function el(balise, attributs, ...enfants) {
    const e = document.createElement(balise);
    for (const [cle, valeur] of Object.entries(attributs || {})) {
      if (valeur === undefined || valeur === null || valeur === false) continue;
      if (cle === 'class') e.className = valeur;
      else if (cle.startsWith('on') && typeof valeur === 'function') e.addEventListener(cle.slice(2), valeur);
      else if (cle === 'disabled' || cle === 'checked' || cle === 'hidden') e[cle] = Boolean(valeur);
      else if (cle === 'value') e.value = String(valeur);
      else e.setAttribute(cle, String(valeur));
    }
    for (const enfant of enfants.flat(Infinity)) {
      if (enfant === undefined || enfant === null || enfant === false) continue;
      e.append(enfant instanceof Node ? enfant : document.createTextNode(String(enfant)));
    }
    return e;
  }

  function afficher(...elements) {
    contenu.replaceChildren(...elements.flat());
  }

  let minuterieMessage = null;
  function message(texte, erreur = false) {
    zoneMessage.textContent = texte;
    zoneMessage.className = erreur ? 'erreur' : '';
    zoneMessage.hidden = false;
    clearTimeout(minuterieMessage);
    minuterieMessage = setTimeout(() => { zoneMessage.hidden = true; }, 6000);
  }

  function date(iso, avecHeure = false) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return '—';
    return d.toLocaleString('fr-FR', avecHeure
      ? { dateStyle: 'long', timeStyle: 'short', timeZone: 'Europe/Paris' }
      : { dateStyle: 'long', timeZone: 'Europe/Paris' });
  }

  // ─── Session ──────────────────────────────────────────────────────────────────────────────────────────────

  class ErreurServeur extends Error {
    constructor(code, statut) {
      super(code);
      this.code = code;
      this.statut = statut;
    }
  }

  function lireSession() {
    try {
      const s = JSON.parse(STOCKAGE.getItem('session') || 'null');
      return s && typeof s.access_token === 'string' && typeof s.refresh_token === 'string' ? s : null;
    } catch {
      return null;
    }
  }

  function enregistrerSession(s, codeVerifie = false) {
    const ancienne = lireSession();
    STOCKAGE.setItem('session', JSON.stringify({
      access_token: s.access_token,
      refresh_token: s.refresh_token,
      expires_at: s.expires_at || Math.floor(Date.now() / 1000) + (s.expires_in || 3600),
      code_verifie_le: codeVerifie ? Date.now() : ancienne?.code_verifie_le || null,
    }));
  }

  function oublierSession() {
    STOCKAGE.removeItem('session');
    STOCKAGE.removeItem('verificateur');
  }

  function decoder(jeton) {
    try {
      const morceau = jeton.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
      return JSON.parse(decodeURIComponent(escape(atob(morceau))));
    } catch {
      return {};
    }
  }

  async function lireReponse(r) {
    const texte = await r.text();
    try {
      return texte ? JSON.parse(texte) : null;
    } catch {
      return null;
    }
  }

  async function auth(chemin, { methode = 'POST', corps, jeton } = {}) {
    const entetes = { apikey: CLE, 'Content-Type': 'application/json' };
    if (jeton) entetes.Authorization = `Bearer ${jeton}`;
    let r;
    try {
      r = await fetch(`${SERVEUR}/auth/v1/${chemin}`, {
        method: methode, headers: entetes, body: corps ? JSON.stringify(corps) : undefined, credentials: 'omit',
      });
    } catch {
      throw new ErreurServeur('RESEAU', 0);
    }
    const d = await lireReponse(r);
    if (!r.ok) throw new ErreurServeur(String(d?.error_code || d?.code || d?.error || 'AUTH'), r.status);
    return d;
  }

  // Jeton valable (renouvelé une minute avant la fin) ; null si la session est finie.
  async function jeton() {
    const s = lireSession();
    if (!s) return null;
    if (s.expires_at - 60 > Date.now() / 1000) return s.access_token;
    try {
      const n = await auth('token?grant_type=refresh_token', { corps: { refresh_token: s.refresh_token } });
      enregistrerSession(n);
      return n.access_token;
    } catch {
      oublierSession();
      return null;
    }
  }

  function aleatoire(n) {
    const a = new Uint8Array(n);
    crypto.getRandomValues(a);
    return base64url(a);
  }

  function base64url(octets) {
    let s = '';
    for (const o of octets) s += String.fromCharCode(o);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  // Connexion Google, avec un défi à usage unique (PKCE) : le code renvoyé ne sert qu'à cet onglet.
  async function connexionGoogle() {
    const verificateur = aleatoire(48);
    STOCKAGE.setItem('verificateur', verificateur);
    const defi = base64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verificateur))));
    const u = new URL(`${SERVEUR}/auth/v1/authorize`);
    u.searchParams.set('provider', 'google');
    u.searchParams.set('redirect_to', location.origin + location.pathname);
    u.searchParams.set('code_challenge', defi);
    u.searchParams.set('code_challenge_method', 's256');
    // choix du compte Google à chaque fois, en proposant le compte d'administration
    u.searchParams.set('prompt', 'select_account');
    u.searchParams.set('login_hint', COMPTE_ADMIN);
    location.assign(u.toString());
  }

  async function deconnexion() {
    const j = lireSession()?.access_token;
    oublierSession();
    if (j) await auth('logout', { jeton: j }).catch(() => {});
    document.getElementById('compte').hidden = true;
    ecranConnexion();
  }

  // ─── Appels aux fonctions du serveur ──────────────────────────────────────────────────────────────────────

  async function rpc(fonction, parametres = {}) {
    const j = await jeton();
    if (!j) {
      ecranConnexion('Session terminée : reconnecte-toi.');
      throw new ErreurServeur('SESSION', 401);
    }
    let r;
    try {
      r = await fetch(`${SERVEUR}/rest/v1/rpc/${fonction}`, {
        method: 'POST',
        headers: { apikey: CLE, Authorization: `Bearer ${j}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(parametres),
        credentials: 'omit',
      });
    } catch {
      throw new ErreurServeur('RESEAU', 0);
    }
    const d = await lireReponse(r);
    if (!r.ok) throw new ErreurServeur(String(d?.message || 'SERVEUR'), r.status);
    return d;
  }

  const MESSAGES = {
    INTERDIT: 'Ce compte n\'est pas administrateur.',
    NON_CONNECTE: 'Session terminée : reconnecte-toi.',
    TROP_DE_REQUETES: 'Trop d\'actions en peu de temps : attends une minute.',
    RESEAU: 'Le serveur ne répond pas. Vérifie ta connexion et réessaie.',
  };

  // Erreur d'une action : les cas de sécurité changent d'écran, les autres s'affichent en bas.
  function surErreur(e) {
    const code = e instanceof ErreurServeur ? e.code : 'SERVEUR';
    if (code === 'SESSION') return;
    if (code === 'ADMIN_CODE_REQUIS') return ecranCode();
    if (code === 'ADMIN_FACTEURS') return ecranBloque();
    if (code === 'INTERDIT') return ecranRefuse();
    if (code === 'NON_CONNECTE') return ecranConnexion(MESSAGES.NON_CONNECTE);
    message(MESSAGES[code] || 'Une erreur est survenue. Réessaie.', true);
  }

  // Bouton qui lance une action : désactivé pendant l'appel, message du serveur affiché.
  function bouton(texte, action, classe = '') {
    const b = el('button', { type: 'button', class: classe });
    b.textContent = texte;
    b.addEventListener('click', async () => {
      if (b.disabled) return;
      b.disabled = true;
      try {
        await action();
      } catch (e) {
        surErreur(e);
      } finally {
        b.disabled = false;
      }
    });
    return b;
  }

  // ─── Écrans de connexion ──────────────────────────────────────────────────────────────────────────────────

  function ecranConnexion(info) {
    document.getElementById('compte').hidden = true;
    afficher(el('section', { class: 'carte etroite' },
      el('h2', {}, 'Connexion'),
      el('p', {}, `Connecte-toi avec le compte Google ${COMPTE_ADMIN}, puis donne le code à 6 chiffres de Google Authenticator.`),
      info ? el('p', { class: 'erreur-texte' }, info) : null,
      bouton('Se connecter avec Google', connexionGoogle, 'principal')));
  }

  function ecranRefuse() {
    afficher(el('section', { class: 'carte etroite' },
      el('h2', {}, 'Accès refusé'),
      el('p', {}, `Ce compte n'est pas (ou pas encore) déclaré administrateur. Si tu es connecté avec ${COMPTE_ADMIN} `
        + 'et que tu viens d\'activer Google Authenticator, termine la mise en place dans Supabase (ligne SQL de la '
        + 'notice), puis recharge cette page. Sinon, déconnecte-toi et reconnecte-toi avec le bon compte.'),
      bouton('Me déconnecter', deconnexion, 'principal')));
  }

  function ecranBloque() {
    afficher(el('section', { class: 'carte etroite alerte' },
      el('h2', {}, 'Accès bloqué par sécurité'),
      el('p', {}, 'Le compte d\'administration a plus d\'un code de vérification enregistré (ou aucun code vérifié). '
        + 'Si tu n\'as pas ajouté toi-même un deuxième appareil, quelqu\'un a peut-être accès à ce compte : change '
        + 'tout de suite son mot de passe Google.'),
      el('p', {}, 'Pour débloquer : dans Supabase, Authentication, puis Users, ouvre le compte d\'administration, '
        + 'supprime ses facteurs de vérification (MFA), reconnecte-toi ici tout de suite pour en créer un nouveau, puis '
        + 'note ce nouveau code dans Supabase (ligne SQL de la notice).'),
      bouton('Me déconnecter', deconnexion)));
  }

  function champCode() {
    return el('input', {
      type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: '6', pattern: '[0-9]{6}',
      placeholder: '123456', class: 'code', 'aria-label': 'Code à 6 chiffres',
    });
  }

  async function verifierCode(facteur, champ, codeVerifie) {
    const code = champ.value.replace(/\s/g, '');
    if (!/^[0-9]{6}$/.test(code)) return message('Le code fait 6 chiffres.', true);
    const j = await jeton();
    if (!j) return ecranConnexion('Session terminée : reconnecte-toi.');
    try {
      const defi = await auth(`factors/${encodeURIComponent(facteur)}/challenge`, { jeton: j, corps: {} });
      const s = await auth(`factors/${encodeURIComponent(facteur)}/verify`, { jeton: j, corps: { challenge_id: defi.id, code } });
      enregistrerSession(s, true);
    } catch (e) {
      champ.value = '';
      return message(e instanceof ErreurServeur && e.statut === 422 || e?.statut === 400
        ? 'Code refusé : vérifie l\'heure de ton téléphone et donne le code affiché maintenant.'
        : 'La vérification n\'a pas marché. Réessaie.', true);
    }
    if (codeVerifie) message('Google Authenticator est activé pour ce compte.');
    await demarrer();
  }

  // Première connexion : enregistrer Google Authenticator (QR code à scanner).
  async function ecranActivation(utilisateur) {
    const j = await jeton();
    // un enregistrement commencé puis abandonné est effacé avant d'en commencer un nouveau
    for (const f of utilisateur.factors || []) {
      if (f.status !== 'verified') await auth(`factors/${encodeURIComponent(f.id)}`, { methode: 'DELETE', jeton: j }).catch(() => {});
    }
    let facteur;
    try {
      facteur = await auth('factors', { jeton: j, corps: { factor_type: 'totp', friendly_name: 'Google Authenticator', issuer: 'Astralbum' } });
    } catch (e) {
      return surErreur(e);
    }
    const qr = String(facteur?.totp?.qr_code || '');
    const image = el('img', { alt: 'QR code à scanner avec Google Authenticator', class: 'qr' });
    if (/^data:image\/svg\+xml/.test(qr)) image.src = qr;
    const champ = champCode();
    afficher(el('section', { class: 'carte etroite' },
      el('h2', {}, 'Activer le code à 6 chiffres'),
      el('ol', {},
        el('li', {}, 'Installe Google Authenticator sur ton téléphone.'),
        el('li', {}, 'Dans l\'application, touche « + », puis « Scanner un code QR », et scanne ce code :'),
      ),
      image,
      el('p', { class: 'aide' }, 'Sans appareil photo : « Saisir une clé de configuration », avec cette clé :'),
      el('p', { class: 'cle' }, String(facteur?.totp?.secret || '')),
      el('ol', { start: '3' }, el('li', {}, 'Écris ici le code à 6 chiffres affiché par l\'application :')),
      champ,
      bouton('Activer', () => verifierCode(facteur.id, champ, true), 'principal'),
      el('p', { class: 'aide' }, 'Ne partage jamais ce QR code ni cette clé. Un seul téléphone peut être enregistré.')));
    champ.focus();
  }

  async function ecranCode() {
    const j = await jeton();
    if (!j) return ecranConnexion();
    let utilisateur;
    try {
      utilisateur = await auth('user', { methode: 'GET', jeton: j });
    } catch (e) {
      return surErreur(e);
    }
    const verifies = (utilisateur.factors || []).filter((f) => f.status === 'verified');
    if (verifies.length === 0) return ecranActivation(utilisateur);
    if (verifies.length > 1) return ecranBloque();
    const champ = champCode();
    champ.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') valider.click(); });
    const valider = bouton('Vérifier', () => verifierCode(verifies[0].id, champ, false), 'principal');
    afficher(el('section', { class: 'carte etroite' },
      el('h2', {}, 'Code à 6 chiffres'),
      el('p', {}, 'Ouvre Google Authenticator sur ton téléphone et écris le code Astralbum :'),
      champ, valider));
    champ.focus();
  }

  // ─── Écran principal : trois onglets ──────────────────────────────────────────────────────────────────────

  let ongletCourant = 'joueurs';

  function ecranPrincipal() {
    const onglets = [['joueurs', 'Joueurs'], ['signalements', 'Signalements'], ['message', 'Message à tous']];
    const zone = el('div', { class: 'onglet' });
    const barre = el('nav', { class: 'onglets', role: 'tablist' });
    const ouvrir = (id) => {
      ongletCourant = id;
      for (const b of barre.children) b.setAttribute('aria-selected', String(b.dataset.onglet === id));
      zone.replaceChildren(id === 'joueurs' ? ongletJoueurs() : id === 'signalements' ? ongletSignalements() : ongletMessage());
    };
    for (const [id, nom] of onglets) {
      const b = el('button', { type: 'button', role: 'tab', 'data-onglet': id, onclick: () => ouvrir(id) }, nom);
      barre.append(b);
    }
    afficher(barre, zone);
    ouvrir(ongletCourant);
  }

  // Joueurs : demandes sur les données
  let fiche = null;

  function ongletJoueurs() {
    const racine = el('div');
    const champ = el('input', { type: 'text', autocomplete: 'off', spellcheck: 'false', placeholder: 'Adresse e-mail ou pseudo', 'aria-label': 'Adresse e-mail ou pseudo' });
    const zoneFiche = el('div');
    const montrer = () => zoneFiche.replaceChildren(...(fiche ? vueFiche(fiche, montrer) : [rappel()]));
    const chercher = bouton('Chercher', async () => {
      const q = champ.value.trim();
      if (!q) return;
      const r = await rpc('admin_chercher_joueur', { p_recherche: q });
      fiche = r?.ok ? r.joueur : null;
      if (!r?.ok) message(r?.message || 'Aucun joueur trouvé.', true);
      montrer();
    }, 'principal');
    champ.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') chercher.click(); });
    racine.append(
      el('p', { class: 'aide' }, 'Un joueur te demande quelque chose sur ses données ? Vérifie d\'abord que sa demande '
        + 'vient bien de l\'adresse e-mail de son compte, puis cherche-le ici.'),
      el('div', { class: 'ligne' }, champ, chercher),
      zoneFiche);
    montrer();
    return racine;
  }

  function rappel() {
    return carteDroit('Rappel', `Tu as un mois pour répondre à une demande. Réponds depuis ${SUPPORT}. Si la demande ne `
      + 'vient pas de l\'adresse du compte, demande au joueur d\'écrire depuis celle-ci.');
  }

  function carteDroit(titre, explication, ...actions) {
    return el('section', { class: 'carte droit' }, el('h3', {}, titre), el('p', { class: 'aide' }, explication), ...actions);
  }

  // Réponse {ok, message, joueur?} d'une action sur un joueur.
  function apresAction(r, montrer) {
    if (r?.joueur) fiche = r.joueur;
    message(r?.message || (r?.ok ? 'C\'est fait.' : 'Action refusée.'), !r?.ok);
    montrer();
  }

  function vueFiche(f, montrer) {
    const id = String(f.id);
    const pseudo = String(f.pseudo);
    const etiquettes = [];
    if (f.suspendu) etiquettes.push(['Suspendu', 'rouge']);
    if (f.gel_statut === 'gele') etiquettes.push(['Gelé', 'bleu']);
    if (f.gel_statut === 'bloque') etiquettes.push(['Bloqué', 'rouge']);
    if (f.abonne_jusqu_au && new Date(f.abonne_jusqu_au) > new Date()) etiquettes.push(['Abonné', 'or']);
    if (f.testeur) etiquettes.push(['Compte de test', 'vert']);
    const copie = f.copie_donnees || null;
    const etatCopie = !copie ? null : copie.envoyee_le ? `envoyée le ${date(copie.envoyee_le, true)}`
      : copie.erreur ? 'en échec, réessayée toutes les heures' : `demandée le ${date(copie.demandee_le, true)}, en cours d'envoi`;
    const lignes = [
      ['Adresse e-mail', f.email || '—'], ['Inscrit le', date(f.cree_le)], ['Dernière activité', date(f.derniere_activite)],
      ['Astres différents', f.astres_distincts ?? 0], ['Achats (15 mois)', f.achats ?? 0], ['Signalements reçus', f.signalements_recus ?? 0],
      ...(f.suppression_prevue ? [['Suppression prévue', date(f.suppression_prevue)]] : []),
      ...(etatCopie ? [['Copie des données', etatCopie]] : []),
    ];

    const nouveauPseudo = el('input', { type: 'text', autocomplete: 'off', spellcheck: 'false', placeholder: 'Nouveau pseudo', 'aria-label': 'Nouveau pseudo' });
    const confirmationSuppression = el('input', { type: 'text', autocomplete: 'off', spellcheck: 'false', placeholder: `Recopie « ${pseudo} »`, 'aria-label': 'Pseudo à recopier' });
    const reponseOpposition = 'Bonjour,\n\nNous avons bien reçu ta demande. Les données concernées (dates de tes actions, journaux '
      + 'techniques) servent uniquement à la sécurité du jeu et à la lutte contre la triche, ce qui protège l\'ensemble des '
      + 'joueurs : nous ne pouvons donc pas cesser de les utiliser tant que ton compte existe. Si tu le souhaites, tu peux '
      + 'supprimer ton compte à tout moment (Paramètres, puis Supprimer mon compte) : ces données seront alors effacées, '
      + 'sauf les traces des achats, gardées 15 mois sans lien avec ton compte.\n\nL\'équipe Astralbum';

    return [
      el('section', { class: 'carte fiche' },
        el('h2', {}, pseudo),
        etiquettes.length ? el('div', { class: 'etiquettes' }, etiquettes.map(([t, c]) => el('span', { class: `etiquette ${c}` }, t))) : null,
        el('dl', {}, lignes.map(([n, v]) => [el('dt', {}, n), el('dd', {}, String(v))]))),
      carteDroit('Accès et portabilité',
        'Le joueur veut une copie de ses données. Elle part par e-mail, à l\'adresse de son compte (jamais à une autre), '
        + 'dans un fichier JSON : son profil, sa collection, ses achats, ses échanges, etc. Une copie par jour au plus.',
        bouton('Envoyer la copie de ses données', async () => apresAction(await rpc('admin_envoyer_donnees', { p_joueur: id }), montrer), 'principal')),
      carteDroit('Rectification',
        'Le joueur veut corriger une donnée fausse. Ici : son pseudo (vérifié par le filtre, comme à la création). Son '
        + 'adresse e-mail se corrige dans son compte Google, pas chez nous. Ne rends jamais un pseudo sanctionné.',
        el('div', { class: 'ligne' }, nouveauPseudo, bouton('Changer', async () => {
          const p = nouveauPseudo.value.trim();
          if (!p) return;
          apresAction(await rpc('admin_changer_pseudo', { p_joueur: id, p_pseudo: p }), montrer);
        }))),
      carteDroit('Limitation',
        'Le joueur veut qu\'on arrête d\'utiliser ses données sans les effacer, par exemple le temps de vérifier une '
        + 'contestation. Le compte est suspendu : il ne peut plus jouer, ses données sont gardées. Réactive-le une fois '
        + 'la question réglée.',
        f.suspendu
          ? bouton('Réactiver le compte', async () => apresAction(await rpc('admin_suspendre', { p_joueur: id, p_suspendu: false }), montrer), 'principal')
          : bouton('Suspendre le compte', async () => apresAction(await rpc('admin_suspendre', { p_joueur: id, p_suspendu: true }), montrer))),
      carteDroit('Effacement',
        'Le joueur veut que ses données soient effacées et ne peut pas le faire lui-même (Paramètres, puis Supprimer mon '
        + 'compte). La suppression est définitive ; les traces des achats restent 15 mois, sans lien avec le compte.',
        el('div', { class: 'ligne' }, confirmationSuppression, bouton('Supprimer le compte', async () => {
          if (!window.confirm(`Supprimer définitivement le compte de ${pseudo} ?`)) return;
          const r = await rpc('admin_supprimer_compte', { p_joueur: id, p_confirmation: confirmationSuppression.value.trim() });
          if (r?.ok) fiche = null;
          apresAction(r, montrer);
        }, 'danger'))),
      carteDroit('Opposition',
        'Le joueur refuse que ses données servent à la sécurité du jeu et à la lutte contre la triche. La loi permet de '
        + 'refuser pour ce motif : ces données protègent tous les joueurs. Réponds-lui avec ce texte ; s\'il ne veut '
        + 'vraiment plus que ses données servent, il peut supprimer son compte.',
        el('textarea', { readonly: 'readonly', rows: '7', class: 'reponse', 'aria-label': 'Réponse type' }, reponseOpposition),
        bouton('Copier la réponse type', async () => {
          await navigator.clipboard.writeText(reponseOpposition);
          message('Réponse copiée : colle-la dans ton e-mail.');
        })),
    ];
  }

  // Signalements
  function ongletSignalements() {
    const racine = el('div');
    const liste = el('div', {}, el('p', { class: 'aide' }, 'Chargement…'));
    const charger = async () => {
      const r = await rpc('admin_signalements');
      const s = Array.isArray(r?.signalements) ? r.signalements : [];
      liste.replaceChildren(...(s.length === 0
        ? [el('p', { class: 'vide' }, 'Aucun signalement à traiter.')]
        : s.map((x) => {
          const pseudo = String(x.pseudo);
          const decider = (decision) => async () => {
            const texte = decision === 'sanction'
              ? `Sanctionner ${pseudo} ? Le pseudo est remplacé par un pseudo neutre, le joueur est prévenu dans le jeu et ceux qui l'ont signalé reçoivent un « Merci ! ».`
              : `Classer sans suite les signalements de ${pseudo} ? Le pseudo est gardé ; personne n'est prévenu.`;
            if (!window.confirm(texte)) return;
            const d = await rpc('admin_decider_signalement', { p_pseudo: pseudo, p_decision: decision });
            message(d?.message || 'C\'est fait.', !d?.ok);
            await charger();
          };
          return el('section', { class: 'carte signalement' },
            el('h3', {}, pseudo),
            el('p', { class: 'aide' }, `${x.signaleurs} joueur(s), ${x.signalements} signalement(s) · premier le ${date(x.premier)}, dernier le ${date(x.dernier)}`),
            el('div', { class: 'ligne' }, bouton('Sanctionner', decider('sanction'), 'danger'), bouton('Sans suite', decider('sans_suite'))));
        })));
    };
    racine.append(
      el('div', { class: 'ligne entre' },
        el('p', { class: 'aide' }, 'Pseudos signalés, du plus signalé au moins signalé. Les signalements sont effacés 6 mois après leur envoi : traite-les avant.'),
        bouton('Actualiser', charger)),
      liste);
    charger().catch(surErreur);
    return racine;
  }

  // Message à tous les joueurs
  function ongletMessage() {
    const objet = el('input', { type: 'text', maxlength: '150', placeholder: 'Objet de l\'e-mail', 'aria-label': 'Objet de l\'e-mail' });
    const texte = el('textarea', { rows: '12', placeholder: 'Texte. Laisse une ligne vide entre deux paragraphes.', 'aria-label': 'Texte' });
    const relu = el('input', { type: 'checkbox', id: 'relu' });
    const resultat = el('pre', { class: 'resultat', hidden: true });
    const texteServeur = () => texte.value.trim().split(/\n\s*\n/).map((p) => p.trim()).filter(Boolean).join(' § ');
    const envoyer = async (etape) => {
      if (etape === 'tous' && !window.confirm('Envoyer ce message par e-mail à TOUS les joueurs ? Ce n\'est pas annulable.')) return;
      const r = await rpc('admin_message_tous', { p_objet: objet.value.trim(), p_texte: texteServeur(), p_etape: etape, p_confirme: etape === 'tous' });
      resultat.textContent = r?.message || '';
      resultat.hidden = !resultat.textContent;
      resultat.className = r?.ok ? 'resultat' : 'resultat erreur-texte';
      if (etape === 'tous' && r?.ok) { relu.checked = false; majTous(); }
    };
    const tous = bouton('2. Envoyer à tous les joueurs', () => envoyer('tous'), 'danger');
    const majTous = () => { tous.disabled = !relu.checked; };
    relu.addEventListener('change', majTous);
    for (const champ of [objet, texte]) champ.addEventListener('input', () => { relu.checked = false; majTous(); });
    majTous();
    return el('div', {},
      el('p', { class: 'aide' }, 'Seulement pour une information importante sur les comptes (changement des conditions, '
        + 'fuite de données), jamais pour de la publicité. « Bonjour [pseudo], », la ligne du support et la signature '
        + 'sont ajoutés tout seuls.'),
      objet, texte,
      bouton(`1. M'envoyer un exemple (${SUPPORT})`, () => envoyer('exemple'), 'principal'),
      el('label', { class: 'case', for: 'relu' }, relu, ' J\'ai reçu et relu l\'exemple, sans rien changer depuis'),
      tous,
      bouton('Où en est l\'envoi ?', () => envoyer('suivi')),
      resultat);
  }

  // ─── Démarrage ────────────────────────────────────────────────────────────────────────────────────────────

  async function demarrer() {
    if (!SERVEUR.startsWith('https://') || !CLE) {
      return afficher(el('p', { class: 'erreur-texte' }, 'Page mal configurée : adresse du serveur ou clé absente.'));
    }
    // retour de Google : échange du code contre une session (une seule fois)
    const p = new URLSearchParams(location.search);
    if (p.has('code') || p.has('error') || p.has('error_description')) {
      history.replaceState(null, '', location.pathname);
      const verificateur = STOCKAGE.getItem('verificateur');
      STOCKAGE.removeItem('verificateur');
      if (!p.has('code') || !verificateur) return ecranConnexion('La connexion avec Google n\'a pas abouti. Réessaie.');
      try {
        enregistrerSession(await auth('token?grant_type=pkce', { corps: { auth_code: p.get('code'), code_verifier: verificateur } }));
      } catch {
        return ecranConnexion('La connexion avec Google n\'a pas abouti. Réessaie.');
      }
    }
    const j = await jeton();
    if (!j) return ecranConnexion();
    let utilisateur;
    try {
      utilisateur = await auth('user', { methode: 'GET', jeton: j });
    } catch {
      oublierSession();
      return ecranConnexion('Session terminée : reconnecte-toi.');
    }
    document.getElementById('compte-email').textContent = String(utilisateur.email || '');
    document.getElementById('compte').hidden = false;
    if (String(utilisateur.email || '').toLowerCase() !== COMPTE_ADMIN.toLowerCase()) return ecranRefuse();
    // code à 6 chiffres : donné dans cette session depuis moins de 8 heures
    const s = lireSession();
    if (decoder(j).aal !== 'aal2' || !s?.code_verifie_le || Date.now() - s.code_verifie_le > DUREE_CODE_MS) return ecranCode();
    try {
      await rpc('admin_verifier');
    } catch (e) {
      return surErreur(e);
    }
    ecranPrincipal();
  }

  // Déconnexion après 30 minutes sans activité, et au bout de 8 heures.
  let derniereActivite = Date.now();
  for (const evenement of ['click', 'keydown', 'pointermove', 'touchstart']) {
    window.addEventListener(evenement, () => { derniereActivite = Date.now(); }, { passive: true });
  }
  setInterval(() => {
    const s = lireSession();
    if (!s) return;
    if (Date.now() - derniereActivite > INACTIVITE_MS || (s.code_verifie_le && Date.now() - s.code_verifie_le > DUREE_CODE_MS)) {
      deconnexion().then(() => message('Déconnecté après une période d\'inactivité.'));
    }
  }, 30 * 1000);

  document.getElementById('deconnexion').addEventListener('click', deconnexion);
  demarrer().catch(() => ecranConnexion('Une erreur est survenue. Réessaie.'));
})();
