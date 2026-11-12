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

  // Identifiant de ce navigateur, tiré au hasard une fois et gardé (localStorage) : le serveur n'envoie l'e-mail
  // d'alerte que pour un appareil ou un navigateur jamais vu (connexion inhabituelle). Rien de personnel dedans.
  function identifiantAppareil() {
    const cle = 'astralbum_admin_appareil';
    try {
      let id = window.localStorage.getItem(cle);
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id || '')) {
        id = crypto.randomUUID();
        window.localStorage.setItem(cle, id);
      }
      return id;
    } catch {
      return null; // stockage refusé (navigation privée stricte) : connexion traitée comme inhabituelle
    }
  }

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

  // Le serveur (Supabase) donne le QR code comme un dessin SVG brut (« <?xml …?><svg …> »), ou selon les versions
  // « data:img/svg+xml;utf-8,… » (type d'image mal écrit), avec des « # » dans les couleurs qui coupent une adresse.
  // La page n'acceptait que « data:image/svg+xml » : le QR code ne s'affichait pas. Le dessin est relu, vérifié (c'est bien
  // un dessin SVG), puis réécrit en entier dans une adresse d'image correcte. Rend '' sinon (la clé écrite sous le QR
  // code reste utilisable).
  function adresseImageQr(qr) {
    const texte = String(qr || '');
    let dessin;
    if (texte.trimStart().startsWith('<')) {
      // dessin SVG brut (réponse directe du serveur : c'est la bibliothèque JavaScript de Supabase, que cette page
      // n'utilise pas, qui y ajoute d'habitude le début « data:… »)
      dessin = texte;
    } else {
      const m = /^data:(?:image|img)\/svg\+xml([^,]*),([\s\S]*)$/i.exec(texte);
      if (!m) return '';
      dessin = m[2];
      try {
        if (/;base64/i.test(m[1])) dessin = new TextDecoder().decode(Uint8Array.from(atob(dessin), (c) => c.charCodeAt(0)));
        else if (!dessin.trimStart().startsWith('<')) dessin = decodeURIComponent(dessin);
      } catch (_) {
        return '';
      }
    }
    // en-tête XML, déclaration de type et commentaires avant le dessin : retirés
    dessin = dessin.replace(/^\s*(?:<\?xml[^>]*\?>\s*|<!DOCTYPE[^>]*>\s*|<!--[\s\S]*?-->\s*)*/i, '');
    if (!/^<svg[\s>]/i.test(dessin)) return '';
    return 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(dessin);
  }

  // Clé de configuration écrite par blocs de 4 caractères (plus facile à recopier sur le téléphone). Les blocs sont
  // séparés par une marge, pas par des espaces : un copier-coller donne la clé exacte.
  function cleEnBlocs(secret) {
    const cle = String(secret || '').replace(/\s+/g, '').toUpperCase();
    const p = el('p', { class: 'cle' });
    for (let i = 0; i < cle.length; i += 4) p.appendChild(el('span', {}, cle.slice(i, i + 4)));
    return p;
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
    const adresseQr = adresseImageQr(qr);
    if (adresseQr) image.src = adresseQr;
    const champ = champCode();
    afficher(el('section', { class: 'carte etroite' },
      el('h2', {}, 'Activer le code à 6 chiffres'),
      el('ol', {},
        el('li', {}, 'Installe Google Authenticator sur ton téléphone.'),
        el('li', {}, 'Dans l\'application, touche « + », puis « Scanner un code QR », et scanne ce code :'),
      ),
      image,
      el('p', { class: 'aide' }, 'Sans appareil photo : « Saisir une clé de configuration », type « Basée sur l\'heure », '
        + 'avec cette clé (sans les espaces). Elle ne contient que des lettres et les chiffres 2 à 7 : « O » est la lettre O, '
        + 'jamais le chiffre zéro, et « I » la lettre I, jamais le chiffre un.'),
      cleEnBlocs(facteur?.totp?.secret),
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

  let ongletCourant = 'tableau';
  let ouvrirOnglet = () => {};

  function ecranPrincipal() {
    const onglets = [['tableau', 'Tableau de bord'], ['joueurs', 'Joueurs'], ['signalements', 'Signalements'],
      ['message', 'Message à tous'], ['journal', 'Journal']];
    const contenus = { tableau: ongletTableau, joueurs: ongletJoueurs, signalements: ongletSignalements, message: ongletMessage, journal: ongletJournal };
    const zone = el('div', { class: 'onglet' });
    const barre = el('nav', { class: 'onglets', role: 'tablist' });
    const ouvrir = (id) => {
      ongletCourant = id;
      for (const b of barre.children) b.setAttribute('aria-selected', String(b.dataset.onglet === id));
      zone.replaceChildren(contenus[id]());
    };
    ouvrirOnglet = ouvrir;
    for (const [id, nom] of onglets) {
      const b = el('button', { type: 'button', role: 'tab', 'data-onglet': id, onclick: () => ouvrir(id) }, nom);
      barre.append(b);
    }
    afficher(barre, zone);
    ouvrir(ongletCourant);
  }

  // Nom d'un produit de la boutique (même règle que le jeu et les e-mails).
  function nomProduit(id) {
    const t = String(id || '');
    if (t.startsWith('abonnement')) return 'Abonnement Astronome';
    const n = Number(t.split('_').at(-1));
    const pl = Number.isInteger(n) && n > 1 ? 's' : '';
    if (t.startsWith('boosters_') && Number.isInteger(n)) return `${n} booster${pl}`;
    if (t.startsWith('stellaires_') && Number.isInteger(n)) return `${n} booster${pl} stellaire${pl}`;
    if (t.startsWith('nuit_claire') && Number.isInteger(n)) return n > 1 ? `${n} Nuits claires` : '1 Nuit claire';
    return t;
  }

  const nombre = (n) => Number(n || 0).toLocaleString('fr-FR');

  // Tuile du tableau de bord : un nombre, son libellé, et éventuellement l'onglet qu'elle ouvre.
  function tuile(valeur, libelle, { alerte = false, onglet = null, detail = null } = {}) {
    const t = el(onglet ? 'button' : 'div', { type: onglet ? 'button' : undefined, class: `tuile${alerte ? ' alerte' : ''}` },
      el('span', { class: 'valeur' }, valeur), el('span', { class: 'libelle' }, libelle),
      detail ? el('span', { class: 'detail' }, detail) : null);
    if (onglet) t.addEventListener('click', () => ouvrirOnglet(onglet));
    return t;
  }

  // Tableau de bord
  function ongletTableau() {
    const racine = el('div', {}, el('p', { class: 'aide' }, 'Chargement…'));
    const charger = async () => {
      const d = await rpc('admin_tableau_bord');
      const j = d?.joueurs || {};
      const a = d?.achats_mois || {};
      const sg = d?.signalements || {};
      const echecs = Number(d?.emails_en_echec || 0);
      const suspects = Number(d?.suspects || 0);
      const limite = sg.premier_efface_le ? new Date(sg.premier_efface_le) : null;
      const signalementsUrgents = limite && limite - Date.now() < 14 * 86400000;
      const produits = Object.entries(a.par_produit || {}).sort((x, y) => y[1] - x[1]);
      const precedente = d?.derniere_connexion_admin;
      racine.replaceChildren(
        el('div', { class: 'ligne entre' },
          el('p', { class: 'aide' }, `Mis à jour le ${date(d?.genere_le, true)}. Les comptes de test ne sont pas comptés.`),
          bouton('Actualiser', charger)),
        el('h3', {}, 'À surveiller'),
        el('div', { class: 'tuiles' },
          tuile(nombre(sg.pseudos), 'pseudos signalés à traiter', {
            alerte: signalementsUrgents, onglet: 'signalements',
            detail: limite ? `le plus ancien : avant le ${date(sg.premier_efface_le)}` : null,
          }),
          tuile(nombre(suspects), 'joueurs à surveiller (triche)', {
            alerte: suspects > 0, onglet: 'signalements', detail: 'activité suspecte, 30 derniers jours',
          }),
          tuile(nombre(echecs), 'e-mails en échec', { alerte: echecs > 0, detail: echecs > 0 ? 'réessayés toutes les heures' : null }),
          tuile(nombre(j.geles), 'comptes gelés', { detail: `${nombre(j.bloques)} bloqué(s), ${nombre(j.suspendus)} suspendu(s)` })),
        el('h3', {}, 'Joueurs'),
        el('div', { class: 'tuiles' },
          tuile(nombre(j.inscrits), 'inscrits', { detail: `${nombre(j.nouveaux_7j)} nouveaux en 7 jours` }),
          tuile(nombre(j.actifs_24h), 'actifs en 24 h'),
          tuile(nombre(j.actifs_7j), 'actifs en 7 jours'),
          tuile(nombre(j.actifs_30j), 'actifs en 30 jours'),
          tuile(nombre(j.abonnes), 'abonnés')),
        el('h3', {}, `Achats depuis le ${date(a.depuis)}`),
        el('div', { class: 'tuiles' },
          tuile(nombre(a.achats), 'achats'),
          tuile(nombre(a.remboursements), 'remboursements', { alerte: Number(a.remboursements) > 0 })),
        produits.length
          ? el('ul', { class: 'liste-simple' }, produits.map(([p, n]) => el('li', {}, `${nomProduit(p)} : ${nombre(n)}`)))
          : el('p', { class: 'aide' }, 'Aucun achat ce mois-ci.'),
        el('p', { class: 'aide' }, precedente
          ? `Connexion précédente à l'administration : ${date(precedente.le, true)}${precedente.ip ? ` (adresse IP ${precedente.ip})` : ''}. Pas toi ? Regarde le journal.`
          : 'Première connexion à l\'administration.'));
    };
    charger().catch(surErreur);
    return racine;
  }

  // Journal des actions d'administration
  const ACTIONS = {
    connexion: 'Connexion à l\'administration', consulter: 'Fiche consultée', envoyer_donnees: 'Copie des données envoyée',
    changer_pseudo: 'Pseudo corrigé', suspendre: 'Compte suspendu', reactiver: 'Compte réactivé',
    supprimer_compte: 'Compte supprimé', sanction_pseudo: 'Pseudo sanctionné', classer_signalements: 'Signalements classés sans suite',
    message_exemple: 'Message à tous : exemple envoyé', message_tous: 'Message à tous : envoi lancé', lever_gel: 'Gel levé',
    offrir: 'Ajouté au compte', annuler_avertissement: 'Avertissement annulé', annuler_sanction: 'Sanction de pseudo annulée',
    testeur: 'Compte de test donné', retirer_testeur: 'Compte de test retiré',
  };

  // « 5 booster(s), 1 Nuit(s) claire(s) »
  function quantites(b, s, n) {
    return [Number(b) > 0 ? `${b} booster(s)` : null, Number(s) > 0 ? `${s} booster(s) stellaire(s)` : null,
      Number(n) > 0 ? `${n} Nuit(s) claire(s)` : null].filter(Boolean).join(', ');
  }

  function detailAction(x) {
    const d = x.details || {};
    if (x.action === 'connexion') return [d.ip ? `IP ${d.ip}` : null, d.navigateur].filter(Boolean).join(' · ');
    if (['changer_pseudo', 'sanction_pseudo', 'annuler_sanction'].includes(x.action)) return `${d.ancien || '?'} → ${d.nouveau || '?'}`;
    if (x.action === 'offrir') return `${quantites(d.boosters, d.stellaires, d.nuits_claires)} · motif : ${d.motif || '—'}`;
    if (x.action === 'annuler_avertissement') return [nomProduit(d.produit), d.commande].filter(Boolean).join(' · ');
    if (x.action === 'consulter' && d.commande) return `par la commande ${d.commande}`;
    if (x.action.startsWith('message_')) return d.objet ? `« ${d.objet} »` : '';
    if (x.action === 'classer_signalements') return d.signalements ? `${d.signalements} signalement(s)` : '';
    return '';
  }

  let masquerConsultations = true;

  function ongletJournal() {
    const liste = el('div', {}, el('p', { class: 'aide' }, 'Chargement…'));
    const masquer = el('input', { type: 'checkbox', id: 'masquer', checked: masquerConsultations });
    const charger = async () => {
      const r = await rpc('admin_journal', { p_limite: 100, p_sans_consultations: masquerConsultations });
      const actions = Array.isArray(r?.actions) ? r.actions : [];
      liste.replaceChildren(actions.length === 0
        ? el('p', { class: 'vide' }, 'Aucune action.')
        : el('table', { class: 'journal actions' },
          el('thead', {}, el('tr', {}, el('th', {}, 'Date'), el('th', {}, 'Action'), el('th', {}, 'Joueur'), el('th', {}, 'Par'))),
          el('tbody', {}, actions.map((x) => el('tr', { class: x.action === 'connexion' ? 'connexion' : '' },
            el('td', {}, date(x.le, true)),
            el('td', {}, ACTIONS[x.action] || String(x.action), detailAction(x) ? el('span', { class: 'detail' }, detailAction(x)) : null),
            el('td', {}, x.joueur || '—'),
            el('td', {}, x.par || '—'))))));
    };
    masquer.addEventListener('change', () => { masquerConsultations = masquer.checked; charger().catch(surErreur); });
    charger().catch(surErreur);
    return el('div', {},
      el('p', { class: 'aide' }, 'Les 100 dernières actions d\'administration (gardées 12 mois). Une action que tu n\'as pas faite ? '
        + 'Change le mot de passe du compte Google d\'administration et supprime son code de vérification dans Supabase.'),
      el('div', { class: 'ligne entre' },
        el('label', { class: 'case', for: 'masquer' }, masquer, ' Masquer les fiches consultées'),
        bouton('Actualiser', charger)),
      liste);
  }

  // Joueurs : demandes sur les données, contestations
  let fiche = null;
  let commande = null; // recherche par numéro de commande Google : {numero, achats, supprime}

  // Pseudo à chercher en ouvrant l'onglet Joueurs (bouton « Ouvrir sa fiche » d'un autre onglet).
  let rechercheDemandee = null;

  function ongletJoueurs() {
    const racine = el('div');
    const champ = el('input', { type: 'text', autocomplete: 'off', spellcheck: 'false', placeholder: 'E-mail, pseudo ou n° de commande (GPA.…)',
      'aria-label': 'Adresse e-mail, pseudo ou numéro de commande Google' });
    const zoneFiche = el('div');
    const montrer = () => zoneFiche.replaceChildren(...(commande ? [carteCommande(commande)] : []),
      ...(fiche ? vueFiche(fiche, montrer) : commande ? [] : [rappel()]));
    const chercher = bouton('Chercher', async () => {
      const q = champ.value.trim();
      if (!q) return;
      const r = await rpc('admin_chercher_joueur', { p_recherche: q });
      fiche = r?.ok && r.joueur ? r.joueur : null;
      commande = r?.ok && Array.isArray(r.achats) ? { numero: String(r.commande || q), achats: r.achats, supprime: !r.joueur } : null;
      if (!r?.ok) message(r?.message || 'Aucun joueur trouvé.', true);
      else if (r.message) message(r.message);
      montrer();
    }, 'principal');
    champ.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') chercher.click(); });
    if (rechercheDemandee) {
      champ.value = rechercheDemandee;
      rechercheDemandee = null;
      setTimeout(() => chercher.click(), 0);
    }
    racine.append(
      el('p', { class: 'aide' }, 'Un joueur te demande quelque chose sur ses données ? Vérifie d\'abord que sa demande '
        + 'vient bien de l\'adresse e-mail de son compte, puis cherche-le ici. Une contestation d\'achat ? Colle le numéro '
        + 'de commande Google (GPA.…) du reçu du joueur.'),
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
      ['Avertissements / gels', `${f.avertissements ?? 0} / ${f.gels ?? 0}`],
      ['Boosters / stellaires / Nuits claires', `${f.boosters ?? 0} / ${f.stellaires ?? 0} / ${f.nuits_claires ?? 0}`],
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
      f.gel_statut ? carteGel(f, montrer) : null,
      carteAchats(f.liste_achats, f, montrer),
      carteOffrir(f, montrer),
      carteDroit('Compte de test',
        f.testeur
          ? 'Ce compte a les outils de test dans le jeu ; il n\'apparaît dans aucun classement et n\'enregistre pas de '
            + 'premières observations. Retirer ce statut retire aussi ses amis simulés (essais d\'échanges).'
          : 'Donne à ce compte les outils de test dans le jeu (boosters, monnaies, niveau du télescope, amis simulés…). '
            + 'Un compte de test n\'apparaît dans aucun classement et n\'enregistre pas de premières observations.',
        f.testeur
          ? bouton('Retirer le statut de compte de test', async () => {
              if (!window.confirm(`Retirer le statut de compte de test de ${pseudo} ?`)) return;
              apresAction(await rpc('admin_testeur', { p_joueur: id, p_testeur: false }), montrer);
            })
          : bouton('En faire un compte de test', async () => {
              if (!window.confirm(`Faire de ${pseudo} un compte de test ? Il quittera les classements.`)) return;
              apresAction(await rpc('admin_testeur', { p_joueur: id, p_testeur: true }), montrer);
            }, 'principal')),
      carteHistorique(f, montrer),
      carteDroit('Accès et portabilité',
        'Le joueur veut une copie de ses données. Elle part par e-mail, à l\'adresse de son compte (jamais à une autre), '
        + 'dans un fichier JSON : son profil, sa collection, ses achats, ses échanges, etc. Une copie par jour au plus.',
        bouton('Envoyer la copie de ses données', async () => apresAction(await rpc('admin_envoyer_donnees', { p_joueur: id }), montrer), 'principal')),
      carteDroit('Rectification',
        'Le joueur veut corriger une donnée fausse. Ici : son pseudo (vérifié par le filtre, comme à la création). Son '
        + 'adresse e-mail se corrige dans son compte Google, pas chez nous. Un pseudo sanctionné à tort se rend avec « Annuler '
        + 'la sanction », dans l\'historique.',
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
          if (r?.ok) { fiche = null; commande = null; }
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

  // Compte gelé ou bloqué : depuis quand, ce qu'il reste à régulariser, « Lever le gel ».
  function carteGel(f, montrer) {
    const reste = f.a_regulariser || {};
    const dus = [
      reste.boosters > 0 ? `${reste.boosters} booster(s)` : null,
      reste.boosters_stellaires > 0 ? `${reste.boosters_stellaires} booster(s) stellaire(s)` : null,
      reste.nuits_claires > 0 ? `${reste.nuits_claires} Nuit(s) claire(s)` : null,
      reste.abonnement ? 'l\'abonnement remboursé' : null,
    ].filter(Boolean);
    return el('section', { class: 'carte alerte' },
      el('h3', {}, f.gel_statut === 'bloque' ? 'Compte bloqué' : 'Compte gelé'),
      el('p', {}, `Depuis le ${date(f.gel_le)}.`
        + (f.degel_prevu ? ` Régularisé : de nouveau actif le ${date(f.degel_prevu, true)}.` : '')
        + (f.suppression_prevue ? ` Suppression prévue le ${date(f.suppression_prevue)} sans régularisation.` : '')),
      el('p', { class: 'aide' }, dus.length ? `À régulariser : ${dus.join(', ')}.` : 'Rien à régulariser.'),
      el('p', { class: 'aide' }, 'Lever le gel (erreur ou geste commercial) : le compte est de nouveau actif tout de suite, la '
        + 'suppression est annulée et ce qu\'il devait est effacé. Les compteurs d\'avertissements et de gels sont gardés.'),
      bouton('Lever le gel', async () => {
        if (!window.confirm(`Lever le gel du compte de ${f.pseudo} ?`)) return;
        apresAction(await rpc('admin_lever_gel', { p_joueur: String(f.id) }), montrer);
      }, 'principal'));
  }

  // Tableau d'achats (fiche, ou recherche par numéro de commande). Avec [f], un avertissement peut être annulé.
  function tableAchats(liste, f, montrer) {
    return el('table', { class: 'journal achats' },
      el('thead', {}, el('tr', {}, el('th', {}, 'Date'), el('th', {}, 'Produit'), el('th', {}, 'Prix'), el('th', {}, 'État'))),
      el('tbody', {}, liste.map((a) => el('tr', { class: a.etat === 'rembourse' ? 'rembourse' : '' },
        el('td', {}, date(a.le, true)),
        el('td', {}, nomProduit(a.produit), a.commande ? el('span', { class: 'detail' }, a.commande) : null),
        el('td', {}, a.prix || '—'),
        el('td', {}, a.etat === 'rembourse'
          ? [`Remboursé le ${date(a.rembourse_le)}`,
            a.avertissement ? el('span', { class: 'detail' }, 'avec avertissement') : null,
            a.avertissement_annule_le ? el('span', { class: 'detail' }, `avertissement annulé le ${date(a.avertissement_annule_le)}`) : null,
            a.avertissement && f ? bouton('Annuler l\'avertissement', async () => {
              if (!window.confirm(`Annuler l'avertissement de cet achat (${nomProduit(a.produit)}) ? Le joueur aura un avertissement de moins. `
                + 'Un gel éventuel reste à lever à part.')) return;
              apresAction(await rpc('admin_annuler_avertissement', { p_joueur: String(f.id), p_achat: Number(a.id) }), montrer);
            }, 'petit') : null]
          : a.etat === 'annule' ? 'Annulé' : 'Crédité')))));
  }

  // Les 30 derniers achats du joueur (gardés 15 mois) : remboursements et avertissements.
  function carteAchats(achats, f, montrer) {
    const liste = Array.isArray(achats) ? achats : [];
    return el('section', { class: 'carte' },
      el('h3', {}, 'Achats'),
      liste.length === 0 ? el('p', { class: 'aide' }, 'Aucun achat.') : tableAchats(liste, f, montrer));
  }

  // Résultat d'une recherche par numéro de commande Google.
  function carteCommande(c) {
    return el('section', { class: `carte ${c.supprime ? 'alerte' : 'trouve'}` },
      el('h3', {}, `Commande ${c.numero}`),
      el('p', { class: 'aide' }, c.supprime
        ? 'Le compte du joueur a été supprimé : il ne reste que la trace de l\'achat (gardée 15 mois). Rien ne peut être rendu sur ce compte.'
        : 'Achat trouvé : la fiche du joueur est en dessous.'),
      tableAchats(c.achats, null, null));
  }

  // Offrir ou rendre (contestation, bug, geste commercial) : motif obligatoire, noté au journal.
  function carteOffrir(f, montrer) {
    const champNombre = (nom) => el('input', { type: 'number', min: '0', max: '100', step: '1', value: '0', inputmode: 'numeric', 'aria-label': nom });
    const b = champNombre('Boosters'); const s = champNombre('Boosters stellaires'); const n = champNombre('Nuits claires');
    const motif = el('input', { type: 'text', maxlength: '300', autocomplete: 'off', placeholder: 'Motif (ex. : bug du 8 novembre, e-mail du joueur du 9)', 'aria-label': 'Motif' });
    const valeur = (c) => (c.value.trim() === '' ? 0 : Number(c.value));
    return carteDroit('Offrir ou rendre',
      'Ajoute des boosters, boosters stellaires ou Nuits claires au compte (100 au plus de chaque). Une dette (solde négatif) '
      + 'est comblée d\'abord. Le motif est obligatoire et noté au journal.',
      el('div', { class: 'quantites' },
        el('label', {}, 'Boosters', b), el('label', {}, 'Boosters stellaires', s), el('label', {}, 'Nuits claires', n)),
      motif,
      bouton('Ajouter au compte', async () => {
        const q = [valeur(b), valeur(s), valeur(n)];
        if (q.some((x) => !Number.isInteger(x) || x < 0 || x > 100)) return message('Chaque quantité doit être un nombre entier entre 0 et 100.', true);
        if (q.every((x) => x === 0)) return message('Indique au moins une quantité.', true);
        if (motif.value.trim().length < 5) { motif.focus(); return message('Écris le motif (au moins 5 caractères).', true); }
        if (!window.confirm(`Ajouter au compte de ${f.pseudo} : ${quantites(...q)} ?\nMotif : ${motif.value.trim()}`)) return;
        apresAction(await rpc('admin_offrir', { p_joueur: String(f.id), p_boosters: q[0], p_stellaires: q[1], p_nuits: q[2],
          p_motif: motif.value.trim() }), montrer);
      }, 'principal'));
  }

  // Historique : messages reçus dans le jeu et actions du journal concernant le joueur (50 derniers).
  const MESSAGES_JEU = {
    remboursement: 'Remboursement effectué', avertissement: 'Avertissement reçu', gel: 'Compte gelé', blocage: 'Compte bloqué',
    sanction_pseudo: 'Sanction pseudo injurieux', merci_signalement: 'Merci ! (signalement)', sanction_annulee: 'Sanction annulée',
  };
  let historiqueConsultations = false;

  function detailMessage(x) {
    const c = x.contenu || {};
    if (x.type === 'sanction_pseudo') return `nouveau pseudo : ${c.nouveau || '?'}`;
    if (x.type === 'sanction_annulee') return `pseudo rendu : ${c.pseudo || '?'}`;
    if (x.type === 'remboursement' || x.type === 'avertissement') return c.abonnement ? 'Abonnement Astronome' : nomProduit(c.produit);
    return '';
  }

  function carteHistorique(f, montrer) {
    const tout = Array.isArray(f.historique) ? f.historique : [];
    const corps = el('div');
    const case_ = el('input', { type: 'checkbox', id: 'historique-consultations', checked: historiqueConsultations });
    const remplir = () => {
      const liste = tout.filter((x) => historiqueConsultations || x.action !== 'consulter');
      corps.replaceChildren(liste.length === 0 ? el('p', { class: 'aide' }, 'Rien pour l\'instant.') : el('table', { class: 'journal historique' },
        el('thead', {}, el('tr', {}, el('th', {}, 'Date'), el('th', {}, 'Événement'))),
        el('tbody', {}, liste.map((x) => {
          if (x.sorte === 'message') {
            return el('tr', { class: 'message-jeu' },
              el('td', {}, date(x.le, true)),
              el('td', {}, `Message dans le jeu : ${MESSAGES_JEU[x.type] || x.type}`,
                el('span', { class: 'detail' }, [detailMessage(x), x.lu ? 'vu par le joueur' : 'pas encore vu'].filter(Boolean).join(' · '))));
          }
          const sanction = x.action === 'sanction_pseudo';
          return el('tr', {},
            el('td', {}, date(x.le, true)),
            el('td', {}, ACTIONS[x.action] || String(x.action),
              el('span', { class: 'detail' }, [detailAction(x), `par ${x.par || '—'}`].filter(Boolean).join(' · ')),
              sanction && x.annulee ? el('span', { class: 'detail' }, 'annulée depuis') : null,
              sanction && !x.annulee ? bouton('Annuler la sanction', async () => {
                const ancien = x.details?.ancien || '?';
                if (!window.confirm(`Annuler la sanction ? Le joueur retrouve son pseudo « ${ancien} » (s'il est encore libre) `
                  + 'et il est prévenu dans le jeu.')) return;
                apresAction(await rpc('admin_annuler_sanction', { p_joueur: String(f.id), p_sanction: Number(x.id) }), montrer);
              }, 'petit') : null));
        }))));
    };
    case_.addEventListener('change', () => { historiqueConsultations = case_.checked; remplir(); });
    remplir();
    return el('section', { class: 'carte' },
      el('h3', {}, 'Historique'),
      el('p', { class: 'aide' }, 'Les messages que le joueur a reçus dans le jeu (gardés 60 jours une fois vus) et les actions '
        + 'd\'administration qui le concernent (gardées 12 mois), du plus récent au plus ancien.'),
      el('label', { class: 'case', for: 'historique-consultations' }, case_, ' Montrer les fiches consultées'),
      corps);
  }

  // Signalements, triés au choix (gardé pendant la session)
  let triSignalements = 'nombre';
  const TRIS = [['nombre', 'Les plus signalés'], ['recent', 'Les plus récents'], ['ancien', 'Les plus anciens (à traiter d\'abord)']];

  function ongletSignalements() {
    const racine = el('div');
    const liste = el('div', {}, el('p', { class: 'aide' }, 'Chargement…'));
    const choixTri = el('select', { 'aria-label': 'Trier les signalements' },
      TRIS.map(([v, t]) => el('option', { value: v }, t)));
    choixTri.value = triSignalements;
    choixTri.addEventListener('change', () => {
      triSignalements = choixTri.value;
      charger().catch(surErreur);
    });
    const charger = async () => {
      const r = await rpc('admin_signalements', { p_tri: triSignalements });
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
          const limite = new Date(x.efface_le);
          const urgent = !Number.isNaN(limite.getTime()) && limite - Date.now() < 14 * 86400000;
          return el('section', { class: 'carte signalement' },
            el('h3', {}, pseudo),
            el('p', { class: 'aide' }, `${x.signaleurs} joueur(s), ${x.signalements} signalement(s) · premier le ${date(x.premier)}, dernier le ${date(x.dernier)}`),
            el('p', { class: urgent ? 'erreur-texte' : 'aide' }, `À traiter avant le ${date(x.efface_le)} (effacement du premier signalement)`),
            el('div', { class: 'ligne' }, bouton('Sanctionner', decider('sanction'), 'danger'), bouton('Sans suite', decider('sans_suite'))));
        })));
    };
    racine.append(
      el('p', { class: 'aide' }, 'Pseudos signalés. Les signalements sont effacés 6 mois après leur envoi : traite-les avant.'),
      el('div', { class: 'ligne' }, el('label', { class: 'aide' }, 'Trier : '), choixTri, bouton('Actualiser', charger)),
      liste,
      sectionActivitesSuspectes());
    charger().catch(surErreur);
    return racine;
  }

  // Activité suspecte aux observations (migration 0114) : joueurs arrivés à la 3e fois d'un même jour (observation
  // manuelle en moins de 5 s par étape en moyenne, note d'au moins 90 %), sur les 30 derniers jours.
  function sectionActivitesSuspectes() {
    const liste = el('div', {}, el('p', { class: 'aide' }, 'Chargement…'));
    const pct = (x) => `${Math.round(Number(x || 0) * 100)} %`;
    const secondes = (x) => `${Number(x || 0).toLocaleString('fr-FR', { maximumFractionDigits: 1 })} s`;
    const charger = async () => {
      const r = await rpc('admin_activites_suspectes');
      const j = Array.isArray(r?.joueurs) ? r.joueurs : [];
      liste.replaceChildren(...(j.length === 0
        ? [el('p', { class: 'vide' }, 'Aucun joueur à surveiller.')]
        : j.map((x) => {
          const pseudo = String(x.pseudo);
          const etiquettes = [];
          if (x.suspendu) etiquettes.push(['Suspendu', 'rouge']);
          if (x.testeur) etiquettes.push(['Compte de test', 'vert']);
          const dernieres = Array.isArray(x.dernieres) ? x.dernieres : [];
          return el('section', { class: 'carte suspect' },
            el('h3', {}, pseudo),
            etiquettes.length ? el('div', { class: 'etiquettes' }, etiquettes.map(([t, c]) => el('span', { class: `etiquette ${c}` }, t))) : null,
            el('p', { class: 'aide' }, `${x.total_30j} activité(s) suspecte(s) en 30 jours, dont ${x.jours} jour(s) à 3 fois ou plus · dernière le ${date(x.dernier, true)}`),
            el('ul', { class: 'liste-simple' }, dernieres.map((a) => el('li', {},
              `${date(a.le, true)} : ${a.rang}e fois du jour, ${a.etapes} étape(s), ${secondes(a.duree_moyenne_s)} par étape, note ${pct(a.note)}`))),
            el('div', { class: 'ligne' }, bouton('Ouvrir sa fiche', () => { rechercheDemandee = pseudo; ouvrirOnglet('joueurs'); })));
        })));
    };
    const section = el('div', {},
      el('h3', {}, 'Activité suspecte aux observations'),
      el('p', { class: 'aide' }, 'Joueurs qui ont fini au moins 3 observations manuelles le même jour en moins de 5 secondes '
        + 'par étape en moyenne, avec une note d\'au moins 90 %. Le jeu les bloque déjà quelques minutes à chaque fois ; '
        + 'à toi de décider s\'il faut suspendre le compte (fiche du joueur).'),
      el('div', { class: 'ligne' }, bouton('Actualiser', charger)),
      liste);
    charger().catch(surErreur);
    return section;
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
      await rpc('admin_verifier', { p_appareil: identifiantAppareil() });
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
