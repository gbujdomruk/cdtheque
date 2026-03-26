// ═══════════════════════════════════════════════════════════
// Cloudflare Worker — Arkiv — Discogs OAuth Proxy
// Variables d'environnement à configurer dans Cloudflare :
//   DISCOGS_CONSUMER_KEY     → votre Consumer Key Discogs
//   DISCOGS_CONSUMER_SECRET  → votre Consumer Secret Discogs
//   APP_URL                  → https://votre-pseudo.github.io/cdtheque
// ═══════════════════════════════════════════════════════════

const DISCOGS_API = 'https://api.discogs.com';
const DISCOGS_REQUEST_TOKEN_URL = 'https://www.discogs.com/oauth/request_token';
const DISCOGS_AUTHORIZE_URL = 'https://www.discogs.com/oauth/authorize';
const DISCOGS_ACCESS_TOKEN_URL = 'https://www.discogs.com/oauth/access_token';
const USER_AGENT = 'Arkiv/1.0 +https://github.com';

// ─── CORS headers ────────────────────────────────────────
function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
  };
}

function jsonResponse(data, status = 200, origin) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
  });
}

// ─── OAuth 1.0a helpers ──────────────────────────────────
function generateNonce() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
}

function percentEncode(str) {
  return encodeURIComponent(str).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

async function hmacSha1(key, data) {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    'raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, enc.encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

async function buildOAuthHeader(method, url, params, consumerKey, consumerSecret, token = '', tokenSecret = '') {
  const oauthParams = {
    oauth_consumer_key: consumerKey,
    oauth_nonce: generateNonce(),
    oauth_signature_method: 'HMAC-SHA1',
    oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
    oauth_version: '1.0',
    ...(token ? { oauth_token: token } : {}),
  };

  const allParams = { ...oauthParams, ...params };
  const sortedParams = Object.keys(allParams).sort()
    .map(k => `${percentEncode(k)}=${percentEncode(allParams[k])}`).join('&');

  const baseString = [method.toUpperCase(), percentEncode(url), percentEncode(sortedParams)].join('&');
  const signingKey = `${percentEncode(consumerSecret)}&${percentEncode(tokenSecret)}`;
  const signature = await hmacSha1(signingKey, baseString);

  oauthParams['oauth_signature'] = signature;
  const headerValue = 'OAuth ' + Object.keys(oauthParams)
    .map(k => `${percentEncode(k)}="${percentEncode(oauthParams[k])}"`)
    .join(', ');

  return headerValue;
}

// ─── Routes ──────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || env.APP_URL;

    // Preflight CORS
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders(origin) });
    }

    // ── GET /request_token ─────────────────────────────
    // Étape 1 OAuth : obtient un request token temporaire
    if (url.pathname === '/request_token') {
      const callbackUrl = `${url.origin}/callback`;
      const authHeader = await buildOAuthHeader(
        'GET', DISCOGS_REQUEST_TOKEN_URL,
        { oauth_callback: callbackUrl },
        env.DISCOGS_CONSUMER_KEY, env.DISCOGS_CONSUMER_SECRET
      );

      const res = await fetch(DISCOGS_REQUEST_TOKEN_URL, {
        headers: { 'Authorization': authHeader, 'User-Agent': USER_AGENT }
      });

      if (!res.ok) {
        return jsonResponse({ error: 'Discogs request token failed', status: res.status }, 500, origin);
      }

      const text = await res.text();
      const params = Object.fromEntries(new URLSearchParams(text));

      // Stocke le request_token_secret temporairement dans un cookie sécurisé (5 min)
      const redirectUrl = `${DISCOGS_AUTHORIZE_URL}?oauth_token=${params.oauth_token}`;
      return new Response(null, {
        status: 302,
        headers: {
          'Location': redirectUrl,
          'Set-Cookie': `rts=${params.oauth_token_secret}; HttpOnly; Secure; SameSite=Lax; Max-Age=300; Path=/`,
          ...corsHeaders(origin),
        },
      });
    }

    // ── GET /callback ──────────────────────────────────
    // Étape 2 OAuth : échange le verifier contre un access token
    if (url.pathname === '/callback') {
      const oauthToken = url.searchParams.get('oauth_token');
      const oauthVerifier = url.searchParams.get('oauth_verifier');
      const cookieHeader = request.headers.get('Cookie') || '';
      const rts = cookieHeader.split(';').find(c => c.trim().startsWith('rts='))?.split('=')[1]?.trim() || '';

      if (!oauthToken || !oauthVerifier) {
        return jsonResponse({ error: 'Missing OAuth params' }, 400, origin);
      }

      const authHeader = await buildOAuthHeader(
        'POST', DISCOGS_ACCESS_TOKEN_URL,
        { oauth_verifier: oauthVerifier },
        env.DISCOGS_CONSUMER_KEY, env.DISCOGS_CONSUMER_SECRET,
        oauthToken, rts
      );

      const res = await fetch(DISCOGS_ACCESS_TOKEN_URL, {
        method: 'POST',
        headers: { 'Authorization': authHeader, 'User-Agent': USER_AGENT }
      });

      if (!res.ok) {
        return jsonResponse({ error: 'Access token exchange failed' }, 500, origin);
      }

      const text = await res.text();
      const params = Object.fromEntries(new URLSearchParams(text));

      // Redirige vers l'app avec le token dans le fragment URL (#)
      // Le fragment n'est jamais envoyé au serveur — sécurisé
      const appRedirect = `${env.APP_URL}#access_token=${params.oauth_token}&token_secret=${params.oauth_token_secret}`;
      return new Response(null, {
        status: 302,
        headers: {
          'Location': appRedirect,
          'Set-Cookie': 'rts=; HttpOnly; Secure; Max-Age=0; Path=/', // supprime le cookie
          ...corsHeaders(origin),
        },
      });
    }

    // ── GET /search?q=...&token=...&secret=... ─────────
    // Proxy pour les recherches Discogs (évite d'exposer les clés consumer)
    if (url.pathname === '/search') {
      const q = url.searchParams.get('q') || '';
      const token = url.searchParams.get('token') || '';
      const secret = url.searchParams.get('secret') || '';

      if (!q || !token) {
        return jsonResponse({ error: 'Missing q or token' }, 400, origin);
      }

      const searchUrl = `${DISCOGS_API}/database/search?q=${encodeURIComponent(q)}&type=release&per_page=5&page=1`;
      const authHeader = await buildOAuthHeader(
        'GET', `${DISCOGS_API}/database/search`,
        { q, type: 'release', per_page: '5', page: '1' },
        env.DISCOGS_CONSUMER_KEY, env.DISCOGS_CONSUMER_SECRET,
        token, secret
      );

      const res = await fetch(searchUrl, {
        headers: {
          'Authorization': authHeader,
          'User-Agent': USER_AGENT,
          'Accept': 'application/vnd.discogs.v2.plaintext+json',
        }
      });

      const data = await res.json();
      return jsonResponse(data, res.status, origin);
    }

    return jsonResponse({ error: 'Not found', routes: ['/request_token', '/callback', '/search'] }, 404, origin);
  }
};
