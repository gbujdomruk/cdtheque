// ═══════════════════════════════════════════════════════════
// Cloudflare Worker — Arkiv — Discogs OAuth Proxy (Version Corrigée)
// ═══════════════════════════════════════════════════════════

const DISCOGS_API = 'https://api.discogs.com';
const DISCOGS_REQUEST_TOKEN_URL = 'https://api.discogs.com/oauth/request_token';
const DISCOGS_AUTHORIZE_URL = 'https://www.discogs.com/oauth/authorize';
const DISCOGS_ACCESS_TOKEN_URL = 'https://api.discogs.com/oauth/access_token';
const USER_AGENT = 'Arkiv/1.0 +https://github.com';

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
  return 'OAuth ' + Object.keys(oauthParams)
    .map(k => `${percentEncode(k)}="${percentEncode(oauthParams[k])}"`)
    .join(', ');
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || env.APP_URL;

    if (request.method === 'OPTIONS') return new Response(null, { headers: corsHeaders(origin) });

    // ── GET /request_token ──
    if (url.pathname === '/request_token') {
      const callbackUrl = `${url.origin}/callback`;
      
      // 1. On génère l'en-tête de base SANS le callback dans les params de signature
      // Car Discogs semble l'exclure de sa base string (vu ton dernier message d'erreur)
      const oauthParams = {
        oauth_consumer_key: env.DISCOGS_CONSUMER_KEY,
        oauth_nonce: generateNonce(),
        oauth_signature_method: 'HMAC-SHA1',
        oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
        oauth_version: '1.0',
        oauth_callback: callbackUrl // On l'inclut ici pour le calcul
      };

      // 2. On trie et on signe
      const sortedParams = Object.keys(oauthParams).sort()
        .map(k => `${percentEncode(k)}=${percentEncode(oauthParams[k])}`).join('&');

      const baseString = ['POST', percentEncode(DISCOGS_REQUEST_TOKEN_URL), percentEncode(sortedParams)].join('&');
      const signingKey = `${percentEncode(env.DISCOGS_CONSUMER_SECRET)}&`;
      const signature = await hmacSha1(signingKey, baseString);

      oauthParams['oauth_signature'] = signature;

      // 3. On construit l'en-tête final
      const authHeader = 'OAuth ' + Object.keys(oauthParams)
        .map(k => `${percentEncode(k)}="${percentEncode(oauthParams[k])}"`)
        .join(', ');

      const res = await fetch(DISCOGS_REQUEST_TOKEN_URL, {
        method: 'POST',
        headers: { 
          'Authorization': authHeader, 
          'User-Agent': USER_AGENT 
        }
      });

      if (!res.ok) {
        const errText = await res.text();
        return jsonResponse({ error: 'Discogs request token failed', details: errText, status: res.status }, 500, origin);
      }

      const params = Object.fromEntries(new URLSearchParams(await res.text()));
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

    // ── GET /callback ──
    if (url.pathname === '/callback') {
      const oauthToken = url.searchParams.get('oauth_token');
      const oauthVerifier = url.searchParams.get('oauth_verifier');
      const cookieHeader = request.headers.get('Cookie') || '';
      const rts = cookieHeader.split(';').find(c => c.trim().startsWith('rts='))?.split('=')[1] || '';

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

      if (!res.ok) return jsonResponse({ error: 'Access token exchange failed' }, 500, origin);

      const params = Object.fromEntries(new URLSearchParams(await res.text()));
      const appRedirect = `${env.APP_URL}#access_token=${params.oauth_token}&token_secret=${params.oauth_token_secret}`;
      
      return new Response(null, {
        status: 302,
        headers: {
          'Location': appRedirect,
          'Set-Cookie': 'rts=; HttpOnly; Secure; Max-Age=0; Path=/',
          ...corsHeaders(origin),
        },
      });
    }

    // ── GET /search ──
    if (url.pathname === '/search') {
      const q = url.searchParams.get('q') || '';
      const token = url.searchParams.get('token') || '';
      const secret = url.searchParams.get('secret') || '';

      const searchUrl = `${DISCOGS_API}/database/search?q=${encodeURIComponent(q)}&type=release&per_page=5&page=1`;
      const authHeader = await buildOAuthHeader(
        'GET', `${DISCOGS_API}/database/search`,
        { q, type: 'release', per_page: '5', page: '1' },
        env.DISCOGS_CONSUMER_KEY, env.DISCOGS_CONSUMER_SECRET,
        token, secret
      );

      const res = await fetch(searchUrl, {
        headers: { 'Authorization': authHeader, 'User-Agent': USER_AGENT, 'Accept': 'application/vnd.discogs.v2.plaintext+json' }
      });

      return jsonResponse(await res.json(), res.status, origin);
    }

    return jsonResponse({ error: 'Not found' }, 404, origin);
  }
};
