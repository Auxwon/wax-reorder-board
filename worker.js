/* ============================================================================
   Wax Reorder Board - Cloudflare Worker
   A shared, password-protected restocking tracker for Wax Museum Records.
   - Serves the page (bundled reorder.html)
   - Shared reorder list in KV (record of what's on order + who + committed spend)
   - Shopify OAuth (read_products, read_inventory, read_orders) for a live
     "what sold and is now low" reorder-suggestions feed
   Read-only against Shopify: it never changes stock, orders, or the store.
============================================================================ */
import pageHtml from './reorder.html';

const SHOP = 'wax-museum-records.myshopify.com';
const API_VERSION = '2026-01';
const SHOP_SCOPES = 'read_products,read_inventory,read_orders';
const STATUSES = ['to_order', 'ordered', 'received'];
const DEFAULT_SUPPLIERS = ['One Nation', 'Fat Beats', 'Traffic', 'Rushhour', 'Juno', 'Grace', 'Greg Japan', 'Inertia', 'Rocket', 'Universal', 'Efficient Space'];

/* ---------------- helpers ---------------- */
function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
  });
}
function htmlResponse(html) {
  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer' } });
}
function b64url(buf) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
async function hmacB64(secret, msg) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64url(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(msg)));
}
async function shaB64(s) { return b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s))); }
function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
async function pbkdf2B64(passcode, saltHex) {
  const salt = Uint8Array.from((saltHex.match(/.{2}/g) || []).map((h) => parseInt(h, 16)));
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(passcode), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' }, km, 256);
  return b64url(bits);
}

/* ---------------- auth (passcode + signed session cookie) ---------------- */
const SESSION_TTL = 60 * 60 * 24 * 30;
async function passcodeSet(env) {
  if (env.DASHBOARD_PASSCODE) return true;
  if (env.STORE) return !!(await env.STORE.get('sys:passcode_hash'));
  return false;
}
let _sessionKeyCache = null;
async function getSessionKey(env) {
  if (env.SESSION_SECRET) return env.SESSION_SECRET;
  if (_sessionKeyCache) return _sessionKeyCache;
  if (env.STORE) {
    let k = await env.STORE.get('sys:session_secret');
    if (!k) {
      const b = new Uint8Array(32); crypto.getRandomValues(b);
      k = Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
      await env.STORE.put('sys:session_secret', k);
    }
    _sessionKeyCache = k; return k;
  }
  return env.DASHBOARD_PASSCODE || 'unset';
}
async function makeSession(env) {
  const payload = 'v1.' + Math.floor(Date.now() / 1000);
  return payload + '.' + await hmacB64(await getSessionKey(env), payload);
}
async function validSession(env, token) {
  if (!token) return false;
  const i = token.lastIndexOf('.'); if (i < 0) return false;
  const payload = token.slice(0, i);
  if (!timingSafeEqual(token.slice(i + 1), await hmacB64(await getSessionKey(env), payload))) return false;
  const issued = parseInt(payload.split('.')[1], 10);
  return !!issued && (Date.now() / 1000 - issued) <= SESSION_TTL;
}
function getCookie(request, name) {
  const m = (request.headers.get('Cookie') || '').match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : null;
}
async function isLoggedIn(request, env) { return await validSession(env, getCookie(request, 'wax_session')); }
function sessionCookie(token, maxAge) {
  return 'wax_session=' + encodeURIComponent(token) + '; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=' + maxAge;
}
async function apiLogin(env, request) {
  if (!(await passcodeSet(env))) return json({ ok: false, error: 'no_passcode' }, 400);
  let body; try { body = await request.json(); } catch (e) { return json({ ok: false }, 400); }
  const passcode = String((body && body.passcode) || '');
  let ok = false;
  if (env.DASHBOARD_PASSCODE) ok = timingSafeEqual(await shaB64(passcode), await shaB64(env.DASHBOARD_PASSCODE));
  else if (env.STORE) {
    const stored = await env.STORE.get('sys:passcode_hash');
    if (stored) { const dot = stored.indexOf('.'); ok = timingSafeEqual(await pbkdf2B64(passcode, stored.slice(0, dot)), stored.slice(dot + 1)); }
  }
  if (!ok) return json({ ok: false }, 401);
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'Set-Cookie': sessionCookie(await makeSession(env), SESSION_TTL) } });
}
async function apiSetup(env, request) {
  if (!env.STORE) return json({ ok: false, error: 'no_store' }, 400);
  if ((await passcodeSet(env)) && !(await isLoggedIn(request, env))) return json({ ok: false, error: 'exists' }, 403);
  let body; try { body = await request.json(); } catch (e) { return json({ ok: false }, 400); }
  const passcode = String((body && body.passcode) || '');
  if (passcode.length < 6) return json({ ok: false, error: 'too_short' }, 400);
  const saltB = new Uint8Array(16); crypto.getRandomValues(saltB);
  const saltHex = Array.from(saltB).map((x) => x.toString(16).padStart(2, '0')).join('');
  await env.STORE.put('sys:passcode_hash', saltHex + '.' + (await pbkdf2B64(passcode, saltHex)));
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'Set-Cookie': sessionCookie(await makeSession(env), SESSION_TTL) } });
}
function apiLogout() {
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'Set-Cookie': sessionCookie('', 0) } });
}

/* ---------------- Shopify OAuth + GraphQL ---------------- */
function randomState() {
  const a = new Uint8Array(16); crypto.getRandomValues(a);
  return Array.from(a).map((b) => b.toString(16).padStart(2, '0')).join('');
}
async function shopAuthStart(env, url) {
  const state = randomState();
  await env.STORE.put('oauthstate:shop', state, { expirationTtl: 600 });
  const p = new URLSearchParams({
    client_id: env.SHOP_CLIENT_ID || '',
    scope: SHOP_SCOPES,
    redirect_uri: url.origin + '/auth/shop/callback',
    state
  });
  return Response.redirect('https://' + SHOP + '/admin/oauth/authorize?' + p.toString(), 302);
}
async function shopAuthCallback(env, url) {
  const code = url.searchParams.get('code');
  const gotState = url.searchParams.get('state');
  const wantState = await env.STORE.get('oauthstate:shop');
  if (!code || !gotState || gotState !== wantState) {
    return new Response('That authorisation didn’t complete cleanly. Go back and click Connect Shopify again.', { status: 400 });
  }
  await env.STORE.delete('oauthstate:shop');
  const res = await fetch('https://' + SHOP + '/admin/oauth/access_token', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_id: env.SHOP_CLIENT_ID, client_secret: env.SHOP_CLIENT_SECRET, code })
  });
  if (!res.ok) return new Response('The Shopify connection couldn’t be finished (' + res.status + '). Check the app settings and try again.', { status: 502 });
  const t = await res.json();
  await env.STORE.put('tokens:shop', JSON.stringify({ access_token: t.access_token, obtained_at: new Date().toISOString() }));
  return Response.redirect(url.origin + '/', 302);
}
async function shopToken(env) {
  const raw = await env.STORE.get('tokens:shop');
  if (!raw) return null;
  try { return (JSON.parse(raw) || {}).access_token || null; } catch (e) { return null; }
}
async function shopifyGraphql(env, query, variables) {
  const token = await shopToken(env);
  if (!token) { const e = new Error('shop not connected'); e.status = 401; throw e; }
  const res = await fetch('https://' + SHOP + '/admin/api/' + API_VERSION + '/graphql.json', {
    method: 'POST',
    headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' },
    body: JSON.stringify({ query, variables: variables || {} })
  });
  if (!res.ok) { const e = new Error('shopify http ' + res.status); e.status = res.status; throw e; }
  const j = await res.json();
  if (j && j.errors && j.errors.length) { const e = new Error('shopify: ' + (j.errors[0].message || 'error')); e.status = 502; throw e; }
  return j && j.data;
}
async function shopName(env) {
  try { const d = await shopifyGraphql(env, '{ shop { name } }'); return (d && d.shop && d.shop.name) || 'Shopify'; }
  catch (e) { return null; }
}

/* "What sold and is now low": walk orders (last 60d), sum sold per variant and
   read each variant's current inventory in the same pass, then keep the ones
   at or below the threshold, busiest sellers first. */
async function shopSuggestions(env, threshold, fromDate, untilDate) {
  const from = /^\d{4}-\d{2}-\d{2}$/.test(fromDate) ? fromDate : new Date(Date.now() - 60 * 86400000).toISOString().slice(0, 10);
  const until = /^\d{4}-\d{2}-\d{2}$/.test(untilDate) ? untilDate : '';
  const range = 'created_at:>=' + from + (until ? ' created_at:<=' + until : '');
  const q = 'query($cursor:String){ orders(first:60, sortKey:CREATED_AT, query:"' + range + ' -status:cancelled", after:$cursor){ pageInfo{ hasNextPage endCursor } nodes{ lineItems(first:50){ nodes{ quantity sku title variant{ id sku title inventoryQuantity product{ title vendor isGiftCard productType } } } } } } }';
  const agg = {};
  let cursor = null, pages = 0;
  do {
    const data = await shopifyGraphql(env, q, { cursor });
    const orders = (data && data.orders) || {};
    for (const o of (orders.nodes || [])) {
      for (const li of ((o.lineItems && o.lineItems.nodes) || [])) {
        const v = li.variant; if (!v || !v.id) continue;
        const e = agg[v.id] || { sold: 0, inv: v.inventoryQuantity, title: (v.product && v.product.title) || li.title || 'Item', variantTitle: (v.title && v.title !== 'Default Title') ? v.title : '', sku: v.sku || li.sku || '', vendor: (v.product && v.product.vendor) || '', giftCard: !!(v.product && v.product.isGiftCard), productType: (v.product && v.product.productType) || '' };
        e.sold += (li.quantity || 0);
        if (typeof v.inventoryQuantity === 'number') e.inv = v.inventoryQuantity;
        agg[v.id] = e;
      }
    }
    cursor = orders.pageInfo && orders.pageInfo.hasNextPage ? orders.pageInfo.endCursor : null;
    pages++;
  } while (cursor && pages < 24);
  const th = (typeof threshold === 'number' && threshold >= 0) ? threshold : 3;
  /* Drop non-reorderable noise: gift cards/vouchers and the used/secondhand bulk
     bins (which run on big negative stock and aren't restocked from a supplier). */
  const NOISE_RE = /gift\s?(card|voucher)|voucher|second\s?hand|secondhand|used bin|\$\d+\s?bin/i;
  return Object.keys(agg).map((id) => Object.assign({ id }, agg[id]))
    .filter((e) => typeof e.inv === 'number' && e.inv <= th &&
      !e.giftCard && !NOISE_RE.test(e.title || '') && !/gift ?card/i.test(e.productType || ''))
    .sort((a, b) => (b.sold - a.sold) || (a.inv - b.inv))
    .slice(0, 150);
}

/* ---------------- reorder items store ---------------- */
async function getItems(env) {
  const raw = await env.STORE.get('reorder:items');
  if (!raw) return [];
  try { const a = JSON.parse(raw); return Array.isArray(a) ? a : []; } catch (e) { return []; }
}
async function saveItems(env, items) { await env.STORE.put('reorder:items', JSON.stringify(items)); }
async function getSuppliers(env) {
  const raw = await env.STORE.get('reorder:suppliers');
  if (!raw) return DEFAULT_SUPPLIERS.slice();
  try { const a = JSON.parse(raw); return Array.isArray(a) ? a : DEFAULT_SUPPLIERS.slice(); } catch (e) { return DEFAULT_SUPPLIERS.slice(); }
}
async function saveSuppliers(env, list) { await env.STORE.put('reorder:suppliers', JSON.stringify(list)); }
async function apiSuppliers(env, request) {
  let body; try { body = await request.json(); } catch (e) { return json({ ok: false }, 400); }
  const action = body && body.action;
  const name = String((body && body.name) || '').trim().slice(0, 80);
  let list = await getSuppliers(env);
  if (action === 'add') { if (name && list.indexOf(name) < 0) list.push(name); }
  else if (action === 'remove') { list = list.filter((n) => n !== name); }
  else return json({ ok: false, error: 'bad action' }, 400);
  await saveSuppliers(env, list);
  return json({ ok: true, suppliers: list });
}
function newId() { return Date.now().toString(36) + Math.random().toString(36).slice(2, 7); }
function cleanItem(input, base) {
  const out = Object.assign({}, base || {});
  const s = (v, max) => (v == null ? '' : String(v)).slice(0, max || 200);
  if ('title' in input) out.title = s(input.title, 200);
  if ('variantTitle' in input) out.variantTitle = s(input.variantTitle, 120);
  if ('sku' in input) out.sku = s(input.sku, 80);
  if ('supplier' in input) out.supplier = s(input.supplier, 120);
  if ('orderedBy' in input) out.orderedBy = s(input.orderedBy, 60);
  if ('note' in input) out.note = s(input.note, 400);
  if ('eta' in input) out.eta = s(input.eta, 40);
  if ('qty' in input) { const n = Math.round(Number(input.qty)); out.qty = isFinite(n) && n >= 0 ? n : 0; }
  if ('unitCost' in input) { const n = Number(input.unitCost); out.unitCost = isFinite(n) && n >= 0 ? Math.round(n * 100) / 100 : 0; }
  if ('status' in input && STATUSES.includes(input.status)) out.status = input.status;
  return out;
}
function committedSpend(items) {
  return Math.round(items.filter((i) => i.status === 'ordered').reduce((s, i) => s + (Number(i.qty) || 0) * (Number(i.unitCost) || 0), 0) * 100) / 100;
}

async function apiState(env) {
  const items = await getItems(env);
  const token = await shopToken(env);
  let shop = { connected: false, name: null };
  if (token) shop = { connected: true, name: await shopName(env) };
  return json({ items, suppliers: await getSuppliers(env), committed: committedSpend(items), shop, generatedAt: new Date().toISOString() });
}
async function apiAddItem(env, request) {
  let body; try { body = await request.json(); } catch (e) { return json({ ok: false }, 400); }
  const items = await getItems(env);
  const now = new Date().toISOString();
  const item = cleanItem(body || {}, { id: newId(), title: '', variantTitle: '', sku: '', supplier: '', qty: 1, unitCost: 0, orderedBy: '', note: '', eta: '', status: 'to_order', source: body && body.source === 'shopify' ? 'shopify' : 'manual', createdAt: now, updatedAt: now });
  if (!item.title) return json({ ok: false, error: 'title required' }, 400);
  items.unshift(item);
  await saveItems(env, items);
  return json({ ok: true, item });
}
async function apiUpdateItem(env, request) {
  let body; try { body = await request.json(); } catch (e) { return json({ ok: false }, 400); }
  const id = body && body.id; if (!id) return json({ ok: false, error: 'id required' }, 400);
  const items = await getItems(env);
  const idx = items.findIndex((i) => i.id === id);
  if (idx < 0) return json({ ok: false, error: 'not found' }, 404);
  items[idx] = cleanItem(body, items[idx]);
  items[idx].updatedAt = new Date().toISOString();
  await saveItems(env, items);
  return json({ ok: true, item: items[idx] });
}
async function apiDeleteItem(env, request) {
  let body; try { body = await request.json(); } catch (e) { return json({ ok: false }, 400); }
  const id = body && body.id; if (!id) return json({ ok: false, error: 'id required' }, 400);
  const items = (await getItems(env)).filter((i) => i.id !== id);
  await saveItems(env, items);
  return json({ ok: true });
}
async function apiSuggestions(env, url) {
  if (!(await shopToken(env))) return json({ error: 'shop_not_connected' }, 400);
  const th = Math.max(0, Math.min(50, parseInt(url.searchParams.get('threshold') || '3', 10)));
  let from = url.searchParams.get('from') || '';
  let until = url.searchParams.get('to') || '';
  if (!/^\d{4}-\d{2}-\d{2}$/.test(from)) {
    const days = [30, 60, 90].indexOf(parseInt(url.searchParams.get('days') || '60', 10)) >= 0 ? parseInt(url.searchParams.get('days'), 10) : 60;
    from = new Date(Date.now() - days * 86400000).toISOString().slice(0, 10);
    until = '';
  }
  try { return json({ items: await shopSuggestions(env, th, from, until) }); }
  catch (e) { return json({ error: 'shopify', plain: 'Couldn’t read Shopify just now. Try again in a moment.' }, e.status || 500); }
}

/* ---------------- router ---------------- */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    if (path === '/favicon.ico') return new Response(null, { status: 204 });
    if (path === '/api/login' && request.method === 'POST') return apiLogin(env, request);
    if (path === '/api/setup' && request.method === 'POST') return apiSetup(env, request);
    if (path === '/api/logout' && request.method === 'POST') return apiLogout();

    const loggedIn = await isLoggedIn(request, env);
    if (path === '/' || path === '/index.html') {
      if (loggedIn) return htmlResponse(pageHtml);
      return htmlResponse(pageHtml); /* page shows its own login/setup gate */
    }
    if (path === '/api/gate') return json({ passcodeSet: await passcodeSet(env), loggedIn });

    if (path.startsWith('/auth/shop/')) {
      if (!loggedIn) return Response.redirect(url.origin + '/', 302);
      if (path === '/auth/shop/start') return shopAuthStart(env, url);
      if (path === '/auth/shop/callback') return shopAuthCallback(env, url);
    }
    if (path.startsWith('/api/')) {
      if (!loggedIn) return json({ error: 'auth' }, 401);
      if (path === '/api/state' && request.method === 'GET') return apiState(env);
      if (path === '/api/items' && request.method === 'POST') return apiAddItem(env, request);
      if (path === '/api/items/update' && request.method === 'POST') return apiUpdateItem(env, request);
      if (path === '/api/items/delete' && request.method === 'POST') return apiDeleteItem(env, request);
      if (path === '/api/suppliers' && request.method === 'POST') return apiSuppliers(env, request);
      if (path === '/api/suggestions' && request.method === 'GET') return apiSuggestions(env, url);
      if (path === '/api/disconnect' && request.method === 'POST') { await env.STORE.delete('tokens:shop'); return json({ ok: true }); }
    }
    return new Response('Not found', { status: 404 });
  }
};
// EOF worker.js
