'use strict';
/*
 * Manhunt - no backend of our own. Phones talk through public MQTT brokers
 * (both at once, so one outage does not stop a game). Everything is AES-GCM
 * encrypted with a key derived from the game code, so brokers see only noise.
 *
 * Topics under <base>/, all retained so a reloaded phone can catch up:
 *   s        game setup, written by the host (newest `v` wins)
 *   p/<id>   one player's name and last sent position (newest `ts` wins)
 *   c/<id>   a hider was caught, written by anyone
 */
const BROKERS = ['wss://broker.hivemq.com:8884/mqtt', 'wss://broker.emqx.io:8084/mqtt'];
const HUNTERS = 2, HIDERS = 3, MAX_PLAYERS = HUNTERS + HIDERS;
const PULSE_MS = 60000;
const STALE_MS = 150000;
const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const STORE = 'manhunt.session';

let session = null;      // {code, id, name}
let key = null, base = '';
let clients = [];
let game = null;
let players = {};        // id -> last message from that player
let caught = {};         // hiderId -> {by, ts}
let fix = null;          // my latest GPS fix
let geoError = null, watchId = null, needPing = false;
let lastPulse = -1, lastAlertPulse = -1, wasOut = false, ended = false, drawing = false;
let wakeLock = null, audio = null, joinedAt = 0, tickCount = 0;

const $ = id => document.getElementById(id);
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const normCode = s => s.toUpperCase().replace(/[^A-Z0-9]/g, '');
const prettyCode = c => c.slice(0, 4) + '-' + c.slice(4);
const mmss = ms => { const s = Math.max(0, Math.ceil(ms / 1000)); return Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0'); };
const isHost = () => game && session && game.host === session.id;
const rosterMe = () => game && session && game.roster.find(r => r.id === session.id);
const huntStart = () => game.startAt + game.hideMin * 60000;
const endAt = () => huntStart() + game.durMin * 60000;

/* ---------- crypto ---------- */
const enc = new TextEncoder(), dec = new TextDecoder();
async function deriveRoom(code) {
  // One slow KDF yields both the key and the topic, so the topic visible on
  // the public broker cannot be used to brute-force the code cheaply.
  const material = await crypto.subtle.importKey('raw', enc.encode(code), 'PBKDF2', false, ['deriveBits']);
  const bits = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode('manhunt-v1'), iterations: 150000 }, material, 512));
  key = await crypto.subtle.importKey('raw', bits.slice(0, 32), 'AES-GCM', false, ['encrypt', 'decrypt']);
  base = 'manhunt1/' + [...bits.slice(32, 48)].map(b => b.toString(16).padStart(2, '0')).join('');
}
async function seal(sub, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(sub) }, key, enc.encode(JSON.stringify(obj))));
  const all = new Uint8Array(12 + ct.length); all.set(iv); all.set(ct, 12);
  return btoa(String.fromCharCode(...all));
}
async function open_(sub, text) {
  const all = Uint8Array.from(atob(text), c => c.charCodeAt(0));
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: all.slice(0, 12), additionalData: enc.encode(sub) }, key, all.slice(12));
  return JSON.parse(dec.decode(pt));
}

/* ---------- network ---------- */
function connect() {
  clients = BROKERS.map(url => {
    const c = mqtt.connect(url, { reconnectPeriod: 3000, connectTimeout: 8000, keepalive: 30, clean: true });
    c.on('connect', () => { c.subscribe(base + '/#', { qos: 1 }); announce(); render(); });
    c.on('close', render);
    c.on('error', () => {});
    c.on('message', (topic, payload) => onMessage(topic, payload.toString()).catch(() => {}));
    return c;
  });
}
function disconnect() { clients.forEach(c => c.end(true)); clients = []; }
async function publish(sub, obj) {
  const body = await seal(sub, obj);
  clients.forEach(c => c.publish(base + '/' + sub, body, { qos: 1, retain: true }));
}
function clearRetained(sub) { clients.forEach(c => c.publish(base + '/' + sub, '', { qos: 1, retain: true })); }

async function onMessage(topic, text) {
  if (!topic.startsWith(base + '/')) return;
  const sub = topic.slice(base.length + 1);
  const [kind, id] = sub.split('/');
  if (kind === 'p' && !text) {           // a player left
    if (players[id]) { delete players[id]; }
    if (isHost() && game.phase === 'lobby' && game.roster.some(r => r.id === id)) {
      game.roster = game.roster.filter(r => r.id !== id); pushGame();
    }
    return render();
  }
  if (!text) return;
  const m = await open_(sub, text);
  if (kind === 's') {
    if (!game || m.v > game.v) {
      if (m.phase === 'play' && (!game || game.phase !== 'play')) { didFitArea = false; acquireWake(); }
      game = m;
    }
  } else if (kind === 'p' && m.id === id) {
    if (!players[id] || m.ts >= players[id].ts) {
      const prev = players[id];
      // A reloading phone announces itself without coordinates; keep the last known spot.
      if (prev && m.lat === undefined && prev.lat !== undefined) Object.assign(m, { lat: prev.lat, lng: prev.lng, acc: prev.acc, at: prev.at, out: prev.out });
      players[id] = m;
      if (isHost()) hostAdmit(m);
      maybeAlert(m);
    }
  } else if (kind === 'c' && !caught[id]) {
    caught[id] = m;
  } else {
    return;
  }
  render();
}

function hostAdmit(m) {
  if (game.phase !== 'lobby') return;
  const name = String(m.name).slice(0, 16);
  const r = game.roster.find(x => x.id === m.id);
  if (r) { if (r.name !== name) { r.name = name; pushGame(); } return; }
  if (game.roster.length >= MAX_PLAYERS) return;
  const hunters = game.roster.filter(x => x.role === 'hunter').length;
  game.roster.push({ id: m.id, name, role: hunters < HUNTERS ? 'hunter' : 'hider' });
  pushGame();
}
function pushGame() { game.v = Math.max(Date.now(), game.v + 1); publish('s', game); render(); }

/** Lobby heartbeat. Carries no position: nobody is tracked before the hunt. */
function announce() {
  if (!session || (game && game.phase !== 'lobby')) return;
  publish('p/' + session.id, { id: session.id, name: session.name, ts: Date.now(), gps: !!fix });
}

/* ---------- location ---------- */
function startGeo() {
  if (watchId !== null || ended) return;
  if (!navigator.geolocation) { geoError = 'Tenhle prohlížeč neumí polohu.'; return render(); }
  watchId = navigator.geolocation.watchPosition(p => {
    fix = { lat: p.coords.latitude, lng: p.coords.longitude, acc: Math.round(p.coords.accuracy), at: Date.now() };
    geoError = null;
    if (needPing) sendPing();
    checkBounds();
    render();
  }, e => {
    if (e.code === e.PERMISSION_DENIED) {
      geoError = 'Poloha je zakázaná. Povol ji pro prohlížeč v nastavení telefonu a zkus to znovu.';
      navigator.geolocation.clearWatch(watchId); watchId = null;
    } else if (!fix) geoError = 'Čekám na GPS signál…';
    render();
  }, { enableHighAccuracy: true, maximumAge: 5000, timeout: 20000 });
}
function stopGeo() { if (watchId !== null) navigator.geolocation.clearWatch(watchId); watchId = null; }

function inArea(lat, lng, poly) {
  let inside = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const [ai, bi] = poly[i], [aj, bj] = poly[j];
    if ((bi > lng) !== (bj > lng) && lat < (aj - ai) * (lng - bi) / (bj - bi) + ai) inside = !inside;
  }
  return inside;
}
const hasArea = () => game && game.area && game.area.length >= 3;
const isOut = () => !!(fix && hasArea() && !inArea(fix.lat, fix.lng, game.area));
function checkBounds() {
  const out = isOut() && game.phase === 'play';
  if (out && !wasOut) { buzz([300, 100, 300]); beep(220); }
  wasOut = out;
}
function distM(a, b) {
  const R = 6371000, r = Math.PI / 180, dLat = (b.lat - a.lat) * r, dLng = (b.lng - a.lng) * r;
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(a.lat * r) * Math.cos(b.lat * r) * Math.sin(dLng / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(h));
}

/** Phones send their position only once per pulse: between pulses it is not on the network at all. */
function sendPing() {
  if (caught[session.id]) return;
  const head = { id: session.id, name: session.name, ts: Date.now(), pulse: lastPulse };
  needPing = !fix;
  const msg = fix ? { ...head, gps: true, lat: fix.lat, lng: fix.lng, acc: fix.acc, at: fix.at, out: isOut() } : { ...head, gps: false };
  const prior = players[session.id];
  if (!fix && prior && prior.lat !== undefined) { msg.lat = prior.lat; msg.lng = prior.lng; msg.acc = prior.acc; msg.at = prior.at; }
  players[session.id] = msg;
  publish('p/' + session.id, msg);
}

/* ---------- feedback ---------- */
function buzz(p) { if (navigator.vibrate) navigator.vibrate(p); }
function beep(freq) {
  if (!audio) return;
  const o = audio.createOscillator(), g = audio.createGain();
  o.frequency.value = freq; g.gain.value = .25; o.connect(g); g.connect(audio.destination);
  o.start(); o.stop(audio.currentTime + .18);
}
let toastTimer;
function toast(text) {
  const t = $('toast'); t.textContent = text; t.classList.add('show');
  clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove('show'), 4000);
}
function maybeAlert(m) {
  const me = rosterMe();
  if (!me || me.role !== 'hunter' || !game || game.phase !== 'play') return;
  const r = game.roster.find(x => x.id === m.id);
  if (!r || r.role !== 'hider' || m.lat === undefined || m.pulse <= lastAlertPulse) return;
  lastAlertPulse = m.pulse;
  toast('Nové polohy schovávačů');
  buzz(200); beep(880);
}
async function acquireWake() {
  try { if ('wakeLock' in navigator && !wakeLock && !document.hidden) { wakeLock = await navigator.wakeLock.request('screen'); wakeLock.addEventListener('release', () => { wakeLock = null; }); } } catch (e) { /* battery saver may refuse */ }
}

/* ---------- map ---------- */
let map, areaLayer, meMarker, meCircle, didLocate = false, didFitArea = false;
const pins = {};
function initMap() {
  if (map) return;
  map = L.map('map', { zoomControl: false, attributionControl: true }).setView([49.8, 15.5], 7);
  L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 19, attribution: '© OpenStreetMap' }).addTo(map);
  areaLayer = L.layerGroup().addTo(map);
  map.on('click', e => {
    if (!drawing || !isHost() || game.phase !== 'lobby') return;
    game.area = [...(game.area || []), [+e.latlng.lat.toFixed(6), +e.latlng.lng.toFixed(6)]];
    pushGame();
  });
  new ResizeObserver(() => map.invalidateSize()).observe($('mapwrap'));
}
function drawArea() {
  areaLayer.clearLayers();
  const a = (game && game.area) || [];
  const style = { color: '#ffc53d', weight: 3, fillOpacity: .08 };
  if (a.length >= 3) L.polygon(a, style).addTo(areaLayer);
  else if (a.length === 2) L.polyline(a, style).addTo(areaLayer);
  if (drawing) a.forEach(p => L.circleMarker(p, { radius: 6, color: '#ffc53d', fillOpacity: 1, interactive: false }).addTo(areaLayer));
}
/** Hunters see everyone's pings. Hiders see only fellow hiders, never the hunters. */
function visibleOthers() {
  const me = rosterMe();
  if (!me || game.phase !== 'play') return [];
  return game.roster.filter(r => r.id !== me.id && !caught[r.id] && (me.role === 'hunter' || r.role === 'hider'))
    .map(r => ({ r, p: players[r.id] })).filter(x => x.p && Number.isFinite(x.p.lat) && Number.isFinite(x.p.lng));
}
function drawPins() {
  const seen = new Set();
  const now = Date.now();
  visibleOthers().forEach(({ r, p }) => {
    seen.add(r.id);
    const cls = 'pin ' + r.role + (now - p.at > STALE_MS ? ' old' : '');
    const ll = [p.lat, p.lng];
    if (!pins[r.id]) {
      pins[r.id] = L.marker(ll, { icon: L.divIcon({ className: cls, html: esc(r.name[0].toUpperCase()), iconSize: [34, 34] }), keyboard: false })
        .bindTooltip(esc(r.name), { permanent: true, direction: 'top', offset: [0, -16], className: 'pin-label' }).addTo(map);
      pins[r.id]._cls = cls;
    } else {
      pins[r.id].setLatLng(ll);
      if (pins[r.id]._cls !== cls) { pins[r.id].setIcon(L.divIcon({ className: cls, html: esc(r.name[0].toUpperCase()), iconSize: [34, 34] })); pins[r.id]._cls = cls; }
    }
  });
  Object.keys(pins).forEach(id => { if (!seen.has(id)) { pins[id].remove(); delete pins[id]; } });
  if (fix) {
    const ll = [fix.lat, fix.lng];
    if (!meMarker) {
      meCircle = L.circle(ll, { radius: fix.acc, color: '#2f7bff', weight: 1, fillOpacity: .12, interactive: false }).addTo(map);
      meMarker = L.marker(ll, { icon: L.divIcon({ className: 'me', iconSize: [18, 18] }), interactive: false, keyboard: false }).addTo(map);
    } else { meMarker.setLatLng(ll); meCircle.setLatLng(ll).setRadius(fix.acc); }
    if (!didLocate && !hasArea()) { didLocate = true; map.setView(ll, 15); }
  }
  if (hasArea() && !didFitArea && !drawing) { didFitArea = true; didLocate = true; map.fitBounds(game.area, { padding: [24, 24] }); }
}
function fitAll() {
  const pts = [...visibleOthers().map(x => [x.p.lat, x.p.lng])];
  if (fix) pts.push([fix.lat, fix.lng]);
  if (hasArea()) pts.push(...game.area);
  if (pts.length) map.fitBounds(pts, { padding: [30, 30], maxZoom: 17 });
}

/* ---------- rules ---------- */
function outcome() {
  if (!game || game.phase === 'lobby') return null;
  if (game.phase === 'end') return { title: 'Hra ukončena', text: 'Host hru ukončil.', cls: '' };
  const hiders = game.roster.filter(r => r.role === 'hider');
  if (hiders.length && hiders.every(r => caught[r.id])) return { title: 'Lovci vyhráli', text: 'Všichni schovávači jsou chycení.', cls: 'bad' };
  if (Date.now() >= endAt()) return { title: 'Schovávači vyhráli', text: 'Čas vypršel a někdo zůstal na svobodě.', cls: '' };
  return null;
}

/* ---------- rendering ---------- */
let lastPanel = '';
function setPanel(html) { if (html !== lastPanel) { $('panel').innerHTML = html; lastPanel = html; } }
function view(name) {
  const c = 'view-' + name;
  if (document.body.className !== c) {
    document.body.className = c;
    if (name === 'play') { initMap(); setTimeout(() => map.invalidateSize(), 50); }
  }
}
function netDot() {
  const n = clients.filter(c => c.connected).length;
  return `<span class="dim"><span class="dot ${n ? 'ok' : ''}"></span>${n ? 'online' : 'bez spojení'}</span>`;
}
function ago(at) {
  const s = Math.max(0, (Date.now() - at) / 1000);
  if (s < 10) return 'právě teď';
  if (s < 90) return 'před ' + Math.round(s / 10) * 10 + ' s';
  return 'před ' + Math.round(s / 60) + ' min';
}

function render() {
  if (!session) return view('home');
  const out = outcome();
  if (out) return renderEnd(out);
  view('play');
  if (map) { drawArea(); if (game) drawPins(); }
  renderBanner();
  if (!game) return renderWaiting();
  if (game.phase === 'lobby') return rosterMe() ? renderLobby() : renderNotAdmitted();
  if (!rosterMe()) return renderNotAdmitted();
  renderGame();
}
function renderBanner() {
  const b = $('banner');
  let html = '', bad = false;
  const inGame = game && game.phase === 'play' && rosterMe();
  if (geoError) { html = esc(geoError) + ' <button data-act="retry-geo">Znovu</button>'; bad = true; }
  else if (inGame && isOut() && !caught[session.id]) { html = 'Jsi mimo hranice hry! Vrať se dovnitř.'; bad = true; }
  else if (document.visibilityState === 'visible' && inGame && !wakeLock) html = 'Nezamykej telefon a nech appku otevřenou, jinak se poloha neposílá.';
  b.innerHTML = html;
  b.className = (html ? 'show' : '') + (bad ? ' bad' : '');
}
function renderWaiting() {
  const late = Date.now() - joinedAt > 12000;
  setPanel(`<div class="status"><b>Hledám hru ${esc(prettyCode(session.code))}…</b>${netDot()}</div>
    ${late ? '<p class="warn">Hra se zatím nenašla. Zkontroluj kód, nebo ať je host online.</p>' : ''}
    <div class="btns"><button data-act="leave">Zpět</button></div>`);
}
function renderNotAdmitted() {
  const running = game.phase !== 'lobby';
  const full = game.roster.length >= MAX_PLAYERS;
  setPanel(`<div class="status"><b>${running ? 'Hra už běží bez tebe.' : full ? 'Hra je plná (5/5).' : 'Připojuji…'}</b>${netDot()}</div>
    <div class="btns"><button data-act="leave">Zpět</button></div>`);
}
function renderLobby() {
  const host = isHost();
  const hunters = game.roster.filter(r => r.role === 'hunter').length;
  const hiders = game.roster.length - hunters;
  const ready = hunters === HUNTERS && hiders === HIDERS;
  const points = (game.area || []).length;
  const rows = game.roster.map(r => {
    const p = players[r.id];
    const gps = r.id === session.id ? !!fix : !!(p && p.gps);
    const label = r.role === 'hunter' ? 'Lovec' : 'Schovávač';
    return `<li><div class="who"><b>${esc(r.name)}${r.id === session.id ? ' (ty)' : ''}${r.id === game.host ? ' · host' : ''}</b>
      <span class="dim"><span class="dot ${gps ? 'ok' : ''}"></span>${gps ? 'GPS OK' : 'čeká na GPS'}</span></div>
      ${host ? `<button class="small role ${r.role}" data-act="toggle-role" data-id="${esc(r.id)}">${label}</button>
      ${r.id !== session.id ? `<button class="small" data-act="kick" data-id="${esc(r.id)}" aria-label="Odebrat hráče">✕</button>` : ''}`
      : `<span class="tag ${r.role}">${label}</span>`}</li>`;
  }).join('');
  const areaText = points >= 3 ? "Hranice jsou nastavené" : 'Hranice nejsou nastavené (celý svět)';
  const opt = (v, cur, t) => `<option value="${v}"${v === cur ? ' selected' : ''}>${t}</option>`;
  setPanel(`
    <div class="status"><div><div class="dim">Kód hry</div><div class="codebox">${esc(prettyCode(session.code))}</div></div>${netDot()}</div>
    <div class="btns"><button data-act="share">Poslat pozvánku</button></div>
    <ul class="list">${rows}</ul>
    <p class="dim">${game.roster.length}/${MAX_PLAYERS} hráčů · lovci ${hunters}/${HUNTERS} · schovávači ${hiders}/${HIDERS}</p>
    <p class="dim">${areaText}. Náskok ${game.hideMin} min, hra ${game.durMin} min.</p>
    ${host ? `
      ${drawing ? `<p class="warn">Klepej do mapy a přidávej rohy oblasti (aspoň 3 body).</p>
        <div class="btns"><button class="primary" data-act="draw-done">Hotovo</button><button data-act="area-undo">Zpět bod</button><button data-act="area-clear">Smazat</button></div>`
      : `<div class="btns"><button data-act="draw">${points ? 'Upravit hranice' : 'Nakreslit hranice'}</button><button data-act="shuffle">Náhodné role</button></div>`}
      <div class="settings">
        <div><label for="hide">Náskok</label><select id="hide" data-set="hideMin">${[0, 2, 5, 10, 15].map(v => opt(v, game.hideMin, v ? v + ' min' : 'žádný')).join('')}</select></div>
        <div><label for="dur">Délka hry</label><select id="dur" data-set="durMin">${[15, 30, 45, 60, 90, 120].map(v => opt(v, game.durMin, v + ' min')).join('')}</select></div>
      </div>
      <div class="btns"><button class="primary" data-act="start" ${ready ? '' : 'disabled'}>${ready ? 'Spustit hru' : `Potřeba ${HUNTERS} lovci a ${HIDERS} schovávači`}</button></div>`
    : '<p class="dim">Čekej, až host spustí hru. Nech appku otevřenou.</p>'}
    <div class="btns"><button class="small" data-act="leave">Odejít</button></div>`);
}
function renderGame() {
  const me = rosterMe(), now = Date.now(), hs = huntStart();
  const hunter = me.role === 'hunter', iAmCaught = !!caught[me.id];
  const hiding = now < hs;
  const next = hiding ? hs - now : PULSE_MS - ((now - hs) % PULSE_MS);
  let head, sub;
  if (hiding) {
    head = mmss(hs - now);
    sub = hunter ? 'Schovávači utíkají. Ještě nelov!' : 'Náskok. Uteč a schovej se!';
  } else {
    head = mmss(next);
    sub = iAmCaught ? 'Jsi chycený.' : hunter ? 'do další polohy schovávačů' : 'do dalšího prozrazení tvé polohy';
  }
  const hiders = game.roster.filter(r => r.role === 'hider' && (hunter || r.id !== me.id));
  const rows = hiders.map(r => {
    const p = players[r.id], isC = !!caught[r.id];
    let info = 'zatím bez polohy';
    if (isC) info = 'chycený';
    else if (p && p.at) {
      const stale = now - p.at > STALE_MS;
      const d = fix ? ' · ' + (m => m >= 1000 ? (m / 1000).toFixed(1) + ' km' : Math.round(m / 10) * 10 + ' m')(distM(fix, p)) : '';
      info = `${ago(p.at)}${d}${stale ? ' · <span class="warn">neposílá polohu</span>' : ''}${p.out ? ' · <span class="bad">mimo hranice</span>' : ''}`;
    }
    return `<li class="${isC ? 'caught' : ''}"><div class="who"><b>${esc(r.name)}</b><span class="dim">${info}</span></div>
      ${hunter && !isC && !hiding ? `<button class="small danger" data-act="catch" data-id="${esc(r.id)}">Chycen</button>` : ''}</li>`;
  }).join('');
  setPanel(`
    <div class="status"><span class="tag ${me.role}">${hunter ? 'Lovec' : 'Schovávač'}</span>${netDot()}<span class="dim">konec za <b id="t-end"></b></span></div>
    <div class="big" id="t-main"></div><div class="dim">${sub}</div>
    <ul class="list">${rows}</ul>
    <div class="btns">
      ${!hunter && !iAmCaught && !hiding ? '<button class="danger" data-act="catch-me">Chytili mě</button>' : ''}
      ${isHost() ? '<button class="small" data-act="abort">Ukončit hru</button>' : ''}
    </div>`);
  $('t-main').textContent = head;
  $('t-end').textContent = mmss(endAt() - now);
}
function renderEnd(o) {
  if (!ended) {
    ended = true;
    stopGeo();
    // Nothing about anyone's position should outlive the game on the brokers.
    clearRetained('p/' + session.id);
    if (wakeLock) wakeLock.release().catch(() => {});
    buzz([400, 100, 400]); beep(660);
  }
  view('end');
  const rows = game.roster.map(r => `<li><div class="who"><b>${esc(r.name)}</b></div><span class="tag ${r.role}">${r.role === 'hunter' ? 'Lovec' : caught[r.id] ? 'Chycený' : 'Schovávač'}</span></li>`).join('');
  const html = `<div class="big ${o.cls}">${esc(o.title)}</div><p>${esc(o.text)}</p><ul class="list">${rows}</ul><button class="primary" data-act="leave">Nová hra</button>`;
  if ($('end').innerHTML !== html) $('end').innerHTML = html;
}

/* ---------- actions ---------- */
function randomCode() {
  const r = crypto.getRandomValues(new Uint32Array(8));
  return [...r].map(x => CODE_ALPHABET[x % CODE_ALPHABET.length]).join('');
}
function shuffled(a) {
  const c = [...a];
  for (let i = c.length - 1; i > 0; i--) { const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1); [c[i], c[j]] = [c[j], c[i]]; }
  return c;
}
async function enter(code, name, id, createGame) {
  session = { code, id: id || crypto.randomUUID().replace(/-/g, '').slice(0, 16), name };
  localStorage.setItem(STORE, JSON.stringify(session));
  localStorage.setItem('manhunt.name', name);
  history.replaceState(null, '', '#' + code);
  joinedAt = Date.now();
  await deriveRoom(code);
  if (createGame) {
    game = { v: Date.now(), host: session.id, phase: 'lobby', roster: [{ id: session.id, name, role: 'hunter' }], area: null, hideMin: 5, durMin: 60 };
  }
  view('play');
  connect();
  if (createGame) publish('s', game);
  startGeo();
  acquireWake();
  render();
}
function leave() {
  if (clients.length) clearRetained('p/' + session.id);
  const old = clients;
  setTimeout(() => old.forEach(c => c.end(true)), 400);
  clients = [];
  stopGeo();
  localStorage.removeItem(STORE);
  history.replaceState(null, '', location.pathname);
  location.reload();
}
const actions = {
  create() {
    const name = $('name').value.trim();
    if (!name) return ($('home-err').textContent = 'Napiš svoje jméno.');
    enter(randomCode(), name, null, true);
  },
  join() {
    const name = $('name').value.trim(), code = normCode($('code').value);
    if (!name) return ($('home-err').textContent = 'Napiš svoje jméno.');
    if (code.length !== 8) return ($('home-err').textContent = 'Kód má 8 znaků.');
    enter(code, name, null, false);
  },
  leave() { if (ended || confirm('Opravdu odejít ze hry?')) leave(); },
  async share() {
    const url = location.origin + location.pathname + '#' + session.code;
    if (navigator.share) { try { await navigator.share({ title: 'Manhunt', text: 'Pojď hrát Manhunt, kód ' + prettyCode(session.code), url }); } catch (e) { /* user closed the sheet */ } return; }
    try { await navigator.clipboard.writeText(url); toast('Odkaz zkopírován'); } catch (e) { prompt('Zkopíruj odkaz:', url); }
  },
  'retry-geo'() { geoError = null; stopGeo(); startGeo(); render(); },
  'toggle-role'(el) { const r = game.roster.find(x => x.id === el.dataset.id); if (r) { r.role = r.role === 'hunter' ? 'hider' : 'hunter'; pushGame(); } },
  kick(el) { const id = el.dataset.id; game.roster = game.roster.filter(r => r.id !== id); clearRetained('p/' + id); pushGame(); },
  shuffle() { shuffled(game.roster).forEach((r, i) => { r.role = i < HUNTERS ? 'hunter' : 'hider'; }); pushGame(); },
  draw() { drawing = true; if (fix) map.setView([fix.lat, fix.lng], Math.max(map.getZoom(), 14)); render(); },
  'draw-done'() {
    if ((game.area || []).length < 3) { game.area = null; pushGame(); }
    drawing = false; render();
  },
  'area-undo'() { if (game.area && game.area.length) { game.area = game.area.slice(0, -1); pushGame(); } },
  'area-clear'() { game.area = null; pushGame(); },
  start() {
    if (drawing) { drawing = false; }
    if (game.area && game.area.length < 3) game.area = null;
    didFitArea = false;
    game.phase = 'play'; game.startAt = Date.now() + 2000;
    pushGame(); acquireWake();
  },
  catch(el) {
    const r = game.roster.find(x => x.id === el.dataset.id);
    if (r && confirm(`Opravdu je ${r.name} chycený?`)) markCaught(r.id);
  },
  'catch-me'() { if (confirm('Opravdu tě chytili? Vrátit se to nedá.')) markCaught(session.id); },
  abort() { if (confirm('Ukončit hru pro všechny?')) { game.phase = 'end'; pushGame(); } },
  'fit-me'() { if (fix) map.setView([fix.lat, fix.lng], 17); else toast('Zatím nemám GPS'); },
  'fit-all'() { fitAll(); },
};
function markCaught(id) {
  caught[id] = { by: session.id, ts: Date.now() };
  publish('c/' + id, caught[id]);
  render();
}

document.addEventListener('click', e => {
  if (!audio && (window.AudioContext || window.webkitAudioContext)) { audio = new (window.AudioContext || window.webkitAudioContext)(); audio.resume(); }
  const el = e.target.closest('[data-act]');
  if (el && !el.disabled && actions[el.dataset.act]) actions[el.dataset.act](el);
});
document.addEventListener('change', e => {
  const f = e.target.dataset && e.target.dataset.set;
  if (f && isHost()) { game[f] = +e.target.value; pushGame(); }
});
document.addEventListener('visibilitychange', () => {
  if (document.hidden || !session) return;
  acquireWake();
  clients.forEach(c => { if (!c.connected) c.reconnect(); });
  tick();
});

/* ---------- clock ---------- */
function tick() {
  if (!session) return;
  tickCount++;
  if (game && game.phase === 'lobby' && tickCount % 5 === 0) {
    announce();
    if (isHost()) publish('s', game);
  }
  if (game && game.phase === 'play' && rosterMe() && !outcome()) {
    const now = Date.now();
    if (now >= huntStart()) {
      const pulse = Math.floor((now - huntStart()) / PULSE_MS);
      if (pulse > lastPulse) {
        lastPulse = pulse;
        sendPing();
        publish('s', game); // any phone can restore the setup if a broker lost it
      }
    }
  }
  render();
}

/* ---------- boot ---------- */
(function boot() {
  $('name').value = localStorage.getItem('manhunt.name') || '';
  const hashCode = normCode(location.hash.slice(1));
  let saved = null;
  try { saved = JSON.parse(localStorage.getItem(STORE)); } catch (e) { /* corrupt store means fresh start */ }
  setInterval(tick, 1000);
  if (saved && saved.code && (!hashCode || hashCode === saved.code)) return enter(saved.code, saved.name, saved.id, false);
  if (hashCode) $('code').value = prettyCode(hashCode);
  view('home');
})();
