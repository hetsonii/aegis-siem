'use strict';
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
let CART = [];

async function api(path, opts) {
  const r = await fetch(path, opts);
  return r.json().catch(() => ({}));
}

function card(p) {
  return `<div class="card" data-id="${p.id}">
    <div class="emoji">${esc(p.emoji || '🧃')}</div>
    <div class="tag">${esc(p.tag || '')}</div>
    <h3>${esc(p.name)}</h3>
    <div class="row"><span class="price">$${esc(Number(p.price).toFixed(2))}</span>
      <button class="add" data-add="${p.id}">Add</button></div>
  </div>`;
}

async function loadGrid(list, title) {
  $('grid-title').textContent = title || 'Our juices';
  const data = list || (await api('/api/products')).products || [];
  $('grid').innerHTML = data.length ? data.map(card).join('')
    : '<p>No juices matched your search.</p>';
}

async function search() {
  const q = $('q').value.trim();
  if (!q) return loadGrid();
  const r = await api('/api/products/search?q=' + encodeURIComponent(q));
  loadGrid(r.results || [], `Results for “${q}”`);
}

async function openProduct(id) {
  const p = await api('/api/products/' + id);
  if (p.error) return;
  const rev = await api('/api/reviews?product=' + id);
  $('modal-body').innerHTML = `
    <div class="big">${esc(p.emoji)}</div>
    <h2>${esc(p.name)}</h2>
    <p>${esc(p.desc)}</p>
    <div class="row"><span class="price" style="font-size:22px">$${esc(Number(p.price).toFixed(2))}</span>
      <button class="primary" style="width:auto" data-add="${p.id}">Add to basket</button></div>
    <div class="reviews">
      <h4>Reviews</h4>
      <div id="rev-list">${(rev.reviews || []).map((r) =>
        `<div class="review"><b>${esc(r.author)}</b>: ${esc(r.text)}</div>`).join('') || '<p>No reviews yet.</p>'}</div>
      <input id="rev-author" placeholder="Your name">
      <textarea id="rev-text" placeholder="Leave a review…"></textarea>
      <button class="primary" id="rev-submit">Post review</button>
    </div>`;
  $('modal').classList.remove('hidden');
  $('rev-submit').onclick = async () => {
    await api('/api/reviews', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ product: id, author: $('rev-author').value, text: $('rev-text').value }) });
    openProduct(id);
  };
}

function addToCart(id) {
  CART.push(id);
  $('cart-count').textContent = CART.length;
}
async function openCart() {
  const products = (await api('/api/products')).products || [];
  const byId = Object.fromEntries(products.map((p) => [String(p.id), p]));
  let total = 0;
  $('cart-items').innerHTML = CART.map((id) => {
    const p = byId[String(id)]; if (!p) return '';
    total += Number(p.price);
    return `<li><span>${esc(p.emoji)} ${esc(p.name)}</span><span>$${esc(Number(p.price).toFixed(2))}</span></li>`;
  }).join('') || '<li>Your basket is empty.</li>';
  $('cart-total').textContent = total.toFixed(2);
  $('cart').classList.remove('hidden');
}

let authMode = 'login';
function openAuth(mode) {
  authMode = mode;
  $('auth-title').textContent = mode === 'login' ? 'Sign in' : 'Create account';
  $('auth-submit').textContent = mode === 'login' ? 'Sign in' : 'Register';
  $('auth-msg').textContent = '';
  $('auth').classList.remove('hidden');
}
async function submitAuth() {
  const email = $('auth-email').value, password = $('auth-pass').value;
  const url = authMode === 'login' ? '/api/login' : '/api/register';
  const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }) });
  $('auth-msg').textContent = r.ok && authMode === 'register'
    ? 'Account created (demo).' : 'Invalid credentials.';
}

// events
document.addEventListener('click', (e) => {
  const addId = e.target.getAttribute && e.target.getAttribute('data-add');
  if (addId) { addToCart(addId); e.stopPropagation(); return; }
  const cardEl = e.target.closest && e.target.closest('.card');
  if (cardEl) openProduct(cardEl.getAttribute('data-id'));
});
$('go').onclick = search;
$('q').addEventListener('keydown', (e) => { if (e.key === 'Enter') search(); });
$('nav-shop').onclick = (e) => { e.preventDefault(); $('q').value = ''; loadGrid(); };
$('nav-admin').onclick = (e) => { e.preventDefault(); fetch('/admin').then(() => alert('403 — admins only.')); };
$('nav-login').onclick = () => openAuth('login');
$('nav-cart').onclick = openCart;
$('auth-switch').onclick = (e) => { e.preventDefault(); openAuth(authMode === 'login' ? 'register' : 'login'); };
$('auth-submit').onclick = submitAuth;
$('checkout').onclick = () => { $('auth-msg') && null; alert('Checkout is disabled in this demo.'); };
$('modal-x').onclick = () => $('modal').classList.add('hidden');
$('auth-x').onclick = () => $('auth').classList.add('hidden');
$('cart-x').onclick = () => $('cart').classList.add('hidden');
[$('modal'), $('auth'), $('cart')].forEach((m) =>
  m.addEventListener('click', (e) => { if (e.target === m) m.classList.add('hidden'); }));

loadGrid();
