'use strict';

/* ════════════════════════════════════════════════════════════════
   validation.js — loaded by login.ejs and register.ejs
   CSP-safe: no inline handlers, no eval.
   ════════════════════════════════════════════════════════════════ */

/* ── Visual state helpers ────────────────────────────────────── */
function markOk(input, errorEl) {
  input.classList.remove('field-error');
  input.classList.add('field-valid');
  if (errorEl) { errorEl.textContent = ''; errorEl.classList.add('hidden'); }
}

function markBad(input, errorEl, msg) {
  input.classList.remove('field-valid');
  input.classList.add('field-error');
  if (errorEl) { errorEl.textContent = msg; errorEl.classList.remove('hidden'); }
}

/* ── Button enable / disable ─────────────────────────────────── */
// Fields register themselves; updateBtn() re-checks all silently.
const registeredFields = [];

function updateBtn(btn) {
  if (!btn) return;
  const allOk = registeredFields.every(({ input, validateFn }) => !validateFn(input.value));
  btn.disabled = !allOk;
}

/* ── Password show/hide toggle ───────────────────────────────── */
document.querySelectorAll('[data-pw-toggle]').forEach((btn) => {
  btn.addEventListener('click', () => {
    const input = document.getElementById(btn.getAttribute('data-pw-toggle'));
    if (!input) return;
    const revealing = input.type === 'password';
    input.type = revealing ? 'text' : 'password';
    btn.setAttribute('aria-label', revealing ? 'Hide password' : 'Show password');
    btn.querySelector('.eye-open') ?.classList.toggle('hidden', revealing);
    btn.querySelector('.eye-closed')?.classList.toggle('hidden', !revealing);
  });
});

/* ── Password strength meter ─────────────────────────────────── */
const STRENGTH_LEVELS = [
  { label: 'Weak',   cls: 'text-red-500',     barCls: 'bg-red-400',    segs: 1 },
  { label: 'Fair',   cls: 'text-amber-500',   barCls: 'bg-amber-400',  segs: 2 },
  { label: 'Good',   cls: 'text-blue-500',    barCls: 'bg-blue-400',   segs: 3 },
  { label: 'Strong', cls: 'text-emerald-600', barCls: 'bg-emerald-500',segs: 4 },
];

function passwordScore(val) {
  let s = 0;
  if (val.length >= 8)           s++;
  if (val.length >= 12)          s++;
  if (/[A-Z]/.test(val))         s++;
  if (/[0-9]/.test(val))         s++;
  if (/[^A-Za-z0-9]/.test(val)) s++;
  return Math.min(3, Math.floor(s * 4 / 5));
}

function updateStrengthMeter(val) {
  const meter = document.getElementById('strength-meter');
  if (!meter) return;
  if (!val) { meter.classList.add('hidden'); return; }
  meter.classList.remove('hidden');

  const level = STRENGTH_LEVELS[passwordScore(val)];
  ['seg-1', 'seg-2', 'seg-3', 'seg-4'].forEach((id, i) => {
    const seg = document.getElementById(id);
    if (!seg) return;
    seg.className = 'h-1.5 flex-1 rounded-full transition-colors duration-300';
    seg.classList.add(i < level.segs ? level.barCls : 'bg-gray-200');
  });

  const lbl = document.getElementById('strength-label');
  if (!lbl) return;
  lbl.className = 'text-xs font-medium mt-0.5 ' + level.cls;
  lbl.textContent = level.label;
}

/* ── Validators ──────────────────────────────────────────────── */
function vIdentifier(val) {
  if (!val.trim()) return 'Email or username is required.';
  const isEmail    = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val.trim());
  const isUsername = /^[a-zA-Z0-9_]{3,30}$/.test(val.trim());
  if (!isEmail && !isUsername) {
    return 'Enter a valid email address or username (letters, numbers, underscores).';
  }
  return null;
}
function vEmail(val) {
  if (!val.trim())                               return 'Email is required.';
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val))  return 'Enter a valid email address.';
  return null;
}
function vPassword(val) {
  if (!val)           return 'Password is required.';
  if (val.length < 8) return 'Must be at least 8 characters.';
  return null;
}
function vUsername(val) {
  if (!val.trim())                    return 'Username is required.';
  if (val.length < 3)                 return 'Must be at least 3 characters.';
  if (val.length > 30)                return 'Cannot exceed 30 characters.';
  if (!/^[a-zA-Z0-9_]+$/.test(val))  return 'Letters, numbers, and underscores only.';
  return null;
}
function vConfirm(val) {
  const pw = document.getElementById('password');
  if (!val)             return 'Please confirm your password.';
  if (val !== pw.value) return 'Passwords do not match.';
  return null;
}

/* ── Wire a single field ─────────────────────────────────────── */
function wireField(id, errorId, validateFn, btn, onInputExtra) {
  const input   = document.getElementById(id);
  const errorEl = document.getElementById(errorId);
  if (!input) return null;

  // Register for silent button-state checks
  registeredFields.push({ input, validateFn });

  let touched = false;

  function run() {
    const msg = validateFn(input.value);
    msg ? markBad(input, errorEl, msg) : markOk(input, errorEl);
    return !msg;
  }

  input.addEventListener('blur', () => {
    touched = true;
    run();
    updateBtn(btn);
  });

  input.addEventListener('input', () => {
    if (onInputExtra) onInputExtra(input.value);
    if (touched) run();
    updateBtn(btn);
  });

  return { input, errorEl, run };
}

/* ════════════════════════════════════════════════════════════════
   LOGIN FORM
   ════════════════════════════════════════════════════════════════ */
(function initLogin() {
  const form = document.getElementById('loginForm');
  if (!form) return;

  const btn = form.querySelector('[type="submit"]');

  const fields = [
    wireField('identifier', 'identifier-error', vIdentifier, btn),
    wireField('password',   'password-error',   vPassword,   btn),
  ].filter(Boolean);

  // If the server pre-marked a field (wrong password / bad email),
  // the input already has field-error class from EJS — just run a
  // silent button check so the button reflects the actual state.
  updateBtn(btn);

  form.addEventListener('submit', (e) => {
    const ok = fields.map((f) => f.run()).every(Boolean);
    updateBtn(btn);
    if (!ok) e.preventDefault();
  });
}());

/* ════════════════════════════════════════════════════════════════
   REGISTER FORM
   ════════════════════════════════════════════════════════════════ */
(function initRegister() {
  const form = document.getElementById('registerForm');
  if (!form) return;

  const btn = form.querySelector('[type="submit"]');

  const confirmField  = wireField('confirmPassword', 'confirm-error',  vConfirm,  btn);
  const passwordField = wireField('password',        'password-error', vPassword, btn, (val) => {
    updateStrengthMeter(val);
    // Keep confirm in sync if already touched
    if (confirmField) {
      const ci = confirmField.input;
      if (ci.classList.contains('field-valid') || ci.classList.contains('field-error')) {
        confirmField.run();
      }
    }
  });

  const fields = [
    wireField('username', 'username-error', vUsername, btn),
    wireField('email',    'email-error',    vEmail,    btn),
    passwordField,
    confirmField,
  ].filter(Boolean);

  updateBtn(btn);

  form.addEventListener('submit', (e) => {
    const ok = fields.map((f) => f.run()).every(Boolean);
    updateBtn(btn);
    if (!ok) e.preventDefault();
  });
}());
