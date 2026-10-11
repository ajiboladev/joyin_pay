import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
import { getAuth, createUserWithEmailAndPassword, signInWithEmailAndPassword, signOut, onAuthStateChanged }
  from "https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js";
import { getFirestore, doc, collection, runTransaction, getDoc, getDocs, onSnapshot, query, orderBy, limit,
  startAfter, increment, serverTimestamp } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js";
import { firebaseConfig } from "./firebase-config.js";

const app = initializeApp(firebaseConfig), auth = getAuth(app), db = getFirestore(app);
const $ = id => document.getElementById(id);
const S = { user: null, profile: null, wallet: null, unsub: null, target: null, hidden: false, last: null, busy: false };
let signingUp = false;

/* ---------- UI helpers ---------- */
const ic = n => `<svg class="i"><use href="#i-${n}"/></svg>`;
const loader = (t) => { $("loader").classList.toggle("show", !!t); if (t) $("loaderText").textContent = t; };
function toast(text, type = "in") {
  const d = document.createElement("div"); d.className = "toast " + type;
  d.innerHTML = ic(type === "er" ? "alert" : type === "ok" ? "check" : "alert"); d.append(text);
  $("toasts").append(d); setTimeout(() => d.remove(), 4200);
}
const msg = (id, text = "", type = "er") => { const e = $(id); e.className = "msg" + (text ? " " + type : ""); e.textContent = text; };
function busy(btn, on, label) {
  if (on) { btn.dataset.l = btn.textContent; btn.textContent = label; } else btn.textContent = btn.dataset.l || btn.textContent;
  btn.disabled = on; btn.classList.toggle("busy", on); S.busy = on;
}
const openM = id => $(id).classList.add("open"), closeM = id => $(id).classList.remove("open");
const naira = k => "\u20A6" + (k / 100).toLocaleString("en-NG", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const toKobo = s => { s = String(s).trim().replace(/,/g, ""); if (!/^\d+(\.\d{1,2})?$/.test(s)) return null;
  const [a, b = ""] = s.split("."); const k = Number(a) * 100 + Number(b.padEnd(2, "0")); return Number.isSafeInteger(k) ? k : null; };

/* ---------- errors: never expose provider names ---------- */
class AppErr extends Error {}
const E = {
  "auth/invalid-email": "That email address doesn't look right.",
  "auth/user-not-found": "No account found with this email.",
  "auth/wrong-password": "Incorrect email or password.",
  "auth/invalid-credential": "Incorrect email or password.",
  "auth/email-already-in-use": "An account with this email already exists. Try logging in.",
  "auth/weak-password": "Password is too weak. Use at least 8 characters with letters and numbers.",
  "auth/too-many-requests": "Too many attempts. Please wait a few minutes and try again.",
  "auth/network-request-failed": "No internet connection. Check your network and try again.",
  "auth/user-disabled": "This account has been disabled. Contact support.",
  "auth/operation-not-allowed": "Sign-in is currently unavailable. Please try again later.",
  "permission-denied": "This action isn't allowed. Please log in again and retry.",
  "unavailable": "Service is temporarily unavailable. Please try again shortly.",
  "deadline-exceeded": "The request took too long. Please try again.",
  "aborted": "Too many people are using this right now. Please try again.",
  "failed-precondition": "The service isn't ready yet. Please try again later.",
  "not-found": "Some account details could not be found."
};
const errMsg = e => e instanceof AppErr ? e.message : (E[e?.code] || E[(e?.code || "").replace("firestore/", "")] || "Something went wrong. Please try again.");
const fail = t => { throw new AppErr(t); };

/* ---------- validation ---------- */
const V = {
  name: v => /^[\p{L}][\p{L}\s'.-]{1,59}$/u.test(v.trim()) || "Enter your full name.",
  email: v => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v.trim()) || "Enter a valid email address.",
  phone: v => /^\+?\d{10,14}$/.test(v.replace(/[\s-]/g, "")) || "Enter a valid phone number.",
  pass: v => (v.length >= 8 && /[A-Za-z]/.test(v) && /\d/.test(v)) || "Password needs 8+ characters with letters and numbers.",
  pin: v => /^\d{4}$/.test(v) || "PIN must be exactly 4 digits."
};
const check = (...rules) => { for (const [fn, val] of rules) { const r = V[fn](val); if (r !== true) return r; } return null; };

/* ---------- PIN hashing (PBKDF2) ---------- */
async function hashPin(pin, salt) {
  const k = await crypto.subtle.importKey("raw", new TextEncoder().encode(pin), "PBKDF2", false, ["deriveBits"]);
  const b = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: new TextEncoder().encode(salt), iterations: 150000, hash: "SHA-256" }, k, 256);
  return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("");
}
const genNo = () => { const a = new Uint32Array(2); crypto.getRandomValues(a); return "30" + String((a[0] * 4294967296 + a[1]) % 1e8).padStart(8, "0"); };

/* ---------- provisioning: one atomic transaction creates profile, unique account number, wallet ---------- */
async function provision(u, { name, phone, pin }) {
  const salt = crypto.randomUUID(), pinHash = await hashPin(pin, salt);
  const uref = doc(db, "users", u.uid), wref = doc(db, "users", u.uid, "private", "wallet");
  for (let i = 0; i < 10; i++) {
    const no = genNo();
    const ok = await runTransaction(db, async t => {
      const us = await t.get(uref), ws = await t.get(wref);
      let acct;
      if (us.exists()) acct = us.data().accountNumber;
      else {
        acct = no; const nref = doc(db, "accountNumbers", acct);
        if ((await t.get(nref)).exists()) return false;            // number taken -> retry with a new one
        t.set(nref, { uid: u.uid, name: name.trim() });
        t.set(uref, { fullName: name.trim(), email: u.email, phone: phone.replace(/[\s-]/g, ""), accountNumber: acct, createdAt: serverTimestamp() });
      }
      if (!ws.exists()) t.set(wref, { balance: 0, pinHash, salt });
      return true;
    });
    if (ok) return;
  }
  fail("We couldn't generate your account number. Please try again.");
}

/* ---------- session ---------- */
async function enter(u) {
  loader("Setting up your account...");
  try {
    const [us, ws] = await Promise.all([getDoc(doc(db, "users", u.uid)), getDoc(doc(db, "users", u.uid, "private", "wallet"))]);
    S.user = u;
    if (us.exists() && ws.exists()) { S.profile = us.data(); startDash(u); }
    else { $("cName").value = us.exists() ? us.data().fullName : ""; $("cPhone").value = us.exists() ? us.data().phone : "";
      $("authView").classList.add("hide"); $("dashView").classList.add("hide"); openM("mComplete"); }
  } catch (e) { toast(errMsg(e), "er"); await signOut(auth); }
  loader(false);
}
function startDash(u) {
  closeM("mComplete"); $("authView").classList.add("hide"); $("dashView").classList.remove("hide");
  $("hi").textContent = `Hi, ${S.profile.fullName.split(" ")[0]} \u{1F44B}`;
  $("acctNo").textContent = S.profile.accountNumber;
  S.unsub?.();
  S.unsub = onSnapshot(doc(db, "users", u.uid, "private", "wallet"), s => { S.wallet = s.data(); renderBal(); },
    e => toast(errMsg(e), "er"));
}
const renderBal = () => { $("balance").textContent = S.hidden ? "\u20A6 ****" : naira(S.wallet?.balance ?? 0);
  $("balEye").innerHTML = ic(S.hidden ? "eyeoff" : "eye"); };

onAuthStateChanged(auth, u => {
  if (signingUp) return;
  if (u) enter(u);
  else { S.unsub?.(); S.user = S.profile = S.wallet = null; closeM("mComplete");
    $("dashView").classList.add("hide"); $("authView").classList.remove("hide"); loader(false); }
});

/* ---------- auth forms ---------- */
const tab = l => { $("loginForm").classList.toggle("hide", !l); $("signupForm").classList.toggle("hide", l);
  $("tabLogin").classList.toggle("on", l); $("tabSignup").classList.toggle("on", !l); };
$("tabLogin").onclick = () => tab(true); $("tabSignup").onclick = () => tab(false);
document.querySelectorAll("[data-eye]").forEach(b => b.onclick = () => { const i = $(b.dataset.eye); const s = i.type === "password";
  i.type = s ? "text" : "password"; b.innerHTML = ic(s ? "eyeoff" : "eye"); });
["sPin", "sPin2", "cPin", "cPin2", "tPin", "tAcct"].forEach(id => $(id).addEventListener("input", e => e.target.value = e.target.value.replace(/\D/g, "")));

$("loginForm").onsubmit = async e => {
  e.preventDefault(); if (S.busy) return; msg("lMsg");
  const email = $("lEmail").value.trim(), pass = $("lPass").value;
  const bad = check(["email", email]) || (pass ? null : "Enter your password.");
  if (bad) return msg("lMsg", bad);
  busy($("lBtn"), true, "Logging in...");
  try { await signInWithEmailAndPassword(auth, email, pass); toast("Login successful.", "ok"); }
  catch (x) { msg("lMsg", errMsg(x)); }
  busy($("lBtn"), false);
};

$("signupForm").onsubmit = async e => {
  e.preventDefault(); if (S.busy) return; msg("sMsg");
  const d = { name: $("sName").value, phone: $("sPhone").value, pin: $("sPin").value }, email = $("sEmail").value.trim(), pass = $("sPass").value;
  const bad = check(["name", d.name], ["email", email], ["phone", d.phone], ["pass", pass], ["pin", d.pin]) || (d.pin !== $("sPin2").value ? "PINs do not match." : null);
  if (bad) return msg("sMsg", bad);
  busy($("sBtn"), true, "Creating account..."); signingUp = true; let user = null;
  try {
    user = (await createUserWithEmailAndPassword(auth, email, pass)).user;
    msg("sMsg", "Account created. Generating your account number...", "in");
    await provision(user, d); toast("Account created successfully.", "ok");
  } catch (x) { msg("sMsg", errMsg(x)); if (user) toast("Account created, but setup is unfinished. Please complete it next.", "in"); }
  signingUp = false; busy($("sBtn"), false); if (user) enter(user);
};

$("cForm").onsubmit = async e => {
  e.preventDefault(); if (S.busy) return; msg("cMsg");
  const d = { name: $("cName").value, phone: $("cPhone").value, pin: $("cPin").value };
  const bad = check(["name", d.name], ["phone", d.phone], ["pin", d.pin]) || (d.pin !== $("cPin2").value ? "PINs do not match." : null);
  if (bad) return msg("cMsg", bad);
  busy($("cBtn"), true, "Saving...");
  try { await provision(S.user, d); toast("Account setup complete.", "ok"); closeM("mComplete"); busy($("cBtn"), false); await enter(S.user); return; }
  catch (x) { msg("cMsg", errMsg(x)); }
  busy($("cBtn"), false);
};
const logout = async () => { try { await signOut(auth); toast("You have been logged out.", "in"); } catch (x) { toast(errMsg(x), "er"); } };
$("logoutBtn").onclick = logout; $("cOut").onclick = logout;

/* ---------- dashboard ---------- */
$("balEye").onclick = () => { S.hidden = !S.hidden; renderBal(); };
$("copyAcct").onclick = async () => { try { await navigator.clipboard.writeText(S.profile.accountNumber); }
  catch { const t = document.createElement("textarea"); t.value = S.profile.accountNumber; document.body.append(t); t.select(); document.execCommand("copy"); t.remove(); }
  $("copyAcct").innerHTML = ic("check"); toast("Account number copied.", "ok"); setTimeout(() => $("copyAcct").innerHTML = ic("copy"), 1500); };
document.querySelectorAll("[data-close]").forEach(b => b.onclick = () => closeM(b.dataset.close));
["mTransfer", "mHistory"].forEach(id => $(id).addEventListener("mousedown", e => { if (e.target.id === id && !S.busy) closeM(id); }));

/* ---------- transfer ---------- */
const step = n => ["t1", "t2", "t3", "t4"].forEach((s, i) => $(s).classList.toggle("hide", i + 1 !== n));
$("openTransfer").onclick = () => { S.target = null; ["tAcct", "tAmt", "tPin"].forEach(i => $(i).value = ""); ["t1Msg", "t2Msg", "t3Msg"].forEach(m => msg(m)); step(1); openM("mTransfer"); $("tAcct").focus(); };

async function search() {
  if (S.busy) return; msg("t1Msg"); const no = $("tAcct").value.trim();
  if (!/^\d{10}$/.test(no)) return msg("t1Msg", "Enter a valid 10-digit account number.");
  if (no === S.profile.accountNumber) return msg("t1Msg", "You can't send money to yourself.");
  busy($("tSearch"), true, "Searching...");
  try {
    const s = await getDoc(doc(db, "accountNumbers", no));
    if (!s.exists()) msg("t1Msg", "Account not found. Check the number and try again.");
    else if (s.data().uid === S.user.uid) msg("t1Msg", "You can't send money to yourself.");
    else { S.target = { no, uid: s.data().uid, name: s.data().name };
      $("tName").textContent = S.target.name; $("tNo").textContent = no; $("tAv").textContent = S.target.name[0].toUpperCase();
      $("tAvail").textContent = "Available balance: " + naira(S.wallet?.balance ?? 0); msg("t2Msg"); step(2); $("tAmt").focus(); }
  } catch (x) { msg("t1Msg", errMsg(x)); }
  busy($("tSearch"), false);
}
$("tSearch").onclick = search; $("tAcct").addEventListener("keydown", e => { if (e.key === "Enter") search(); });
$("tBack").onclick = () => step(1); $("tBack2").onclick = () => step(2);
$("tNext").onclick = () => {
  const k = toKobo($("tAmt").value);
  if (k === null || k <= 0) return msg("t2Msg", "Enter a valid amount (up to 2 decimal places).");
  if (k < 100) return msg("t2Msg", "Minimum transfer is \u20A61.00.");
  if (k > (S.wallet?.balance ?? 0)) return msg("t2Msg", "Insufficient balance. You have " + naira(S.wallet?.balance ?? 0) + ".");
  S.amt = k; $("tSum").textContent = `Send ${naira(k)} to ${S.target.name} (${S.target.no}). Enter your PIN to confirm.`; msg("t3Msg"); step(3); $("tPin").focus();
};

const lock = () => JSON.parse(localStorage.getItem("jp_l") || '{"n":0,"t":0}');
async function send() {
  if (S.busy) return; msg("t3Msg"); const pin = $("tPin").value, L = lock();
  if (L.t > Date.now()) return msg("t3Msg", `Too many wrong PINs. Try again in ${Math.ceil((L.t - Date.now()) / 60000)} minute(s).`);
  if (!/^\d{4}$/.test(pin)) return msg("t3Msg", "Enter your 4-digit PIN.");
  busy($("tSend"), true, "Sending..."); $("tBack2").disabled = true;
  const T = S.target, amt = S.amt, me = S.user.uid, tref = doc(collection(db, "transfers"));
  const wref = doc(db, "users", me, "private", "wallet");
  try {
    await runTransaction(db, async t => {
      const ws = await t.get(wref); if (!ws.exists()) fail("Your wallet could not be found.");
      const w = ws.data();
      if (await hashPin(pin, w.salt) !== w.pinHash) fail("Incorrect PIN.");
      if (!Number.isSafeInteger(w.balance) || w.balance < amt) fail("Insufficient balance.");
      t.set(tref, { from: me, to: T.uid, amount: amt, fromName: S.profile.fullName, toName: T.name, fromAcct: S.profile.accountNumber, toAcct: T.no, createdAt: serverTimestamp() });
      t.update(wref, { balance: w.balance - amt, lastTx: tref.id });
      t.update(doc(db, "users", T.uid, "private", "wallet"), { balance: increment(amt), lastTx: tref.id });
      t.set(doc(db, "users", me, "history", tref.id), { type: "debit", amount: amt, name: T.name, acct: T.no, createdAt: serverTimestamp() });
      t.set(doc(db, "users", T.uid, "history", tref.id), { type: "credit", amount: amt, name: S.profile.fullName, acct: S.profile.accountNumber, createdAt: serverTimestamp() });
    });
    localStorage.removeItem("jp_l"); $("tDone").textContent = `${naira(amt)} was sent to ${T.name}.`; step(4); S.last = null;
  } catch (x) {
    if (x instanceof AppErr && x.message === "Incorrect PIN.") { const n = L.n + 1;
      localStorage.setItem("jp_l", JSON.stringify(n >= 5 ? { n: 0, t: Date.now() + 300000 } : { n, t: 0 }));
      msg("t3Msg", n >= 5 ? "Too many wrong PINs. Transfers are locked for 5 minutes." : `Incorrect PIN. ${5 - n} attempt(s) left.`);
    } else msg("t3Msg", errMsg(x) + " No money was moved.");
  }
  busy($("tSend"), false); $("tBack2").disabled = false;
}
$("tSend").onclick = send; $("tPin").addEventListener("keydown", e => { if (e.key === "Enter") send(); });

/* ---------- history (50 per batch) ---------- */
const PAGE = 50; let hCur = null;
async function loadHistory(more) {
  const btn = $("hMore"); if (S.busy) return;
  if (!more) { hCur = null; $("hList").innerHTML = `<div class="empty">Loading transactions...</div>`; btn.classList.add("hide"); }
  else busy(btn, true, "Loading...");
  try {
    const q = query(collection(db, "users", S.user.uid, "history"), orderBy("createdAt", "desc"), ...(hCur ? [startAfter(hCur)] : []), limit(PAGE));
    const s = await getDocs(q), box = $("hList"); if (!more) box.innerHTML = "";
    if (!more && s.empty) box.innerHTML = `<div class="empty">No transactions yet. Your transfers will show up here.</div>`;
    s.forEach(d => { const h = d.data(), cr = h.type === "credit", r = document.createElement("div"); r.className = "hi-row " + (cr ? "cr" : "dr");
      const dt = h.createdAt?.toDate?.().toLocaleString("en-NG", { dateStyle: "medium", timeStyle: "short" }) || "Just now";
      r.innerHTML = `<span class="hi-ic">${ic(cr ? "down" : "up")}</span><div class="hi-m"><b></b><small></small></div><span class="hi-a"></span>`;
      r.querySelector("b").textContent = (cr ? "From " : "To ") + h.name; r.querySelector("small").textContent = `${h.acct} \u2022 ${dt}`;
      r.querySelector(".hi-a").textContent = (cr ? "+" : "-") + naira(h.amount); box.append(r); });
    hCur = s.docs[s.docs.length - 1] || hCur; btn.classList.toggle("hide", s.size < PAGE);
  } catch (x) { toast(errMsg(x), "er"); if (!more) $("hList").innerHTML = `<div class="empty">Couldn't load history. Close and try again.</div>`; }
  if (more) busy(btn, false);
}
$("openHistory").onclick = () => { openM("mHistory"); loadHistory(false); };
$("hMore").onclick = () => loadHistory(true);
document.addEventListener("keydown", e => e.key === "Escape" && !S.busy && ["mTransfer", "mHistory"].forEach(closeM));