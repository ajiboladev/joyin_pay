// PRF support test. Runs 100% in the browser. Nothing is uploaded.
// A throwaway passkey is created for this page only, then asked the "magic question" (the salt).

const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();

const toHex = (buf) =>
  [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

async function shortHash(buf) {
  // We never show the real secret, only a short fingerprint of it.
  const h = await crypto.subtle.digest("SHA-256", buf);
  return toHex(h).slice(0, 12);
}

function addRow(list, kind, text, detail) {
  const li = document.createElement("li");
  li.className = "row " + kind;
  const dot = document.createElement("span");
  dot.className = "dot";
  const body = document.createElement("span");
  body.textContent = text;
  if (detail) {
    const s = document.createElement("small");
    s.textContent = detail;
    body.appendChild(s);
  }
  li.append(dot, body);
  list.appendChild(li);
  return li;
}

function describePlatform() {
  const ua = navigator.userAgent;
  const m = ua.match(/\(([^)]+)\)/);
  const browser =
    (ua.match(/(Edg|OPR|SamsungBrowser|Firefox|Chrome|Version)\/[\d.]+/) || ["unknown"])[0];
  return { device: m ? m[1] : "unknown", browser };
}

// ---- Environment checks (no prompts) ----
async function checkEnvironment() {
  const list = $("env");
  list.innerHTML = "";
  const info = describePlatform();
  addRow(list, "info", "Browser: " + info.browser, info.device);

  const secure = window.isSecureContext;
  addRow(list, secure ? "ok" : "fail", secure ? "Secure page (HTTPS)" : "Page is not HTTPS, test cannot run");

  const hasWA = !!(window.PublicKeyCredential && navigator.credentials);
  addRow(list, hasWA ? "ok" : "fail", hasWA ? "Passkeys supported by this browser" : "This browser has no passkey support");

  let platformAuth = false;
  if (hasWA && PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
    try { platformAuth = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(); } catch (_) {}
  }
  addRow(
    list,
    platformAuth ? "ok" : "fail",
    platformAuth ? "Screen lock (fingerprint, face, or PIN) is ready" : "No usable screen lock found",
    platformAuth ? "" : "Turn on a fingerprint, face unlock, or PIN in phone settings."
  );

  // Newer browsers can report PRF support up front.
  let capability = "unknown";
  if (hasWA && PublicKeyCredential.getClientCapabilities) {
    try {
      const caps = await PublicKeyCredential.getClientCapabilities();
      if ("extension:prf" in caps) capability = caps["extension:prf"] ? "yes" : "no";
    } catch (_) {}
  }
  addRow(
    list,
    capability === "yes" ? "ok" : capability === "no" ? "fail" : "warn",
    "Browser says PRF is supported: " + capability,
    capability === "unknown" ? "This browser cannot say in advance. The real test below decides." : ""
  );

  return { info, secure, hasWA, platformAuth, capability };
}

// ---- The real test ----
async function runTest(env) {
  const steps = $("steps");
  steps.innerHTML = "";
  const result = { created: false, enabled: false, got: false, stable: false, saltsDiffer: false, error: "" };

  // The salt is the "question". It is fixed in code and it is NOT secret.
  const salt1 = enc.encode("lcu-attendance-test-question-1");
  const salt2 = enc.encode("lcu-attendance-test-question-2");

  try {
    // Step 1: create a throwaway passkey
    addRow(steps, "info", "Step 1 of 3: creating a test passkey. Use your fingerprint, face, or PIN.");
    const cred = await navigator.credentials.create({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { name: "PRF Test" },
        user: {
          id: crypto.getRandomValues(new Uint8Array(16)),
          name: "prf-test",
          displayName: "PRF Test",
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 },
        ],
        authenticatorSelection: {
          authenticatorAttachment: "platform",
          residentKey: "preferred",
          userVerification: "required",
        },
        attestation: "none",
        timeout: 60000,
        extensions: { prf: {} },
      },
    });
    result.created = true;
    const createExt = cred.getClientExtensionResults();
    result.enabled = !!(createExt.prf && createExt.prf.enabled);
    addRow(steps, "ok", "Passkey created");
    addRow(
      steps,
      result.enabled ? "ok" : "warn",
      "PRF reported as enabled at creation: " + result.enabled,
      result.enabled ? "" : "Some phones only reveal it in the next step. Continuing."
    );

    // Step 2: ask the magic question, with two different questions at once
    addRow(steps, "info", "Step 2 of 3: asking the phone. Use your fingerprint, face, or PIN.");
    const a = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{ type: "public-key", id: cred.rawId }],
        userVerification: "required",
        timeout: 60000,
        extensions: { prf: { eval: { first: salt1, second: salt2 } } },
      },
    });
    const ra = a.getClientExtensionResults().prf;
    if (!ra || !ra.results || !ra.results.first) {
      addRow(steps, "fail", "The phone gave no answer to the question", "This phone or browser does not support PRF.");
      return { result, env };
    }
    result.got = true;
    const h1 = await shortHash(ra.results.first);
    addRow(steps, "ok", "Phone answered question 1", "Fingerprint of answer: " + h1);

    if (ra.results.second) {
      const h2 = await shortHash(ra.results.second);
      result.saltsDiffer = h1 !== h2;
      addRow(
        steps,
        result.saltsDiffer ? "ok" : "fail",
        result.saltsDiffer ? "Question 2 gave a different answer (correct)" : "Question 2 gave the same answer (wrong)",
        "Fingerprint of answer: " + h2
      );
    } else {
      addRow(steps, "warn", "Phone only answered one question at a time", "Not a problem for our design.");
      result.saltsDiffer = true; // not required for our design
    }

    // Step 3: ask question 1 again, must give the SAME answer
    addRow(steps, "info", "Step 3 of 3: asking question 1 again. Use your fingerprint, face, or PIN.");
    const b = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{ type: "public-key", id: cred.rawId }],
        userVerification: "required",
        timeout: 60000,
        extensions: { prf: { eval: { first: salt1 } } },
      },
    });
    const rb = b.getClientExtensionResults().prf;
    if (!rb || !rb.results || !rb.results.first) {
      addRow(steps, "fail", "The phone gave no answer the second time");
      return { result, env };
    }
    const h3 = await shortHash(rb.results.first);
    result.stable = h3 === h1;
    addRow(
      steps,
      result.stable ? "ok" : "fail",
      result.stable ? "Same question gave the same answer (correct)" : "Same question gave a different answer (wrong)",
      "Fingerprint of answer: " + h3
    );
  } catch (err) {
    result.error = err && err.name ? err.name : String(err);
    const friendly =
      result.error === "NotAllowedError"
        ? "Cancelled, timed out, or blocked. Try again and finish the fingerprint prompt."
        : result.error === "NotSupportedError"
        ? "This phone or browser does not support this feature."
        : result.error === "SecurityError"
        ? "The page address is not allowed. It must be HTTPS."
        : "Unexpected error.";
    addRow(steps, "fail", "Error: " + result.error, friendly);
  }
  return { result, env };
}

function showVerdict({ result, env }) {
  const pass = result.created && result.got && result.stable && result.saltsDiffer;
  const box = $("verdict");
  box.hidden = false;
  box.className = "verdict " + (pass ? "pass" : "fail");
  $("verdict-title").textContent = pass ? "Your phone works" : "Your phone does not work for this";
  $("verdict-text").textContent = pass
    ? "It can produce a secret that only this phone and your fingerprint can create. You are good for the attendance system."
    : result.error
    ? "The test stopped with an error. If you cancelled by accident, run it again."
    : "This phone or browser cannot produce the secret we need. Send the result code below to the developer.";

  const code = [
    "PRF=" + (pass ? "PASS" : "FAIL"),
    "created=" + result.created,
    "enabledFlag=" + result.enabled,
    "answered=" + result.got,
    "stable=" + result.stable,
    "differs=" + result.saltsDiffer,
    "error=" + (result.error || "none"),
    "screenLock=" + env.platformAuth,
    "browser=" + env.info.browser,
    "device=" + env.info.device,
  ].join(" | ");
  $("summary").value = code;
  box.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ---- Wire up ----
let envState = null;
checkEnvironment().then((e) => {
  envState = e;
  if (!e.secure || !e.hasWA) $("run").disabled = true;
});

$("run").addEventListener("click", async () => {
  const btn = $("run");
  btn.disabled = true;
  btn.textContent = "Testing…";
  $("verdict").hidden = true;
  if (!envState) envState = await checkEnvironment();
  const out = await runTest(envState);
  showVerdict(out);
  btn.disabled = false;
  btn.textContent = "Run the test again";
});

$("copy").addEventListener("click", async () => {
  const ta = $("summary");
  try {
    await navigator.clipboard.writeText(ta.value);
    $("copy").textContent = "Copied";
  } catch (_) {
    ta.select();
    document.execCommand("copy");
    $("copy").textContent = "Copied";
  }
  setTimeout(() => ($("copy").textContent = "Copy result"), 2000);
});