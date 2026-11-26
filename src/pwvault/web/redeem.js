// Redeems a share in the browser. Must stay byte-for-byte compatible with
// pwvault/shares.py. The share secret is read from the URL fragment and never
// sent anywhere; only the derived lookup token goes to the server.
//
// Needs libsodium.js (sumo build) served at /static/sodium.js; see README.
(() => {
  "use strict";

  const PIN_KDF = { opslimit: 3, memlimit: 64 * 1024 * 1024 };  // = crypto.PIN_KDF
  const HKDF_SALT = "pwvault/share/v1";
  const NONCE_SIZE = 24;
  const enc = new TextEncoder();
  const $ = (id) => document.getElementById(id);

  const shareId = decodeURIComponent(location.pathname.split("/").filter(Boolean).pop() || "");
  const secretText = location.hash.slice(1);
  // Drop the secret from the address bar and history once read.
  history.replaceState(null, "", location.pathname);

  function setStatus(text, isError = false) {
    $("status").textContent = text;
    $("status").className = isError ? "error" : "";
  }

  function fromB64url(text) {
    if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new Error("bad base64url");
    let s = text.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  }

  function toB64url(bytes) {
    let s = "";
    bytes.forEach((b) => { s += String.fromCharCode(b); });
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function concat(a, b) {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
  }

  async function hkdf(ikm, info) {
    const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: enc.encode(HKDF_SALT), info: enc.encode(info) },
      key, 256);
    return new Uint8Array(bits);
  }

  const normalizePin = (pin) => pin.replace(/[\s-]/g, "").toUpperCase();

  async function deriveKeys(sodium, secret, pin) {
    let ikm = secret;
    if (pin) {
      const pinKey = sodium.crypto_pwhash(
        32, enc.encode(normalizePin(pin)), fromB64url(shareId),
        PIN_KDF.opslimit, PIN_KDF.memlimit, sodium.crypto_pwhash_ALG_ARGON2ID13);
      ikm = concat(secret, pinKey);
    }
    return {
      encKey: await hkdf(ikm, `enc|${shareId}`),
      lookupToken: await hkdf(ikm, `lookup|${shareId}`),
    };
  }

  function showResult(entry) {
    $("pin-form").hidden = true;
    $("reveal").hidden = true;
    $("r-name").textContent = entry.name;
    $("r-username").textContent = entry.username || "(none)";
    $("r-password").textContent = entry.password;
    $("result").hidden = false;
    setStatus("Save the password somewhere safe: this link may not work again.");
    $("copy").onclick = async () => {
      await navigator.clipboard.writeText(entry.password);
      $("copy").textContent = "Copied";
    };
  }

  async function redeem(sodium, secret, pin) {
    setStatus("Checking…");
    const keys = await deriveKeys(sodium, secret, pin);
    const resp = await fetch(`/v1/shares/${encodeURIComponent(shareId)}/redeem`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: toB64url(keys.lookupToken) }),
    });
    const body = await resp.json().catch(() => ({}));
    if (resp.status === 403) {
      const left = body.attempts_left;
      setStatus(`Wrong PIN. ${left} attempt${left === 1 ? "" : "s"} left.`, true);
      return;
    }
    if (!resp.ok) {
      $("pin-form").hidden = true;
      $("reveal").hidden = true;
      setStatus(/too many/i.test(body.detail || "")
        ? "Too many wrong PINs, so this link has expired. Ask the sender for a new one."
        : "This share has ended.", true);
      return;
    }
    const blob = fromB64url(body.blob);
    const plain = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null, blob.subarray(NONCE_SIZE), enc.encode(`pwvault/share-blob/v1|${shareId}`),
      blob.subarray(0, NONCE_SIZE), keys.encKey);
    showResult(JSON.parse(new TextDecoder().decode(plain)));
  }

  async function main(sodium) {
    let secret;
    try {
      secret = fromB64url(secretText);
      if (secret.length !== 16 || fromB64url(shareId).length !== 16) throw new Error();
    } catch {
      setStatus("This link is incomplete. Ask for the full link or scan the QR code again.", true);
      return;
    }
    const info = await (await fetch(`/v1/shares/${encodeURIComponent(shareId)}/info`)).json();
    if (!info.active) {
      setStatus("This share has ended.", true);
      return;
    }
    const run = (pin) => redeem(sodium, secret, pin).catch((err) => {
      console.error(err);
      setStatus("Something went wrong decrypting the password.", true);
    });
    if (info.has_pin) {
      setStatus("Enter the PIN you were given.");
      $("pin-form").hidden = false;
      $("pin-form").onsubmit = (e) => { e.preventDefault(); run($("pin").value); };
    } else {
      setStatus("Opening reveals the password and uses up this link.");
      $("reveal").hidden = false;
      $("reveal").onclick = () => run(null);
    }
  }

  // libsodium.js browser build calls window.sodium.onload once it is ready.
  window.sodium = { onload: (sodium) => main(sodium) };
  const script = document.createElement("script");
  script.src = "/static/sodium.js";
  script.async = true;
  script.onerror = () => setStatus(
    "The server is missing /static/sodium.js, so this page can't decrypt. Tell the sender.", true);
  document.head.appendChild(script);
})();
