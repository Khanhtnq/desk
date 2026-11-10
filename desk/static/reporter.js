/* Reporter-side behaviour: sign in (email link, XE key, wallet generator), payout binding, filing with
 * attachments, replying and withdrawing. Keys never leave the tab; see signer.js. */
(function () {
  const $ = (s, r) => (r || document).querySelector(s);
  const csrf = () => (document.querySelector('meta[name="desk-csrf"]') || {}).content || "";
  const say = (sel, msg, ok) => { const el = $(sel); if (!el) return; el.textContent = msg; el.className = "msg " + (ok ? "ok" : "err"); el.style.display = ""; };
  const safe = (n) => (n && n.startsWith("/") && !n.startsWith("//") && !n.includes("\\")) ? n : "/my";
  const nextPath = () => {
    const l = $(".login");
    return safe((l && l.dataset.next) || new URLSearchParams(location.search).get("next"));
  };

  async function api(method, path, body, raw) {
    const headers = { "Accept": "application/json", "X-Desk-CSRF": csrf() };
    let payload = body;
    if (body !== undefined && !(body instanceof FormData)) { headers["Content-Type"] = "application/json"; payload = raw ? body : JSON.stringify(body); }
    const res = await fetch(path, { method, headers, body: payload, credentials: "same-origin" });
    const text = await res.text();
    let data; try { data = JSON.parse(text); } catch (e) { data = { raw: text }; }
    if (!res.ok) {
      const d = data && data.detail;
      throw new Error(typeof d === "string" ? d : Array.isArray(d) ? d.map(x => x.msg).join("; ") : data.error || ("HTTP " + res.status));
    }
    return data;
  }

  function randomSeedHex() {
    const b = new Uint8Array(32); crypto.getRandomValues(b);
    return Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
  }

  /* A signed POST that also carries the CSRF header, for routes behind the reporter cookie. */
  async function signedPost(url, domain, payload) {
    const S = window.XeSigner;
    if (!S) throw new Error("signer not loaded");
    if (!(await S.detect())) throw new Error("this browser cannot sign Ed25519 in WebCrypto; try a current Chrome, Safari or Firefox");
    const r = await S.signDigest(domain, payload);
    return api("POST", url, S.body(payload, r.ts, S.pub(), r.signature), true);
  }

  // ---- email link ----------------------------------------------------------------------------
  const emailBtn = $("#email-start");
  if (emailBtn) emailBtn.addEventListener("click", async () => {
    const email = ($("#email").value || "").trim();
    if (!email) return say("#email-msg", "an email address first", false);
    emailBtn.disabled = true;
    try {
      const d = await api("POST", "/v1/reporter/auth/email", { email, next: nextPath() });
      say("#email-msg", d.sent ? "Sent. Open the link within fifteen minutes." : (d.note || "Not sent."), d.sent);
    } catch (e) { say("#email-msg", e.message, false); }
    emailBtn.disabled = false;
  });

  // ---- XE key: sign in / link ---------------------------------------------------------------
  const toggle = $("#xe-link-toggle");
  if (toggle) toggle.addEventListener("click", () => { const b = $("#xe-box"); b.style.display = b.style.display === "none" ? "" : "none"; });
  const have = $("#xe-have");
  if (have) have.addEventListener("click", () => { const b = $("#xe-have-box"); b.style.display = b.style.display === "none" ? "" : "none"; if (b.style.display === "") $("#xe-seed").focus(); });

  async function xeLogin(seedHex) {
    const S = window.XeSigner;
    await S.setSeed(seedHex);
    const d = await signedPost("/v1/reporter/auth/xe", "xe/desk/login/v1", { host: location.host });
    S.forget();
    return d;
  }
  const xeBtn = $("#xe-login");
  if (xeBtn) xeBtn.addEventListener("click", async () => {
    const seed = ($("#xe-seed").value || "").trim();
    xeBtn.disabled = true;
    try { await xeLogin(seed); $("#xe-seed").value = ""; say("#xe-msg", "Signed in.", true); location.assign($("#xe-link-toggle") ? "/account" : nextPath()); }
    catch (e) { say("#xe-msg", e.message, false); window.XeSigner && window.XeSigner.forget(); }
    xeBtn.disabled = false;
  });
  const xeGen = $("#xe-generate");
  if (xeGen) xeGen.addEventListener("click", async () => {
    try {
      const S = window.XeSigner;
      if (!(await S.detect())) throw new Error("this browser cannot sign Ed25519 in WebCrypto");
      const seed = randomSeedHex();
      const { address } = await S.setSeed(seed);
      S.forget();
      $("#xe-new-seed").textContent = seed; $("#xe-new-addr").textContent = address;
      $("#xe-new").style.display = "";
      $("#xe-use-new").onclick = async () => {
        try { await xeLogin(seed); location.assign($("#xe-link-toggle") ? "/account" : nextPath()); }
        catch (e) { say("#xe-msg", e.message, false); }
      };
    } catch (e) { say("#xe-msg", e.message, false); }
  });

  // ---- payout address --------------------------------------------------------------------------
  async function bindPayout(seedHex, pasted) {
    const S = window.XeSigner;
    const known = (($("#payout-box") || {}).dataset || {}).known || "";
    if (pasted && known.split(",").filter(Boolean).includes(seedHex.toLowerCase()))
      throw new Error("that is an address, not a seed; a key made from it could be used by anyone who knows the address");
    const { address } = await S.setSeed(seedHex);
    try {
      if (pasted && !confirm("This seed controls the address\n\n" + address + "\n\nAwards will be paid there. Bind it?")) return null;
      return await signedPost("/v1/reporter/payout", "xe/desk/payout/v1", { address });
    } finally { S.forget(); }
  }
  const payBtn = $("#payout-bind");
  if (payBtn) payBtn.addEventListener("click", async () => {
    payBtn.disabled = true;
    try {
      const d = await bindPayout(($("#payout-seed").value || "").trim(), true);
      if (d) { $("#payout-seed").value = ""; say("#payout-msg", "Bound to " + d.address + ".", true); setTimeout(() => location.reload(), 700); }
    } catch (e) { say("#payout-msg", e.message, false); }
    payBtn.disabled = false;
  });
  const payOff = $("#payout-unbind");
  if (payOff) payOff.addEventListener("click", async () => {
    if (!confirm("Remove the payout address? Nothing can be paid until another is bound.")) return;
    try { await api("POST", "/v1/reporter/payout/unbind"); location.reload(); }
    catch (e) { say("#payout-msg", e.message, false); }
  });
  // ---- ways in: remove one; end other sessions --------------------------------------------------
  // adding GitHub or Discord to the account is a write: asked for by POST, with the CSRF header, and
  // the browser is then sent to the address the desk returns
  document.querySelectorAll("button.link-identity").forEach((b) => b.addEventListener("click", async () => {
    try {
      const r = await api("POST", "/v1/reporter/auth/" + b.dataset.provider + "/link", { next: "/account" });
      location.assign(r.url);
    } catch (e) { say("#unlink-msg", e.message, false); }
  }));
  document.querySelectorAll("button.unlink").forEach((b) => b.addEventListener("click", async () => {
    const kind = b.dataset.kind, value = b.dataset.value || "";
    if (!confirm("Remove this way in? You will no longer be able to sign in with it.")) return;
    try { await api("POST", "/v1/reporter/identities/unlink", { kind, value }); location.reload(); }
    catch (e) { say("#unlink-msg", e.message, false); }
  }));
  const revokeOthers = $("#revoke-others");
  if (revokeOthers) revokeOthers.addEventListener("click", async () => {
    try {
      const d = await api("POST", "/v1/reporter/sessions/revoke-others");
      say("#session-msg", d.ended ? "Ended " + d.ended + " other " + (d.ended === 1 ? "session." : "sessions.") : "No other sessions.", true);
    } catch (e) { say("#session-msg", e.message, false); }
  });

  const payGen = $("#payout-generate");
  if (payGen) payGen.addEventListener("click", async () => {
    try {
      const S = window.XeSigner;
      if (!(await S.detect())) throw new Error("this browser cannot sign Ed25519 in WebCrypto");
      const seed = randomSeedHex();
      const { address } = await S.setSeed(seed);
      S.forget();
      $("#payout-new-seed").textContent = seed; $("#payout-new-addr").textContent = address;
      $("#payout-new").style.display = "";
      $("#payout-use-new").onclick = async () => {
        try { await bindPayout(seed, false); say("#payout-msg", "Bound.", true); setTimeout(() => location.reload(), 700); }
        catch (e) { say("#payout-msg", e.message, false); }
      };
    } catch (e) { say("#payout-msg", e.message, false); }
  });

  // ---- sign out ------------------------------------------------------------------------------
  const out = $("#reporter-logout");
  if (out) out.addEventListener("click", async () => {
    // a refusal (a tab from an older session) is said, not hidden behind a redirect that looks like
    // a sign-out; the reload brings the page up to date with the session
    try { await api("POST", "/v1/reporter/logout"); location.assign("/"); }
    catch (e) { alert("Not signed out: " + e.message); location.reload(); }
  });

  // ---- filing ----------------------------------------------------------------------------------
  const form = $("#report-form");
  if (form) form.addEventListener("submit", async e => {
    e.preventDefault();
    const btn = $("#report-submit");
    const files = $("#files").files;
    const maxMb = +form.dataset.maxMb, maxFiles = +form.dataset.maxFiles;
    if (files.length > maxFiles) return say("#report-msg", "at most " + maxFiles + " files", false);
    for (const f of files) if (f.size > maxMb * 1024 * 1024) return say("#report-msg", f.name + " is over " + maxMb + " MB", false);
    const fd = new FormData(form);
    if (!$("#private") || !$("#private").checked) fd.set("private", "false");
    btn.disabled = true; say("#report-msg", "Filing…", true);
    try {
      const d = await api("POST", "/v1/reporter/tickets", fd);
      const mailed = d.notify_sent === true;
      say("#report-msg", "Filed as " + d.ticket + "." + (mailed ? " A link to confirm your email is on its way." : ""), true);
      setTimeout(() => location.assign(d.url || ("/" + d.ticket)), mailed ? 1800 : 0);
    } catch (err) { say("#report-msg", err.message, false); btn.disabled = false; }
  });

  // ---- on a ticket -----------------------------------------------------------------------------
  const box = $(".compose.reporter");
  if (box) {
    const tid = box.dataset.ticket;
    const send = $("#reporter-send");
    if (send) send.addEventListener("click", async () => {
      const body = $("#reporter-reply").value.trim();
      if (!body) return say("#reporter-msg", "nothing to send", false);
      send.disabled = true;
      try { await api("POST", "/v1/reporter/tickets/" + tid + "/messages", { body }); location.reload(); }
      catch (e) { say("#reporter-msg", e.message, false); send.disabled = false; }
    });
    const wd = $("#reporter-withdraw");
    if (wd) wd.addEventListener("click", async () => {
      const ok = window.desk ? await window.desk.ask({ title: "Withdraw this report?", body: "It closes as withdrawn and the team stops work on it.", ok: "Withdraw", danger: true }) : confirm("Withdraw this? It closes as withdrawn and the team stops work on it.");
      if (!ok) return;
      const body = $("#reporter-reply").value.trim();
      wd.disabled = true;
      try { await api("POST", "/v1/reporter/tickets/" + tid + "/withdraw", { body }); location.reload(); }
      catch (e) { say("#reporter-msg", e.message, false); wd.disabled = false; }
    });
  }
})();
