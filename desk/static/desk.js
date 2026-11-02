/* The desk's page scripts. Everything goes through /v1 with the session cookie and the CSRF header;
   no forms post. Passkeys use the WebAuthn API with the base64url helpers below. */
(function () {
  "use strict";
  const $ = (s, el) => (el || document).querySelector(s);
  const $$ = (s, el) => Array.from((el || document).querySelectorAll(s));
  const csrf = () => (document.querySelector('meta[name="desk-csrf"]') || {}).content || "";

  async function api(method, path, body) {
    const r = await fetch(path, {
      method, credentials: "same-origin",
      headers: Object.assign({ "Accept": "application/json", "X-Desk-CSRF": csrf() }, body !== undefined ? { "Content-Type": "application/json" } : {}),
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    let data = null;
    try { data = await r.json(); } catch (e) { data = null; }
    if (!r.ok) throw new Error((data && (data.error || data.detail)) ? (data.error || JSON.stringify(data.detail)) : `${r.status} ${r.statusText}`);
    return data;
  }
  function say(el, text, ok) {
    if (!el) return;
    el.style.display = text ? "block" : "none";
    el.textContent = text || "";
    el.className = "msg " + (ok ? "ok" : "err");
  }
  const reload = () => location.reload();

  // ---- dialog: ask({title, body, ok, cancel, danger, input, value}) -> Promise<bool|string|null>
  //      tell(title, body) -> Promise<void>. One <dialog> in base.html; never the browser's own boxes.
  function ask(o) {
    const d = $("#desk-dialog");
    if (!d || !d.showModal) return Promise.resolve(o.input !== undefined ? prompt(o.body || o.title, o.value || "") : confirm((o.title || "") + (o.body ? "\n\n" + o.body : "")));
    const title = $("h3", d), body = $(".dialog-body", d), input = $(".dialog-input", d), okB = $("button[value=ok]", d), cancelB = $("button[value=cancel]", d);
    title.textContent = o.title || "";
    body.textContent = o.body || "";
    okB.textContent = o.ok || "Continue";
    cancelB.textContent = o.cancel || "Cancel";
    cancelB.style.display = o.cancel === null ? "none" : "";
    d.classList.toggle("danger", !!o.danger);
    const hasInput = o.input !== undefined;
    input.style.display = hasInput ? "" : "none";
    input.placeholder = hasInput ? (o.input || "") : "";
    input.value = hasInput ? (o.value || "") : "";
    return new Promise((resolve) => {
      const done = (v) => { cleanup(); if (d.open) d.close(); resolve(v); };
      const onOk = () => done(hasInput ? input.value : true);
      const onCancel = () => done(hasInput ? null : false);
      const onClose = () => done(hasInput ? null : false);
      const onKey = (e) => { if (e.key === "Enter" && (!hasInput || e.metaKey || e.ctrlKey)) { e.preventDefault(); onOk(); } };
      function cleanup() { okB.removeEventListener("click", onOk); cancelB.removeEventListener("click", onCancel); d.removeEventListener("close", onClose); d.removeEventListener("keydown", onKey); }
      okB.addEventListener("click", onOk); cancelB.addEventListener("click", onCancel); d.addEventListener("close", onClose); d.addEventListener("keydown", onKey);
      d.showModal();
      (hasInput ? input : okB).focus();
    });
  }
  const tell = (title, body) => ask({ title, body, ok: "OK", cancel: null }).then(() => undefined);
  window.desk = Object.assign(window.desk || {}, { ask, tell });

  // a one-line note that survives a reload: flash("Award approved.") before reload(), shown on the next page
  const FLASH = "desk-flash";
  const flash = (text) => { try { sessionStorage.setItem(FLASH, text); } catch (e) {} };
  function showFlash(el) {
    let text = null;
    try { text = sessionStorage.getItem(FLASH); sessionStorage.removeItem(FLASH); } catch (e) {}
    if (text) say(el, text, true);
  }

  // ---- shell: theme, cog menu, mobile nav (as on the governance site) -------------------------
  const THEME_KEY = "xe-desk-theme";
  const theme = () => document.documentElement.dataset.theme === "light" ? "light" : "dark";
  function setTheme(t, animate) {
    const html = document.documentElement;
    if (animate && !matchMedia("(prefers-reduced-motion: reduce)").matches) {
      html.classList.add("g-theming"); setTimeout(() => html.classList.remove("g-theming"), 320);
    }
    html.dataset.theme = t;
    try { localStorage.setItem(THEME_KEY, t); } catch (e) {}
    const meta = document.querySelector('meta[name="theme-color"]'); if (meta) meta.content = t === "light" ? "#fafafa" : "#0a0a0a";
    $$("[data-theme-label]").forEach(el => { el.textContent = t === "dark" ? "Light theme" : "Dark theme"; });
  }
  document.addEventListener("DOMContentLoaded", () => {
    $$("[data-theme-label]").forEach(el => { el.textContent = theme() === "dark" ? "Light theme" : "Dark theme"; });
    const tt = $("#theme-toggle"); if (tt) tt.addEventListener("click", () => setTheme(theme() === "dark" ? "light" : "dark", true));
    const cog = $("#cog-menu"), pop = $("#cog-pop");
    if (cog && pop) {
      const close = () => { pop.hidden = true; cog.setAttribute("aria-expanded", "false"); };
      cog.addEventListener("click", e => { e.stopPropagation(); const open = pop.hidden; pop.hidden = !open; cog.setAttribute("aria-expanded", String(open)); });
      document.addEventListener("click", e => { if (!pop.hidden && !pop.contains(e.target)) close(); });
      document.addEventListener("keydown", e => { if (e.key === "Escape") close(); });
    }
    const nb = $("#nav-btn"), mn = $("#mobile-nav");
    if (nb && mn) nb.addEventListener("click", () => { mn.hidden = !mn.hidden; nb.setAttribute("aria-expanded", String(!mn.hidden)); });
  });

  // ---- base64url for WebAuthn -----------------------------------------------------------------
  const b64u = {
    enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
    dec: (s) => { s = s.replace(/-/g, "+").replace(/_/g, "/"); s += "=".repeat((4 - s.length % 4) % 4); return Uint8Array.from(atob(s), c => c.charCodeAt(0)).buffer; },
  };
  function toCreationOptions(o) {
    const pk = Object.assign({}, o);
    pk.challenge = b64u.dec(o.challenge);
    pk.user = Object.assign({}, o.user, { id: b64u.dec(o.user.id) });
    if (o.excludeCredentials) pk.excludeCredentials = o.excludeCredentials.map(c => Object.assign({}, c, { id: b64u.dec(c.id) }));
    return pk;
  }
  function toRequestOptions(o) {
    const pk = Object.assign({}, o);
    pk.challenge = b64u.dec(o.challenge);
    if (o.allowCredentials) pk.allowCredentials = o.allowCredentials.map(c => Object.assign({}, c, { id: b64u.dec(c.id) }));
    return pk;
  }
  function credentialToJSON(c) {
    const r = c.response;
    const out = { id: c.id, rawId: b64u.enc(c.rawId), type: c.type, clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {},
      authenticatorAttachment: c.authenticatorAttachment || undefined, response: { clientDataJSON: b64u.enc(r.clientDataJSON) } };
    if (r.attestationObject) {
      out.response.attestationObject = b64u.enc(r.attestationObject);
      if (r.getTransports) out.response.transports = r.getTransports();
    } else {
      out.response.authenticatorData = b64u.enc(r.authenticatorData);
      out.response.signature = b64u.enc(r.signature);
      if (r.userHandle) out.response.userHandle = b64u.enc(r.userHandle);
    }
    return out;
  }

  // ---- sign-in -------------------------------------------------------------------------------
  const loginForm = $("#login-form");
  if (loginForm) {
    const msg = $("#login-msg"), next = loginForm.dataset.next || "/";
    const go = () => { location.href = next.startsWith("/") ? next : "/"; };
    $("#passkey-login").addEventListener("click", async () => {
      try {
        if (!window.PublicKeyCredential) throw new Error("this browser has no passkey support; use the code");
        const email = $("#email").value.trim() || null;
        const begin = await api("POST", "/v1/auth/passkey/login/begin", { email });
        const cred = await navigator.credentials.get({ publicKey: toRequestOptions(begin.options) });
        await api("POST", "/v1/auth/passkey/login/finish", { challenge_id: begin.challenge_id, credential: credentialToJSON(cred) });
        go();
      } catch (e) { say(msg, e.message, false); }
    });
    $("#totp-login").addEventListener("click", async () => {
      try {
        await api("POST", "/v1/auth/totp/login", { email: $("#email").value.trim(), code: $("#code").value.trim() });
        go();
      } catch (e) { say(msg, e.message, false); }
    });
    $("#code").addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); $("#totp-login").click(); } });
  }
  const inviteForm = $("#invite-form");
  if (inviteForm) {
    $("#accept-invite").addEventListener("click", async () => {
      try { await api("POST", "/v1/auth/invite/accept", { token: inviteForm.dataset.token }); location.href = "/team/account"; }
      catch (e) { say($("#invite-msg"), e.message, false); }
    });
  }

  // ---- account -------------------------------------------------------------------------------
  if ($("#add-passkey")) {
    $("#add-passkey").addEventListener("click", async () => {
      const msg = $("#passkey-msg");
      try {
        const begin = await api("POST", "/v1/auth/passkey/register/begin");
        const cred = await navigator.credentials.create({ publicKey: toCreationOptions(begin.options) });
        await api("POST", "/v1/auth/passkey/register/finish", { challenge_id: begin.challenge_id, credential: credentialToJSON(cred), label: $("#passkey-label").value.trim() });
        reload();
      } catch (e) { say(msg, e.message, false); }
    });
    $$("[data-remove-passkey]").forEach(b => b.addEventListener("click", async () => {
      if (!await ask({ title: "Remove this passkey?", body: "You can add it again from this page.", ok: "Remove", danger: true })) return;
      try { await api("DELETE", `/v1/auth/passkeys/${b.dataset.removePasskey}`); reload(); } catch (e) { say($("#passkey-msg"), e.message, false); }
    }));
  }
  const saveName = $("#save-name"), saveEmail = $("#save-email");
  if (saveName) saveName.addEventListener("click", async () => {
    saveName.disabled = true;
    try { await api("POST", "/v1/team/account/name", { name: $("#my-name").value.trim() }); say($("#name-msg"), "Saved.", true); setTimeout(reload, 500); }
    catch (e) { say($("#name-msg"), e.message, false); saveName.disabled = false; }
  });
  if (saveEmail) saveEmail.addEventListener("click", async () => {
    saveEmail.disabled = true;
    try { await api("POST", "/v1/team/account/email", { email: $("#my-email").value.trim() }); say($("#name-msg"), "Saved. Use the new address at sign-in.", true); setTimeout(reload, 900); }
    catch (e) { say($("#name-msg"), e.message, false); saveEmail.disabled = false; }
  });
  if ($("#setup-totp")) {
    let cid = null;
    $("#setup-totp").addEventListener("click", async () => {
      try {
        const r = await api("POST", "/v1/auth/totp/setup");
        cid = r.challenge_id; $("#totp-secret").textContent = r.secret; $("#totp-uri").href = r.uri;
        $("#totp-setup").style.display = "block"; $("#setup-totp").style.display = "none";
      } catch (e) { say($("#totp-msg"), e.message, false); }
    });
    $("#confirm-totp").addEventListener("click", async () => {
      try { await api("POST", "/v1/auth/totp/confirm", { challenge_id: cid, code: $("#totp-code").value.trim() }); reload(); }
      catch (e) { say($("#totp-msg"), e.message, false); }
    });
  }
  if ($("#remove-totp")) $("#remove-totp").addEventListener("click", async () => {
    try { await api("DELETE", "/v1/auth/totp"); reload(); } catch (e) { say($("#totp-msg"), e.message, false); }
  });
  if ($("#logout")) $("#logout").addEventListener("click", async () => { await api("POST", "/v1/auth/logout"); location.href = "/"; });

  // ---- tokens --------------------------------------------------------------------------------
  const tokenForm = $("#token-form");
  if (tokenForm) {
    tokenForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = new FormData(tokenForm), msg = $("#token-msg");
      try {
        const r = await api("POST", "/v1/team/tokens", {
          model_id: fd.get("model_id"), label: fd.get("label") || "", days: parseInt(fd.get("days") || "90", 10),
          scopes: fd.getAll("scopes"), owner_id: fd.get("owner_id") ? parseInt(fd.get("owner_id"), 10) : null,
          instructions: fd.get("instructions") || "",
        });
        say(msg, `Token (shown once): ${r.token}`, true);
        msg.style.userSelect = "all";
      } catch (err) { say(msg, err.message, false); }
    });
    $$("[data-instruct]").forEach(el => el.addEventListener("click", async () => {
      const cur = el.getAttribute("title") || "";
      const next = await ask({ title: "Standing instructions", body: "What this agent should focus on or leave alone. Blank clears them. They are returned by GET /v1/me and folded into the agent's brief.", input: "Only p2p-sync tickets. Never propose status.", value: cur, ok: "Save" });
      if (next === null || next.trim() === cur.trim()) return;
      try { await api("PATCH", `/v1/team/tokens/${el.dataset.instruct}`, { instructions: next.trim() }); reload(); } catch (e) { say($("#token-msg"), e.message, false); }
    }));
    $$("[data-revoke]").forEach(b => b.addEventListener("click", async () => {
      if (!await ask({ title: "Revoke this token?", body: "Calls with it stop at once. This cannot be undone.", ok: "Revoke", danger: true })) return;
      try { await api("DELETE", `/v1/team/tokens/${b.dataset.revoke}`); reload(); } catch (e) { say($("#token-msg"), e.message, false); }
    }));
  }

  // ---- users ---------------------------------------------------------------------------------
  const userForm = $("#user-form");
  if (userForm) {
    userForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = new FormData(userForm), msg = $("#user-msg");
      try {
        const u = await api("POST", "/v1/team/users", { email: fd.get("email"), name: fd.get("name") || "", roles: fd.getAll("roles") });
        const inv = await api("POST", `/v1/auth/invite/${u.id}`);
        say(msg, `Added. Invite link${inv.emailed ? " (also emailed)" : ""}: ${inv.url}`, true);
        msg.style.userSelect = "all";
      } catch (err) { say(msg, err.message, false); }
    });
  }
  $$("[data-invite]").forEach(b => b.addEventListener("click", async () => {
    try { const inv = await api("POST", `/v1/auth/invite/${b.dataset.invite}`); say($("#users-msg"), `Invite link${inv.emailed ? " (also emailed)" : ""}: ${inv.url}`, true); $("#users-msg").style.userSelect = "all"; }
    catch (e) { say($("#users-msg"), e.message, false); }
  }));
  $$("[data-rename]").forEach(el => el.addEventListener("click", async () => {
    const name = await ask({ title: "Rename", body: "The name on this person's replies and notes.", input: "Name", value: el.textContent.trim(), ok: "Save" });
    if (name === null || !name.trim()) return;
    try { await api("PATCH", `/v1/team/users/${el.dataset.rename}`, { name: name.trim() }); reload(); }
    catch (e) { say($("#users-msg"), e.message, false); }
  }));
  $$("[data-toggle-active]").forEach(b => b.addEventListener("click", async () => {
    try { await api("PATCH", `/v1/team/users/${b.dataset.toggleActive}`, { active: b.dataset.active !== "true" }); reload(); }
    catch (e) { say($("#users-msg"), e.message, false); }
  }));

  // ---- ticket page ---------------------------------------------------------------------------
  const ticketEl = $(".ticket[data-ticket]");
  if (ticketEl) {
    const tid = ticketEl.dataset.ticket, facts = $("#facts"), fmsg = $("#facts-msg");
    const T = (p) => `/v1/team/tickets/${tid}${p}`;
    showFlash(fmsg);

    if ($("#edit-facts")) {
      $("#edit-facts").addEventListener("click", () => facts.classList.add("editing"));
      $("#cancel-facts").addEventListener("click", () => facts.classList.remove("editing"));
      $("#save-facts").addEventListener("click", async () => {
        const changes = {};
        $$("select.edit, input.edit", facts).forEach(el => {
          let v = el.value;
          if (el.name === "assignee_id") v = v ? parseInt(v, 10) : null;
          changes[el.name] = v === "" ? null : v;
        });
        try { await api("PATCH", T("/facts"), { changes }); reload(); } catch (e) { say(fmsg, e.message, false); }
      });
    }
    const statusSel = $("#status-select"), reasonSel = $("#closed-reason");
    if (statusSel) {
      statusSel.addEventListener("change", () => { reasonSel.style.display = statusSel.value === "closed" ? "" : "none"; });
      $("#set-status").addEventListener("click", async () => {
        const body = { status: statusSel.value };
        if (statusSel.value === "closed") body.closed_reason = reasonSel.value;
        if (statusSel.value === "disclosed" && !await ask({ title: "Disclose this report?", body: "The body leaves the vault and a public issue is opened. This cannot be undone.", ok: "Disclose", danger: true })) return;
        try { await api("POST", T("/status"), body); reload(); } catch (e) { say(fmsg, e.message, false); }
      });
    }
    if ($("#save-award")) {
      $("#save-award").addEventListener("click", async () => {
        const xe = parseFloat($("#award-xe").value);
        if (isNaN(xe)) return say(fmsg, "enter an amount in XE", false);
        try { await api("POST", T("/award"), { award_xe: Math.round(xe * 1e6) }); reload(); } catch (e) { say(fmsg, e.message, false); }
      });
      if ($("#approve-award")) $("#approve-award").addEventListener("click", async () => {
        const xe = $("#award-xe").value;
        const ok = await ask({ title: `Approve ${xe} XE for ${tid}?`, body: "The award is recorded against you in the log and goes on the treasurer's payout list. The reporter is not told here; set the status to awarded when it is time, and the leaderboard updates then.", ok: "Approve" });
        if (!ok) return;
        try { await api("POST", T("/award"), { approve: true }); flash(`Award of ${xe} XE approved.`); reload(); } catch (e) { say(fmsg, e.message, false); }
      });
      if ($("#unapprove-award")) $("#unapprove-award").addEventListener("click", async () => {
        const xe = $("#award-xe").value;
        const ok = await ask({ title: `Take back approval of ${xe} XE for ${tid}?`, body: "The amount stays set; it leaves the payout list until approved again. Recorded against you in the log.", ok: "Take it back" });
        if (!ok) return;
        try { await api("POST", T("/award"), { approve: false }); flash("Approval taken back; the amount is still set."); reload(); } catch (e) { say(fmsg, e.message, false); }
      });
    }
    if ($("#attach-reporter")) $("#attach-reporter").addEventListener("click", async () => {
      const id = $("#reporter-pick").value, email = $("#reporter-email").value.trim();
      if (!id && !email) return say(fmsg, "pick a reporter or enter their email", false);
      const body = id ? { reporter_id: parseInt(id, 10) } : { email };
      try {
        const r = await api("POST", T("/reporter"), body);
        flash(`Reporter set to ${r.reporter}. When they sign in with that identity, this ticket is theirs.`);
        reload();
      } catch (e) { say(fmsg, e.message, false); }
    });
    if ($("#convert-kind")) $("#convert-kind").addEventListener("click", async () => {
      const to = $("#convert-kind").dataset.to;
      if (!await ask({ title: `Make this a ${to} ticket?`, body: "The id and history stay; the facts that only apply to the other kind are kept but hidden.", ok: `Make ${to}` })) return;
      try { await api("POST", T(`/kind?kind=${to}`)); reload(); } catch (e) { say(fmsg, e.message, false); }
    });
    if ($("#add-patch")) $("#add-patch").addEventListener("click", async () => {
      const ref = $("#patch-ref").value.trim();
      if (!ref) return;
      try { await api("POST", `/v1/tickets/${tid}/patch-refs`, { ref }); reload(); } catch (e) { say(fmsg, e.message, false); }
    });

    // reply
    const replyBody = $("#reply-body"), rmsg = $("#reply-msg");
    if (replyBody) {
      $$("[data-template]").forEach(b => b.addEventListener("click", async () => {
        try { const r = await api("GET", T(`/reply-template/${b.dataset.template}`)); replyBody.value = r.body; replyBody.focus(); }
        catch (e) { say(rmsg, e.message, false); }
      }));
      $("#send-reply").addEventListener("click", async () => {
        const body = replyBody.value.trim();
        if (!body) return say(rmsg, "write something first", false);
        if (!await ask({ title: "Send this reply in public?", body: "It is mirrored to the source channel under your name and cannot be unsent.", ok: "Send" })) return;
        try { await api("POST", T("/replies"), { body }); reload(); } catch (e) { say(rmsg, e.message, false); }
      });
    }
    // notes
    if ($("#add-note")) $("#add-note").addEventListener("click", async () => {
      const body = $("#note-body").value.trim();
      if (!body) return;
      try { await api("POST", `/v1/tickets/${tid}/notes`, { body }); reload(); } catch (e) { say($("#note-msg"), e.message, false); }
    });
    // proposals
    $$("[data-adopt]").forEach(b => b.addEventListener("click", async () => {
      const card = b.closest(".proposal");
      try {
        const r = await api("POST", `/v1/team/proposals/${b.dataset.adopt}/adopt`, {});
        if (r.reply_draft !== undefined && replyBody) { replyBody.value = r.reply_draft; replyBody.focus(); card.classList.add("adopted"); b.disabled = true; }
        else reload();
      } catch (e) { say(fmsg, e.message, false); tell("Could not adopt", e.message); }
    }));
    $$("[data-reject]").forEach(b => b.addEventListener("click", async () => {
      try { await api("POST", `/v1/team/proposals/${b.dataset.reject}/reject`, {}); reload(); } catch (e) { tell("Could not reject", e.message); }
    }));
    if ($("#adopt-all")) $("#adopt-all").addEventListener("click", async () => {
      const ids = $$("[data-adopt]:not([disabled])").filter(b => b.closest(".proposal").dataset.field !== "reply_draft").map(b => parseInt(b.dataset.adopt, 10));
      if (!ids.length || !await ask({ title: `Adopt ${ids.length} proposals?`, body: "Reply drafts are left for you to use one at a time.", ok: "Adopt all" })) return;
      try { await api("POST", "/v1/team/proposals/bulk", { adopt: ids }); reload(); } catch (e) { tell("Could not adopt", e.message); }
    });
  }

  // ---- awards page ---------------------------------------------------------------------------
  if ($(".awards")) {
    const amsg = $("#awards-msg");
    $$("[data-adopt-award]").forEach(b => b.addEventListener("click", async () => {
      try { await api("POST", `/v1/team/proposals/${b.dataset.adoptAward}/adopt`, {}); reload(); }
      catch (e) { say(amsg, e.message, false); }
    }));
    $$("[data-reject-award]").forEach(b => b.addEventListener("click", async () => {
      try { await api("POST", `/v1/team/proposals/${b.dataset.rejectAward}/reject`, {}); reload(); }
      catch (e) { say(amsg, e.message, false); }
    }));
    $$("[data-set-award]").forEach(b => b.addEventListener("click", async () => {
      const tid = b.dataset.setAward, xe = parseFloat($(`[data-award-input="${tid}"]`).value);
      if (isNaN(xe) || xe < 0) return say(amsg, `enter an amount in XE for ${tid}`, false);
      try { await api("POST", `/v1/team/tickets/${tid}/award`, { award_xe: Math.round(xe * 1e6) }); reload(); }
      catch (e) { say(amsg, `${tid}: ${e.message}`, false); }
    }));
    if ($("#adopt-all-awards")) $("#adopt-all-awards").addEventListener("click", async () => {
      const ids = $$("[data-adopt-award]:not([disabled])").map(b => parseInt(b.dataset.adoptAward, 10));
      if (!ids.length || !await ask({ title: `Set ${ids.length} awards from the proposed amounts?`, body: "Each amount is recorded against you in the log as set, not approved. Approve them one by one on the tickets when you have read the reasons.", ok: "Set all" })) return;
      try { await api("POST", "/v1/team/proposals/bulk", { adopt: ids }); reload(); } catch (e) { tell("Could not adopt", e.message); }
    });
  }
})();
