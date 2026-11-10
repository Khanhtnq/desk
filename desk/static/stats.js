// /stats: the figures count up, and the charts say what is under the pointer. The page is whole without
// this: the numbers are in the HTML, and every bar and cell carries its own <title>.
(() => {
  const root = document.querySelector(".stats");
  if (!root) return;

  if (!window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    for (const el of root.querySelectorAll(".st-kpi b[data-count]")) {
      const to = Number(el.dataset.count);
      if (!Number.isFinite(to) || to <= 0) continue;
      const started = performance.now();
      const frame = (now) => {
        const k = Math.min((now - started) / 900, 1);
        el.textContent = Math.round(to * (1 - Math.pow(1 - k, 3))).toLocaleString("en-GB");
        if (k < 1) requestAnimationFrame(frame);
      };
      requestAnimationFrame(frame);
    }
  }

  // one tooltip for everything that carries data-tip; the native ones would say it twice
  for (const t of root.querySelectorAll("svg title")) t.remove();
  const tip = document.createElement("div");
  tip.className = "st-tip";
  tip.hidden = true;
  document.body.append(tip);
  const hide = () => { tip.hidden = true; };
  const show = (e) => {
    const at = e.target instanceof Element ? e.target.closest("[data-tip]") : null;
    if (!at) return hide();
    tip.textContent = at.dataset.tip;
    tip.hidden = false;
    const half = tip.offsetWidth / 2 + 8;
    tip.style.left = `${Math.max(half, Math.min(e.clientX, window.innerWidth - half))}px`;
    tip.style.top = `${Math.max(e.clientY, tip.offsetHeight + 18)}px`;
  };
  root.addEventListener("pointermove", show);
  root.addEventListener("pointerdown", show);
  root.addEventListener("pointerleave", hide);
  window.addEventListener("scroll", hide, { passive: true });
})();
