// Verify page: show only the method named in the URL hash (#pdf, #scan, #id); no hash means #pdf.
// The hash never reaches the server, so this has to happen in the browser. Without JavaScript all
// three methods stay visible.
(function () {
  "use strict";
  const panels = document.querySelectorAll("[data-panel]");
  const tabs = document.querySelectorAll("[data-tab]");
  if (!panels.length) return;
  const names = Array.from(panels, (p) => p.dataset.panel);

  function show() {
    const want = location.hash.slice(1);
    const name = names.includes(want) ? want : "pdf";
    // leaving the scanner: switch the webcam off rather than leave it running behind a hidden panel
    const stop = document.getElementById("scan-stop");
    if (name !== "scan" && stop && !stop.hidden) stop.click();
    panels.forEach((p) => { p.hidden = p.dataset.panel !== name; });
    tabs.forEach((t) => {
      if (t.dataset.tab === name) t.setAttribute("aria-current", "true");
      else t.removeAttribute("aria-current");
    });
  }

  window.addEventListener("hashchange", show);
  show();
})();
