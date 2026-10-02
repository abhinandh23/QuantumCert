// Webcam QR scanner for the verify page.
//
// The laptop webcam is opened at HD resolution (more pixels per QR module = far more reliable reads).
// About 8 times a second the area around the viewfinder square is cropped at full camera resolution
// (every 3rd frame: the whole picture) and sent to the server, which decodes it with zxing-cpp.
// Works on http://localhost (a secure context); frames are never stored.
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const startBtn = $("scan-start"), stopBtn = $("scan-stop"), camSelect = $("scan-camera");
  const stage = $("scan-stage"), video = $("scan-video"), vf = $("viewfinder");
  const label = $("scan-label"), status = $("scan-status"), tips = $("scan-tips");
  if (!startBtn || !video) return;

  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d", { willReadFrequently: false });
  const MAX_SIDE = 1280;   // upload size cap per frame (px)
  const MARGIN = 1.3;      // crop a bit beyond the square so imperfect alignment still works
  let stream = null, running = false, session = 0;

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  function setStatus(msg, kind) { status.textContent = msg || ""; status.className = "scan-status" + (kind ? " " + kind : ""); }

  function stopCamera() {
    running = false;
    session++;
    if (stream) stream.getTracks().forEach((t) => t.stop());
    stream = null;
    video.srcObject = null;
  }

  function resetUi() {
    startBtn.hidden = false;
    stopBtn.hidden = true;
    stage.hidden = true;
    vf.classList.remove("found", "wrong");
  }

  async function listCameras(currentId) {
    const cams = (await navigator.mediaDevices.enumerateDevices()).filter((d) => d.kind === "videoinput");
    camSelect.innerHTML = "";
    cams.forEach((c, i) => {
      const o = document.createElement("option");
      o.value = c.deviceId;
      o.textContent = c.label || "Camera " + (i + 1);
      if (c.deviceId === currentId) o.selected = true;
      camSelect.appendChild(o);
    });
    camSelect.hidden = cams.length < 2;
  }

  async function start(deviceId) {
    stopCamera();
    if (!window.isSecureContext || !navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      setStatus("The camera only works on http://localhost or https:// — open this page via localhost.", "error");
      return;
    }
    setStatus("Starting camera…");
    const constraints = { width: { ideal: 1920 }, height: { ideal: 1080 } };
    if (deviceId) constraints.deviceId = { exact: deviceId };
    try {
      stream = await navigator.mediaDevices.getUserMedia({ video: constraints, audio: false });
    } catch (e) {
      const why = {
        NotAllowedError: "Camera permission was denied. Allow camera access for this site and try again.",
        NotFoundError: "No camera was found on this computer.",
        NotReadableError: "The camera is busy — close other apps using it (Zoom, Meet, Cheese…) and try again.",
        OverconstrainedError: "The selected camera is not available.",
      }[e.name];
      setStatus(why || "Could not start the camera: " + (e.message || e.name), "error");
      resetUi();
      return;
    }
    video.srcObject = stream;
    stage.hidden = false;
    startBtn.hidden = true;
    stopBtn.hidden = false;
    vf.classList.remove("found", "wrong");
    label.textContent = "Fit the QR code inside the square";
    tips.hidden = true;
    try { await video.play(); } catch (e) { /* autoplay attribute covers this */ }
    const track = stream.getVideoTracks()[0];
    const s = track.getSettings ? track.getSettings() : {};
    listCameras(s.deviceId).catch(() => {});
    setStatus("Scanning… (camera " + (s.width || video.videoWidth) + "×" + (s.height || video.videoHeight) + ")");
    running = true;
    loop(++session);
  }

  // Region of the native video frame under the on-screen viewfinder (video uses object-fit: cover,
  // and both are centred, so the CSS mirroring does not change the crop).
  function cropRect(full) {
    const vw = video.videoWidth, vh = video.videoHeight;
    if (full) return { sx: 0, sy: 0, sw: vw, sh: vh };
    const scale = Math.max(stage.clientWidth / vw, stage.clientHeight / vh);
    const vfr = vf.getBoundingClientRect(), str = stage.getBoundingClientRect();
    const side = Math.min((vfr.width / scale) * MARGIN, vw, vh);
    const cx = vw / 2 + ((vfr.left + vfr.width / 2) - (str.left + str.width / 2)) / scale;
    const cy = vh / 2 + ((vfr.top + vfr.height / 2) - (str.top + str.height / 2)) / scale;
    const sx = Math.max(0, Math.min(vw - side, cx - side / 2)), sy = Math.max(0, Math.min(vh - side, cy - side / 2));
    return { sx, sy, sw: side, sh: side };
  }

  function grab(full) {
    const { sx, sy, sw, sh } = cropRect(full);
    const k = Math.min(1, MAX_SIDE / Math.max(sw, sh));
    canvas.width = Math.round(sw * k);
    canvas.height = Math.round(sh * k);
    ctx.drawImage(video, sx, sy, sw, sh, 0, 0, canvas.width, canvas.height);
    return new Promise((resolve) => canvas.toBlob(resolve, "image/jpeg", 0.92));
  }

  async function loop(mySession) {
    const startedAt = Date.now();
    let frame = 0, failures = 0;
    while (running && mySession === session) {
      if (video.readyState < 2 || !video.videoWidth) { await sleep(100); continue; }
      frame++;
      const blob = await grab(frame % 3 === 0);
      if (!blob) { await sleep(100); continue; }
      let data;
      try {
        const r = await fetch("/verify/scan-frame", { method: "POST", headers: { "Content-Type": "image/jpeg" }, body: blob });
        data = await r.json();
        failures = 0;
      } catch (e) {
        if (++failures > 3) setStatus("Cannot reach the server — is it still running?", "error");
        await sleep(1000);
        continue;
      }
      if (!running || mySession !== session) return;
      if (data.found && data.redirect) {
        running = false;
        vf.classList.add("found");
        label.textContent = "QR code read ✓";
        setStatus("QR code read — verifying " + data.cert_id + "…", "ok");
        await sleep(450);
        stopCamera();
        window.location.assign(data.redirect);
        return;
      }
      if (data.found) {
        vf.classList.add("wrong");
        label.textContent = "Not a QuantumCert QR code";
        setStatus(data.message || "That QR code is not a QuantumCert certificate link.", "warn");
      } else if (vf.classList.contains("wrong")) {
        vf.classList.remove("wrong");
        label.textContent = "Fit the QR code inside the square";
      }
      if (tips.hidden && Date.now() - startedAt > 7000) tips.hidden = false;
      await sleep(60);
    }
  }

  startBtn.addEventListener("click", () => start(camSelect.value || undefined));
  stopBtn.addEventListener("click", () => { stopCamera(); resetUi(); setStatus("Scanner stopped."); });
  camSelect.addEventListener("change", () => start(camSelect.value));
  document.addEventListener("visibilitychange", () => {
    if (document.hidden && stream) { stopCamera(); resetUi(); setStatus("Scanner paused while the tab was hidden."); }
  });
  window.addEventListener("pagehide", stopCamera);
})();
