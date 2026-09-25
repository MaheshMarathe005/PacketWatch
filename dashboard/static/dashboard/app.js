// PacketWatch dashboard — upload UX
(function () {
  "use strict";
  var form = document.getElementById("uploadForm");
  var input = document.getElementById("fileInput");
  var zone = document.getElementById("dropzone");
  var title = document.getElementById("dzTitle");
  var btn = document.getElementById("analyzeBtn");
  if (!form || !input || !zone) return;

  var defaultTitle = title ? title.textContent : "";

  function human(bytes) {
    var u = ["B", "KB", "MB", "GB"], i = 0;
    while (bytes >= 1024 && i < u.length - 1) { bytes /= 1024; i++; }
    return (i === 0 ? bytes : bytes.toFixed(1)) + " " + u[i];
  }

  function showFile(file) {
    if (!file) {
      zone.classList.remove("has-file");
      if (title) title.textContent = defaultTitle;
      return;
    }
    zone.classList.add("has-file");
    if (title) title.textContent = "📄 " + file.name + " · " + human(file.size);
  }

  input.addEventListener("change", function () {
    showFile(input.files && input.files[0]);
  });

  ["dragenter", "dragover"].forEach(function (ev) {
    zone.addEventListener(ev, function (e) {
      e.preventDefault(); e.stopPropagation();
      zone.classList.add("dragover");
    });
  });
  ["dragleave", "drop"].forEach(function (ev) {
    zone.addEventListener(ev, function (e) {
      e.preventDefault(); e.stopPropagation();
      zone.classList.remove("dragover");
    });
  });
  zone.addEventListener("drop", function (e) {
    var dt = e.dataTransfer;
    if (dt && dt.files && dt.files.length) {
      input.files = dt.files;
      showFile(dt.files[0]);
    }
  });

  form.addEventListener("submit", function (e) {
    if (!input.files || !input.files.length) {
      e.preventDefault();
      zone.classList.add("dragover");
      setTimeout(function () { zone.classList.remove("dragover"); }, 600);
      if (title) title.textContent = "⚠ Choose a capture file first";
      return;
    }
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Analysing capture…";
    }
  });

  // any demo/other form: show a working state on submit
  document.querySelectorAll("form.demo").forEach(function (f) {
    f.addEventListener("submit", function () {
      var b = f.querySelector("button[type=submit]");
      if (b) { b.disabled = true; b.textContent = "▶ Running demo…"; }
    });
  });
})();
