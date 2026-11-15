/* LINKBREAK frontend — plain JS, no framework. */

(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };

  /* ---------- theme ---------- */
  var root = document.documentElement;
  var savedTheme = null;
  try { savedTheme = localStorage.getItem("linkbreak-theme"); } catch (e) {}
  if (savedTheme) {
    root.setAttribute("data-theme", savedTheme);
  } else if (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches) {
    root.setAttribute("data-theme", "light");
  }
  function syncThemeButton() {
    $("themeToggle").textContent =
      root.getAttribute("data-theme") === "light" ? "🌙" : "☀️";
  }
  syncThemeButton();
  $("themeToggle").addEventListener("click", function () {
    var next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
    root.setAttribute("data-theme", next);
    try { localStorage.setItem("linkbreak-theme", next); } catch (e) {}
    syncThemeButton();
  });

  /* ---------- tabs ---------- */
  var tabs = Array.prototype.slice.call(document.querySelectorAll(".tab"));
  tabs.forEach(function (tab) {
    tab.addEventListener("click", function () {
      tabs.forEach(function (t) {
        t.classList.toggle("active", t === tab);
        t.setAttribute("aria-selected", t === tab ? "true" : "false");
      });
      document.querySelectorAll(".panel").forEach(function (panel) {
        panel.classList.toggle("active", panel.id === "tab-" + tab.dataset.tab);
      });
      if (tab.dataset.tab === "history") loadHistory();
    });
  });

  /* ---------- helpers ---------- */
  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  function badgeClass(status) {
    switch (status) {
      case "Resolved": return "badge-resolved";
      case "Partially Resolved": return "badge-partial";
      case "Blocked": return "badge-blocked";
      case "Unsupported": return "badge-unsupported";
      default: return "badge-failed";
    }
  }

  function badge(status) {
    return '<span class="badge ' + badgeClass(status) + '">' + escapeHtml(status) + "</span>";
  }

  function copyText(text, button) {
    var done = function () {
      if (!button) return;
      var original = button.textContent;
      button.textContent = "Copied ✓";
      setTimeout(function () { button.textContent = original; }, 1500);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text); done(); });
    } else {
      fallbackCopy(text);
      done();
    }
  }

  function fallbackCopy(text) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); } catch (e) {}
    document.body.removeChild(ta);
  }

  async function postJson(path, payload) {
    var response = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    var data = await response.json().catch(function () { return {}; });
    if (!response.ok) {
      throw new Error(data.detail || ("Request failed: HTTP " + response.status));
    }
    return data;
  }

  /* ---------- single resolve ---------- */
  var lastSingleResult = null;

  $("resolveForm").addEventListener("submit", async function (event) {
    event.preventDefault();
    var url = $("urlInput").value.trim();
    if (!url) return;
    var btn = $("resolveBtn");
    btn.disabled = true;
    $("progress").classList.remove("hidden");
    $("singleResult").innerHTML = "";
    try {
      var result = await postJson("/api/resolve", { url: url });
      lastSingleResult = result;
      $("singleResult").innerHTML = resultCardHtml(result);
      wireResultCard($("singleResult"), result);
    } catch (err) {
      $("singleResult").innerHTML =
        '<div class="result-card"><p class="error-note">' + escapeHtml(err.message) + "</p></div>";
    } finally {
      $("progress").classList.add("hidden");
      btn.disabled = false;
    }
  });

  function resultCardHtml(r) {
    var finalDisplay = r.final_url
      ? '<h2><a href="' + escapeHtml(r.final_url) + '" target="_blank" rel="noopener noreferrer">' +
        escapeHtml(r.final_url) + "</a></h2>"
      : '<h2>No destination found</h2>';
    var html = '<div class="result-card">' + finalDisplay;
    html += '<div class="meta">' + badge(r.resolution_status);
    html += "<span>Provider: " + escapeHtml(r.detected_provider) + "</span>";
    if (r.http_status != null) html += "<span>HTTP " + r.http_status + "</span>";
    html += "<span>" + r.elapsed_ms + " ms</span></div>";
    if (r.error_message) {
      html += '<p class="error-note">' + escapeHtml(r.error_message) + "</p>";
    }
    // --- scam-safety panel: final domain first, before any click-through.
    if (r.final_domain) {
      html += '<div class="safety' + (r.brand_mismatch ? " safety-warn" : "") + '">';
      html += '<div class="safety-domain">Final domain: <strong>' + escapeHtml(r.final_domain) + "</strong></div>";
      if (r.brand_mismatch) {
        html += '<div class="safety-alert">⚠️ Brand mismatch — this short link looks like a brand link but lands on a different domain. Check carefully before clicking.</div>';
      } else if (r.domain_changed) {
        html += '<div class="safety-note">The final domain differs from the short link\u2019s domain — normal for shorteners, but verify it before clicking.</div>';
      }
      if (r.safety_notes && r.safety_notes.length) {
        html += '<ul class="safety-list">';
        r.safety_notes.forEach(function (note) {
          html += "<li>" + escapeHtml(note) + "</li>";
        });
        html += "</ul>";
      }
      html += "</div>";
    }
    if (r.canonical_url) {
      html += '<p class="hint">Canonical URL reported by the page' +
        (r.canonical_source ? " (" + escapeHtml(r.canonical_source) + ")" : "") + ": " +
        '<a href="' + escapeHtml(r.canonical_url) + '" target="_blank" rel="noopener noreferrer">' +
        escapeHtml(r.canonical_url) + "</a></p>";
    }
    if (r.final_url) {
      html += '<div class="actions">' +
        '<button type="button" class="btn-secondary" data-action="copy">Copy final URL</button>' +
        '<a class="btn-primary" href="' + escapeHtml(r.final_url) + '" target="_blank" rel="noopener noreferrer" style="text-decoration:none">Open destination ↗</a>' +
        "</div>";
    }
    if (r.redirect_chain && r.redirect_chain.length) {
      html += '<button type="button" class="chain-toggle" data-action="toggle-chain">Hide redirect chain ▴</button>';
      html += '<ol class="chain">';
      r.redirect_chain.forEach(function (hop, i) {
        var note = hop.note ? ' <span class="hop-note">' + escapeHtml(hop.note) + "</span>" : "";
        html += "<li><span class=\"hop-status\">" + (i + 1) + " · " + escapeHtml(hop.method || "HEAD") +
          " · HTTP " + hop.status + " · " + (hop.elapsed_ms || 0) + " ms</span><br>" +
          escapeHtml(hop.url) + note + "</li>";
      });
      html += "</ol>";
    }
    html += "</div>";
    return html;
  }

  function wireResultCard(container, result) {
    var copyBtn = container.querySelector('[data-action="copy"]');
    if (copyBtn) {
      copyBtn.addEventListener("click", function () { copyText(result.final_url, copyBtn); });
    }
    var toggle = container.querySelector('[data-action="toggle-chain"]');
    if (toggle) {
      toggle.addEventListener("click", function () {
        var chain = container.querySelector(".chain");
        var hidden = chain.classList.toggle("hidden");
        toggle.textContent = hidden
          ? "Show redirect chain (" + result.redirect_chain.length + " hops) ▾"
          : "Hide redirect chain ▴";
      });
    }
  }

  /* ---------- bulk ---------- */
  var lastBulkResults = [];

  $("bulkBtn").addEventListener("click", async function () {
    var urls = $("bulkInput").value.split(/\r?\n/).map(function (s) { return s.trim(); })
      .filter(function (s) { return s.length > 0; });
    var status = $("bulkStatus");
    if (!urls.length) { status.textContent = "Paste at least one URL."; return; }
    if (urls.length > 20) { status.textContent = "Max 20 URLs per batch — first 20 will be used."; urls = urls.slice(0, 20); }
    var btn = $("bulkBtn");
    btn.disabled = true;
    status.textContent = "Resolving " + urls.length + " URLs…";
    try {
      var results = await postJson("/api/batch-resolve", { urls: urls });
      lastBulkResults = results;
      renderBulkTable(results);
      $("exportCsvBtn").disabled = false;
      status.textContent = "Done: " + results.length + " resolved.";
    } catch (err) {
      status.textContent = err.message;
    } finally {
      btn.disabled = false;
    }
  });

  function renderBulkTable(results) {
    var table = $("bulkTable");
    var tbody = table.querySelector("tbody");
    tbody.innerHTML = "";
    results.forEach(function (r, i) {
      var tr = document.createElement("tr");
      var finalCell = r.final_url
        ? '<a href="' + escapeHtml(r.final_url) + '" target="_blank" rel="noopener noreferrer">' +
          escapeHtml(r.final_url) + "</a>"
        : "—";
      var copyBtn = r.final_url
        ? '<button type="button" class="copy-btn" data-final="' + escapeHtml(r.final_url) + '">Copy</button>'
        : "";
      tr.innerHTML = "<td>" + (i + 1) + "</td><td>" + escapeHtml(r.original_url) + "</td>" +
        "<td>" + escapeHtml(r.detected_provider) + "</td><td>" + badge(r.resolution_status) + "</td>" +
        "<td>" + finalCell + "</td><td>" + copyBtn + "</td>";
      tbody.appendChild(tr);
    });
    table.classList.remove("hidden");
    tbody.querySelectorAll(".copy-btn").forEach(function (b) {
      b.addEventListener("click", function () { copyText(b.dataset.final, b); });
    });
  }

  $("exportCsvBtn").addEventListener("click", function () {
    if (!lastBulkResults.length) return;
    var rows = [["original_url", "detected_provider", "final_url", "http_status", "resolution_status", "error_message", "elapsed_ms"]];
    lastBulkResults.forEach(function (r) {
      rows.push([r.original_url, r.detected_provider, r.final_url || "", r.http_status == null ? "" : r.http_status,
        r.resolution_status, r.error_message || "", r.elapsed_ms]);
    });
    var csv = rows.map(function (row) {
      return row.map(function (cell) {
        var s = String(cell);
        return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
      }).join(",");
    }).join("\n");
    var blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "linkbreak-results.csv";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  });

  /* ---------- history ---------- */
  async function loadHistory() {
    var tbody = document.querySelector("#historyTable tbody");
    try {
      var response = await fetch("/api/history");
      var entries = await response.json();
      tbody.innerHTML = "";
      $("historyEmpty").classList.toggle("hidden", entries.length > 0);
      entries.forEach(function (e) {
        var tr = document.createElement("tr");
        var when = e.created_at ? new Date(e.created_at * 1000).toLocaleString() : "—";
        var finalCell = e.final_url
          ? '<a href="' + escapeHtml(e.final_url) + '" target="_blank" rel="noopener noreferrer">' +
            escapeHtml(e.final_url) + "</a>"
          : "—";
        tr.innerHTML = "<td>" + escapeHtml(when) + "</td><td>" + escapeHtml(e.original_url) + "</td>" +
          "<td>" + badge(e.resolution_status || "Failed") + "</td><td>" + finalCell + "</td>";
        tbody.appendChild(tr);
      });
    } catch (err) {
      tbody.innerHTML = '<tr><td colspan="4">Could not load history: ' + escapeHtml(err.message) + "</td></tr>";
    }
  }

  $("refreshHistoryBtn").addEventListener("click", loadHistory);
  $("clearHistoryBtn").addEventListener("click", async function () {
    if (!window.confirm("Clear all stored resolution history?")) return;
    await fetch("/api/history", { method: "DELETE" });
    loadHistory();
  });
})();
