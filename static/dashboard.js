const $ = id => document.getElementById(id);

let latestGraph = null;
let latestItems = [];
let latestMode = "user";
let latestTarget = "user_001";
let overviewLoading = false;

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, ch => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[ch]);
}

async function readResponse(response) {
  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.detail || `Request failed (${response.status}).`);
  }

  return data;
}

function showMessage(message, isError = false) {
  $("message").textContent = message;
  $("message").classList.toggle("error-message", isError);
}

function setGraphStatus(message, ready = false) {
  $("graph-status").classList.toggle("ready", ready);
  $("graph-status").innerHTML =
    `<span class="status-dot"></span> ${escapeHTML(message)}`;
}

function showError(message) {
  showMessage(message, true);
  $("results").innerHTML =
    '<div class="empty-results">No findings to display. Check the target and database, then try again.</div>';

  $("results").dataset.items = "[]";
  latestItems = [];
  latestGraph = null;

  setGraphStatus("Query failed");
  renderGraph([]);
}

function severityClass(severity) {
  const value = String(severity || "").toUpperCase();

  if (value === "HIGH") return "high";
  if (value === "MEDIUM") return "medium";

  return "info";
}

function initials(name) {
  return String(name || "?")
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map(part => part[0])
    .join("")
    .toUpperCase();
}

function renderFinding(item) {
  const score = Math.max(
    0,
    Math.min(100, Number(item.risk_score ?? 0))
  );

  const severity = String(
    item.severity ?? item.alert?.severity ?? "INFO"
  ).toUpperCase();

  const level = severityClass(severity);
  const alert = item.alert;

  const alertText = alert
    ? `${escapeHTML(alert.id || "Alert")} · ${escapeHTML(alert.type || "Security alert")} · ${escapeHTML(alert.severity || "UNKNOWN")}`
    : "No linked alert returned";

  return `
    <article class="finding">
      <div class="finding-top">
        <div class="finding-identity">
          <span class="finding-avatar">${escapeHTML(initials(item.user || item.user_id))}</span>
          <div>
            <strong class="finding-name">${escapeHTML(item.user || "Unknown user")}</strong>
            <span class="finding-id">${escapeHTML(item.user_id || "Unknown ID")}</span>
          </div>
        </div>

        <div class="finding-risk">
          <div class="score ${level}">
            ${score}<span style="font-size:11px;color:var(--muted-2)">/100</span>
          </div>
          <span class="tag ${level}">${escapeHTML(severity)}</span>
        </div>
      </div>

      <div class="risk-track" aria-label="Risk score ${score} out of 100">
        <div class="risk-fill ${level}" style="width:${score}%"></div>
      </div>

      <div class="finding-details">
        <div class="detail-item">
          <span class="detail-label">Device</span>
          <span class="detail-value">${escapeHTML(item.device || "—")}</span>
        </div>
        <div class="detail-item">
          <span class="detail-label">IP address</span>
          <span class="detail-value">${escapeHTML(item.ip || "—")}</span>
        </div>
        <div class="detail-item">
          <span class="detail-label">IP reputation</span>
          <span class="detail-value">${escapeHTML(item.reputation || "Unknown")}</span>
        </div>
        <div class="detail-item">
          <span class="detail-label">Evidence type</span>
          <span class="detail-value">${alert ? "Linked security alert" : "Graph relationship"}</span>
        </div>
      </div>

      <div class="alert-line${alert ? "" : " neutral"}">
        <span class="alert-mark">${alert ? "!" : "i"}</span>
        <span>
          <strong>${alert ? "Linked alert" : "Alert status"}:</strong>
          ${alertText}
        </span>
      </div>

      ${item.reason
        ? `<p class="finding-reason">${escapeHTML(item.reason)}</p>`
        : ""}
    </article>`;
}

function buildGraphData(items, mode, target) {
  const nodes = [];
  const edges = [];
  const nodeMap = new Map();
  const edgeSet = new Set();

  function addNode(id, type, label, subtitle, suspicious = false, details = {}) {
    if (!id) return;

    if (nodeMap.has(id)) {
      const existing = nodeMap.get(id);
      existing.suspicious ||= suspicious;
      Object.assign(existing.details, details);
      return;
    }

    const node = {
      id,
      type,
      label: String(label || id),
      subtitle: String(subtitle || ""),
      suspicious,
      details: { ...details }
    };

    nodeMap.set(id, node);
    nodes.push(node);
  }

  function addEdge(from, to, suspicious = false) {
    if (!from || !to || from === to) return;

    const key = `${from}->${to}`;
    if (edgeSet.has(key)) return;

    edgeSet.add(key);
    edges.push({ from, to, suspicious });
  }

  items.forEach((item, index) => {
    const userValue = item.user_id || item.user || `unknown-${index}`;
    const deviceValue = item.device || `unknown-device-${index}`;
    const ipValue = item.ip || `unknown-ip-${index}`;

    const userId = `user:${userValue}`;
    const deviceId = `device:${deviceValue}`;
    const ipId = `ip:${ipValue}`;

    const isSuspicious =
      String(item.reputation || "").toLowerCase() === "suspicious";

    addNode(
      userId,
      "user",
      item.user || userValue,
      userValue,
      false,
      { User: item.user || userValue, "User ID": userValue }
    );

    addNode(
      deviceId,
      "device",
      deviceValue,
      "Device",
      false,
      { Device: deviceValue }
    );

    addNode(
      ipId,
      "ip",
      ipValue,
      item.reputation || "IP address",
      isSuspicious,
      { "IP address": ipValue, Reputation: item.reputation || "Unknown" }
    );

    addEdge(userId, deviceId);
    addEdge(deviceId, ipId, isSuspicious);

    if (item.alert && item.alert.id) {
      const alertId = `alert:${item.alert.id}`;
      const alertSeverity = String(item.alert.severity || "UNKNOWN").toUpperCase();

      addNode(
        alertId,
        "alert",
        item.alert.id,
        `${alertSeverity} · ${item.alert.type || "Alert"}`,
        alertSeverity === "HIGH",
        {
          "Alert ID": item.alert.id,
          Type: item.alert.type || "Security alert",
          Severity: alertSeverity
        }
      );

      addEdge(ipId, alertId, alertSeverity === "HIGH");
    }
  });

  if (
    mode === "ip" &&
    target &&
    !nodes.some(node => node.type === "ip" && node.label === target)
  ) {
    addNode(
      `ip:${target}`,
      "ip",
      target,
      "Queried IP",
      false,
      { "IP address": target, Note: "No matching evidence path was returned." }
    );
  }

  return { nodes, edges };
}

function nodeSymbol(type) {
  return ({
    user: "U",
    device: "D",
    ip: "IP",
    alert: "!"
  })[type] || "?";
}

function truncate(value, maxLength) {
  const text = String(value || "");
  return text.length > maxLength
    ? `${text.slice(0, maxLength - 1)}…`
    : text;
}

function renderGraph(items, mode = latestMode, target = latestTarget) {
  const canvas = $("graph-canvas");
  const graph = buildGraphData(items, mode, target);

  latestGraph = graph;

  if (!graph.nodes.length) {
    canvas.innerHTML = `
      <div class="graph-empty">
        <div class="empty-network" aria-hidden="true">
          <span></span><span></span><span></span><span></span><i></i>
        </div>
        <strong>Your graph starts here</strong>
        <p>Run an investigation to reveal connected users, devices, IPs and alerts.</p>
      </div>`;

    $("graph-count").textContent = "No nodes loaded";
    return;
  }

  const width = Math.max(520, canvas.clientWidth || 700);
  const height = Math.max(300, canvas.clientHeight || 350);
  const padX = 70;
  const usableWidth = width - padX * 2;
  const layers = ["user", "device", "ip", "alert"];
  const positions = new Map();

  layers.forEach((type, layerIndex) => {
    const group = graph.nodes.filter(node => node.type === type);

    group.forEach((node, index) => {
      const x = padX + usableWidth * layerIndex / (layers.length - 1);
      const y = height * (index + 1) / (group.length + 1);

      positions.set(node.id, { x, y });
    });
  });

  const nodeW = 124;
  const nodeH = 54;

  const edgeMarkup = graph.edges.map(edge => {
    const a = positions.get(edge.from);
    const b = positions.get(edge.to);

    if (!a || !b) return "";

    const startX = a.x + nodeW / 2 - 3;
    const endX = b.x - nodeW / 2 + 3;
    const midX = (startX + endX) / 2;

    return `
      <path
        class="graph-edge${edge.suspicious ? " suspicious-edge" : ""}"
        d="M ${startX} ${a.y} C ${midX} ${a.y}, ${midX} ${b.y}, ${endX} ${b.y}"
      >
        <title>Observed investigation relationship</title>
      </path>`;
  }).join("");

  const nodeMarkup = graph.nodes.map(node => {
    const position = positions.get(node.id);
    const x = position.x - nodeW / 2;
    const y = position.y - nodeH / 2;
    const cls = `node-${node.type}${node.suspicious ? " suspicious" : ""}`;

    return `
      <g
        class="graph-node ${cls}"
        data-node-id="${escapeHTML(node.id)}"
        transform="translate(${x},${y})"
        role="button"
        tabindex="0"
        aria-label="View details for ${escapeHTML(node.label)}"
        style="cursor:pointer"
      >
        <title>${escapeHTML(node.label)} — select to inspect</title>
        <rect x="0" y="0" width="${nodeW}" height="${nodeH}" rx="9"></rect>
        <text class="node-symbol" x="16" y="21">${nodeSymbol(node.type)}</text>
        <text class="node-title" x="30" y="21">${escapeHTML(truncate(node.label, 17))}</text>
        <text class="node-subtitle" x="12" y="40">${escapeHTML(truncate(node.subtitle, 20))}</text>
      </g>`;
  }).join("");

  canvas.innerHTML = `
    <svg
      viewBox="0 0 ${width} ${height}"
      role="img"
      aria-label="Investigation subgraph with ${graph.nodes.length} nodes and ${graph.edges.length} relationships"
      preserveAspectRatio="xMidYMid meet"
    >
      <defs>
        <marker id="edge-arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
          <path d="M0,0 L6,3 L0,6 Z" fill="#526d8e"></path>
        </marker>
      </defs>
      ${edgeMarkup}
      ${nodeMarkup}
    </svg>
    <div id="node-inspector" hidden></div>`;

  $("graph-count").textContent =
    `${graph.nodes.length} nodes · ${graph.edges.length} relationships`;
}

function showNodeDetails(nodeId) {
  if (!latestGraph) return;

  const node = latestGraph.nodes.find(item => item.id === nodeId);
  if (!node) return;

  const connectedIds = latestGraph.edges
    .filter(edge => edge.from === nodeId || edge.to === nodeId)
    .map(edge => edge.from === nodeId ? edge.to : edge.from);

  const connectedNodes = connectedIds
    .map(id => latestGraph.nodes.find(item => item.id === id))
    .filter(Boolean);

  const inspector = $("node-inspector");
  if (!inspector) return;

  const details = Object.entries(node.details || {})
    .map(([key, value]) => `
      <div style="margin-top:7px">
        <span style="color:var(--muted-2);font-size:10px">${escapeHTML(key)}</span>
        <div style="overflow-wrap:anywhere;font-size:12px">${escapeHTML(value)}</div>
      </div>`)
    .join("");

  const connectedMarkup = connectedNodes.length
    ? connectedNodes.map(related => `
        <button
          type="button"
          data-related-node="${escapeHTML(related.id)}"
          style="margin:5px 5px 0 0;padding:6px 8px;border:1px solid var(--border);border-radius:7px;background:var(--panel-raised);color:var(--text);cursor:pointer;font-size:10px"
        >${escapeHTML(related.label)}</button>`).join("")
    : '<span style="color:var(--muted);font-size:11px">No returned connections</span>';

  inspector.hidden = false;
  inspector.style.cssText = [
    "position:absolute",
    "z-index:5",
    "left:12px",
    "right:12px",
    "bottom:12px",
    "max-height:65%",
    "overflow:auto",
    "padding:14px",
    "border:1px solid var(--border)",
    "border-radius:12px",
    "background:rgba(14,22,37,.97)",
    "box-shadow:0 12px 35px rgba(0,0,0,.35)"
  ].join(";");

  inspector.innerHTML = `
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px">
      <div>
        <div style="color:var(--cyan);font-size:9px;font-weight:700;letter-spacing:1px">
          ${escapeHTML(node.type.toUpperCase())} NODE
        </div>
        <strong style="display:block;margin-top:4px;font-size:14px;overflow-wrap:anywhere">
          ${escapeHTML(node.label)}
        </strong>
        <div style="color:var(--muted);font-size:11px">${escapeHTML(node.subtitle)}</div>
      </div>
      <button id="close-node-inspector" type="button" aria-label="Close node details"
        style="border:1px solid var(--border);border-radius:7px;background:transparent;color:var(--text);padding:5px 9px;cursor:pointer">✕</button>
    </div>
    ${details}
    <div style="margin-top:12px">
      <div style="color:var(--muted-2);font-size:10px;font-weight:700;letter-spacing:.7px">
        CONNECTED NODES (${connectedNodes.length})
      </div>
      <div>${connectedMarkup}</div>
    </div>
    <p style="margin:10px 0 0;color:var(--muted-2);font-size:10px">
      Connections shown are from the current investigation results.
    </p>`;

  $("close-node-inspector").addEventListener("click", () => {
    inspector.hidden = true;
  });

  inspector.querySelectorAll("[data-related-node]").forEach(button => {
    button.addEventListener("click", () => {
      showNodeDetails(button.dataset.relatedNode);
    });
  });
}

function resetGraph() {
  const inspector = $("node-inspector");
  if (inspector) inspector.hidden = true;

  renderGraph(latestItems, latestMode, latestTarget);
}

async function investigate() {
  const mode = $("mode").value;
  const target = $("target").value.trim();

  if (!target) {
    showError("Please enter a user ID or IP address.");
    $("target").focus();
    return;
  }

  latestMode = mode;
  latestTarget = target;

  const button = $("investigate");
  button.disabled = true;
  button.innerHTML = '<span>Investigating graph…</span><span aria-hidden="true">◌</span>';

  showMessage("Querying graph relationships and evidence…");
  $("results").innerHTML = "";
  $("results").dataset.items = "[]";
  setGraphStatus("Querying graph");

  try {
    const endpoint = mode === "ip" ? "/investigate-ip/" : "/investigate/";
    const response = await fetch(endpoint + encodeURIComponent(target));
    const data = await readResponse(response);

    if (data.status !== "success") {
      showError(data.message || "No matching graph data found.");
      return;
    }

    const items = data.investigation || [];

    if (!items.length) {
      latestItems = [];
      showError("No investigation findings were returned.");
      return;
    }

    latestItems = items;
    $("results").dataset.items = JSON.stringify(items);
    $("results").innerHTML = items.map(renderFinding).join("");

    renderGraph(items, mode, target);

    if (mode === "ip") {
      const count = data.connected_users ??
        new Set(items.map(item => item.user_id)).size;

      showMessage(
        `${count} connected user(s) · ${data.summary?.evidence_paths ?? items.length} evidence path(s)`
      );
    } else {
      showMessage(`${items.length} finding(s) returned for ${target}`);
    }

    setGraphStatus("Graph loaded", true);
  } catch (error) {
    showError(error.message || "Could not connect to the API.");
  } finally {
    button.disabled = false;
    button.innerHTML = '<span>Run investigation</span><span aria-hidden="true">↗</span>';
  }
}

function sample(userId) {
  $("mode").value = "user";
  $("target").value = userId;
  updateTargetPrefix();
  investigate();
}

async function seedData() {
  const button = $("seed");
  button.disabled = true;
  button.innerHTML = '<span>◌</span> Loading demo dataset…';

  showMessage("Loading synthetic demo dataset…");

  try {
    const response = await fetch("/seed-dataset", { method: "POST" });
    await readResponse(response);

    await loadOverview();
    showMessage("Demo dataset loaded. Running selected investigation…");
    await investigate();
  } catch (error) {
    showError(error.message || "Could not load dataset.");
  } finally {
    button.disabled = false;
    button.innerHTML = '<span aria-hidden="true">＋</span> Load / refresh demo dataset';
  }
}

async function loadOverview() {
  if (overviewLoading) return;
  overviewLoading = true;

  try {
    const statsResponse = await fetch("/graph-stats");
    const stats = await readResponse(statsResponse);

    if (stats.status !== "success") {
      throw new Error(stats.message || "Graph statistics unavailable.");
    }

    const labels = stats.nodes_by_label || {};

    // These are counts from FalkorDB, not counts inferred from the UI.
    $("users").textContent = labels.User ?? "—";
    $("devices").textContent = labels.Device ?? "—";
    $("alerts").textContent = labels.Alert ?? "—";

    // The current graph-stats endpoint does not expose IP reputation counts.
    // Estimate suspicious IPs from the three seeded demo-user investigations.
    const responses = await Promise.all(
      ["user_001", "user_002", "user_003"].map(async userId => {
        const response = await fetch(`/investigate/${encodeURIComponent(userId)}`);
        return readResponse(response);
      })
    );

    const findings = responses.flatMap(data =>
      data.status === "success" ? (data.investigation || []) : []
    );

    const suspiciousIPs = new Set(
      findings
        .filter(item => String(item.reputation || "").toLowerCase() === "suspicious")
        .map(item => item.ip)
        .filter(Boolean)
    );

    $("ips").textContent = suspiciousIPs.size;

  } catch (error) {
    showMessage(
      `Could not load all overview metrics: ${error.message}`,
      true
    );
  } finally {
    overviewLoading = false;
  }
}

function updateTargetPrefix() {
  const isIP = $("mode").value === "ip";

  $("target-prefix").textContent = isIP ? "IP" : "ID";
  $("target").placeholder = isIP
    ? "e.g. 203.0.113.42"
    : "e.g. user_001";
}

async function refreshDashboard() {
  const button = $("refresh");
  button.disabled = true;

  try {
    await loadOverview();
    await investigate();
  } finally {
    button.disabled = false;
  }
}

// Event delegation: works after the SVG is re-rendered.
$("graph-canvas").addEventListener("click", event => {
  const node = event.target.closest("[data-node-id]");

  if (node) {
    showNodeDetails(node.dataset.nodeId);
  }
});

$("graph-canvas").addEventListener("keydown", event => {
  const node = event.target.closest("[data-node-id]");

  if (node && (event.key === "Enter" || event.key === " ")) {
    event.preventDefault();
    showNodeDetails(node.dataset.nodeId);
  }
});

$("investigation-form").addEventListener("submit", event => {
  event.preventDefault();
  investigate();
});

$("mode").addEventListener("change", () => {
  $("target").value = $("mode").value === "ip"
    ? "203.0.113.42"
    : "user_001";

  updateTargetPrefix();
});

let resizeFrame = null;

window.addEventListener("resize", () => {
  if (resizeFrame !== null) cancelAnimationFrame(resizeFrame);

  resizeFrame = requestAnimationFrame(() => {
    resizeFrame = null;

    if (latestItems.length) {
      renderGraph(latestItems, latestMode, latestTarget);
    }
  });
});

loadOverview();
updateTargetPrefix();
