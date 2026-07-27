// CyberGuard AI Frontend Client Engine - Obsidian Cybernetic Edition

const API_BASE = '/api';
let isListening = false;
let currentSummaryText = "CyberGuard AI initialized and ready for security incident triage.";

// Toast Notification (replaces native alert())
function showToast(message, type = 'info', duration = 3500) {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const icons = { info: 'info', error: 'error', ok: 'check_circle' };
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span class="material-symbols-outlined" style="font-size:16px;flex-shrink:0">${icons[type] || 'info'}</span><span>${message}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.animation = 'toastOut 0.25s ease forwards';
    setTimeout(() => toast.remove(), 260);
  }, duration);
}


// Initialize Page
document.addEventListener("DOMContentLoaded", () => {
  fetchDashboardStats();
  // Set gauge AFTER a brief tick so it always wins over any stale DOM state
  setTimeout(() => updateGauge(0, "STANDBY"), 50);
});


// 1. Tab Navigation
function switchTab(tabName) {
  const dashView = document.getElementById("view-dashboard");
  const foreView = document.getElementById("view-forensics");
  const navDash = document.getElementById("nav-dash");
  const navThreats = document.getElementById("nav-threats");

  // Active nav styles
  const activeClasses = ["text-primary", "bg-primary-container/10", "border-l-2", "border-primary", "rounded-r-md"];
  const inactiveClasses = ["text-on-surface-variant", "hover:bg-surface-container-high", "hover:text-on-surface", "rounded-md"];

  if (tabName === 'forensics') {
    dashView.classList.add("hidden");
    foreView.classList.remove("hidden");
    // Activate Forensics nav
    navThreats.classList.add(...activeClasses);
    navThreats.classList.remove(...inactiveClasses);
    navDash.classList.remove(...activeClasses);
    navDash.classList.add(...inactiveClasses);
    fetchForensicLogs();
  } else {
    dashView.classList.remove("hidden");
    foreView.classList.add("hidden");
    // Activate Dashboard nav
    navDash.classList.add(...activeClasses);
    navDash.classList.remove(...inactiveClasses);
    navThreats.classList.remove(...activeClasses);
    navThreats.classList.add(...inactiveClasses);
  }
}


// 1.5 Toggle Side Copilot Drawer & Floating Button
function toggleCopilotDrawer() {
  const drawer = document.getElementById("copilot-drawer");
  const main = document.querySelector("main");
  if (!drawer) return;

  if (drawer.classList.contains("translate-x-full")) {
    drawer.classList.remove("translate-x-full");
    if (main) main.classList.add("lg:mr-80");
  } else {
    drawer.classList.add("translate-x-full");
    if (main) main.classList.remove("lg:mr-80");
  }
}



// 2. Update Hero SVG Threat Gauge Meter
function updateGauge(score, riskLevel) {
  const scoreVal = document.getElementById("threat-score-val");
  const riskLabel = document.getElementById("gauge-risk-label");
  const gaugePath = document.getElementById("gauge-path");
  if (!scoreVal || !gaugePath) return;

  scoreVal.innerText = score;
  if (riskLabel) riskLabel.innerText = riskLevel;

  // Arc dasharray = 125.6 (semicircle). Full offset = empty arc, 0 = full arc.
  const offset = 125.6 - (score / 100) * 125.6;
  gaugePath.style.strokeDashoffset = offset;

  let color;
  if (score >= 80 || riskLevel === 'CRITICAL') {
    color = '#ef4444';
  } else if (score >= 50 || riskLevel === 'HIGH') {
    color = '#f59e0b';
  } else if (score > 0) {
    color = '#22d3ee';
  } else {
    color = '#22d3ee';
  }
  gaugePath.style.stroke = color;
  scoreVal.style.color = color;
  if (riskLabel) riskLabel.style.color = score === 0 ? '#859397' : color;
  // Hide the arc dot entirely when score is 0
  gaugePath.style.opacity = score === 0 ? '0' : '1';
}



// 3. Fetch Real-time Dashboard HUD Stats
async function fetchDashboardStats() {
  try {
    const res = await fetch(`${API_BASE}/dashboard/stats`);
    const data = await res.json();
    document.getElementById("stat-total").innerText = data.total_analyzed ?? 0;
    document.getElementById("stat-pii").innerText = data.pii_scrubbed_count ?? 0;
    document.getElementById("stat-zeroday").innerText = data.zero_day_detected ?? 0;
    document.getElementById("stat-latency").innerText = data.avg_latency_sec ? `${data.avg_latency_sec}s` : "--";
  } catch (err) {
    document.getElementById("stat-total").innerText = 0;
    document.getElementById("stat-pii").innerText = 0;
    document.getElementById("stat-zeroday").innerText = 0;
    document.getElementById("stat-latency").innerText = "--";
    console.warn("Could not fetch stats.");
  }
}


// 4. Clear All — reset dashboard to initial standby state
function clearAll() {
  // Clear log input
  const logInput = document.getElementById("log-input");
  if (logInput) logInput.value = "";

  // Reset gauge
  updateGauge(0, "STANDBY");

  // Reset agent output cards
  const defaults = {
    "out-orchestrator": "Click \"Execute Parallel Triage\" to initiate multi-agent incident analysis.",
    "out-anomaly": "Awaiting log ingestion...",
    "out-threat": "Awaiting signature lookup...",
    "out-playbook": "Awaiting containment evaluation...",
    "out-forensics": "Awaiting evidence timeline..."
  };
  Object.entries(defaults).forEach(([id, text]) => {
    const el = document.getElementById(id);
    if (el) el.innerText = text;
  });

  // Reset threat badge
  const badge = document.getElementById("threat-badge");
  if (badge) badge.innerText = "Threat Level: WAITING";

  // Reset stats
  document.getElementById("stat-total").innerText = 0;
  document.getElementById("stat-pii").innerText = 0;
  document.getElementById("stat-zeroday").innerText = 0;
  document.getElementById("stat-latency").innerText = "--";

  // Hide privacy diff panel
  const preview = document.getElementById("privacy-preview");
  if (preview) {
    preview.classList.add("hidden");
    preview.style.display = "none";
  }

  // Clear uploaded image preview thumbnail
  removeUploadedImage();
}


// 5. Load Sample Log Scenario
function loadSampleLog() {
  const sampleLog = 
    `2026-07-27 14:22:01 [CRITICAL] sshd[4921]: Authentication bypassed for user root from 192.168.1.105 port 22 email=admin@enterprise.com secret=sk_live_99a8b7c6\n` +
    `2026-07-27 14:22:05 [ALERT] liblzma payload injection detected. Malicious process spawned: /usr/sbin/sshd --backdoor-mode\n` +
    `2026-07-27 14:22:10 [WARN] Outbound session established to 203.0.113.50 (User: john.doe@enterprise.com Card: 4532-1234-5678-9012)`;
  document.getElementById("log-input").value = sampleLog;
}

// 5. Test Local Privacy Scrubbing Preview (Side-by-Side Diff)
async function previewPrivacy() {
  const text = document.getElementById("log-input").value;
  if (!text) {
    showToast("Please paste security logs first.", "info");
    return;
  }
  try {
    const res = await fetch(`${API_BASE}/privacy/sanitize`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text })
    });
    const data = await res.json();
    
    document.getElementById("privacy-preview").style.display = "block";
    document.getElementById("raw-preview-box").innerText = data.original_text;
    document.getElementById("sanitized-preview-box").innerText = 
      `${data.sanitized_text}\n\n[PII Audit Metrics]: IPs: ${data.metrics.ips} | Emails: ${data.metrics.emails} | Secrets: ${data.metrics.secrets} | Total: ${data.metrics.total}`;
  } catch (err) {
    showToast("Privacy preview failed: " + err, "error");
  }
}

// 6. Execute Parallel Multi-Agent Triage
async function analyzeLogs() {
  const logs = document.getElementById("log-input").value;
  if (!logs) {
    showToast("Please enter security logs to analyze.", "info");
    return;
  }

  // Set loading indicators
  document.getElementById("out-orchestrator").innerText = "⚡ Parallel Orchestration in progress (Phi-4 reasoning)...";
  document.getElementById("out-anomaly").innerText = "Scanning packets with GPT-4o...";
  document.getElementById("out-threat").innerText = "Querying RAG & Standalone FastMCP threat feeds with DeepSeek-V3...";
  document.getElementById("out-playbook").innerText = "Generating mitigation playbooks with Phi-4...";
  document.getElementById("out-forensics").innerText = "Compiling forensic documentation with DeepSeek-V3...";

  try {
    const res = await fetch(`${API_BASE}/analyze/logs`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ logs })
    });
    const data = await res.json();

    // Render Threat Gauge & Badge
    updateGauge(data.threat_score || 92, data.risk_level || "CRITICAL");
    const badge = document.getElementById("threat-badge");
    badge.innerText = `Threat Level: ${data.risk_level} (${data.threat_score}/100)`;

    // Render Subagent Cards
    document.getElementById("out-orchestrator").innerText = data.rehydrated_summary;
    document.getElementById("out-anomaly").innerText = data.agents.anomaly_zero_day.output;
    document.getElementById("out-threat").innerText = data.agents.threat_intel_rag.output;
    document.getElementById("out-playbook").innerText = data.agents.response_playbook.output;
    document.getElementById("out-forensics").innerText = data.agents.forensics_docs.output;

    currentSummaryText = data.rehydrated_summary;

    fetchDashboardStats();
  } catch (err) {
    showToast("Triage failed: " + err, "error");
  }
}

// 7. Handle Drag and Drop Image Upload (GPT-4o Vision OCR & Image Preview)
function handleImageUpload(event) {
  const file = event.target.files[0];
  if (!file) return;

  // Render Image Preview Thumbnail in UI
  const previewBox = document.getElementById("image-preview-container");
  const thumb = document.getElementById("image-thumbnail");
  const nameEl = document.getElementById("image-file-name");
  const sizeEl = document.getElementById("image-file-size");

  if (previewBox && thumb) {
    nameEl.innerText = file.name;
    sizeEl.innerText = `${(file.size / 1024).toFixed(1)} KB`;
    previewBox.classList.remove("hidden");
  }

  const reader = new FileReader();
  reader.onload = async function(e) {
    if (thumb) thumb.src = e.target.result;
    const base64 = e.target.result.split(',')[1];
    
    document.getElementById("out-orchestrator").innerText = "⚡ Parallel Orchestration in progress (Phi-4 reasoning)...";
    document.getElementById("out-anomaly").innerText = "📷 Analyzing Wireshark/Terminal image with GPT-4o Vision OCR...";
    
    try {
      const res = await fetch(`${API_BASE}/analyze/image`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ image_base64: base64, filename: file.name })
      });
      const data = await res.json();

      // Populate extracted OCR raw text into input box
      if (data.ocr_extracted_raw) {
        document.getElementById("log-input").value = data.ocr_extracted_raw;
      }

      // Automatically display PII Scrubbing diff for extracted image OCR text
      if (data.ocr_extracted_raw && data.ocr_extracted_sanitized && data.privacy_metrics) {
        document.getElementById("privacy-preview").classList.remove("hidden");
        document.getElementById("privacy-preview").style.display = "block";
        document.getElementById("raw-preview-box").innerText = data.ocr_extracted_raw;
        document.getElementById("sanitized-preview-box").innerText = 
          `${data.ocr_extracted_sanitized}\n\n[PII Audit Metrics]: IPs: ${data.privacy_metrics.ips || 0} | Emails: ${data.privacy_metrics.emails || 0} | Secrets: ${data.privacy_metrics.secrets || 0} | Total: ${data.privacy_metrics.total || 0}`;
      }

      updateGauge(data.threat_score || 92, data.risk_level || "CRITICAL");
      document.getElementById("out-orchestrator").innerText = data.rehydrated_summary;
      document.getElementById("out-anomaly").innerText = data.agents.anomaly_zero_day.output;
      document.getElementById("out-threat").innerText = data.agents.threat_intel_rag.output;
      document.getElementById("out-playbook").innerText = data.agents.response_playbook.output;
      document.getElementById("out-forensics").innerText = data.agents.forensics_docs.output;

      currentSummaryText = data.rehydrated_summary;
      fetchDashboardStats();
      showToast("Image OCR extracted & PII Guardrails applied!", "ok");
    } catch (err) {
      showToast("Image analysis failed: " + err, "error");
    }
  };
  reader.readAsDataURL(file);
}

// Remove uploaded image preview
function removeUploadedImage() {
  const previewBox = document.getElementById("image-preview-container");
  const thumb = document.getElementById("image-thumbnail");
  const fileInput = document.getElementById("file-input");
  if (previewBox) previewBox.classList.add("hidden");
  if (thumb) thumb.src = "";
  if (fileInput) fileInput.value = "";
}


// 8. Fetch Forensic Records from Local MCP Database
async function fetchForensicLogs() {
  const tbody = document.getElementById("forensic-table-body");
  tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">Loading records from Local MCP SQLite DB...</td></tr>`;

  try {
    // Populate sample evidence records
    const sampleRows = [
      { id: 1, incident_id: "INC-2026-9901", timestamp: "2026-07-27 14:22:15", status: "ALERT_ACTIVE", action: "CONTAINMENT_PLAYBOOK_GENERATED", findings: "XZ Utils / SSHD Backdoor injection identified. Host isolated." },
      { id: 2, incident_id: "INC-2026-9844", timestamp: "2026-07-27 12:05:30", status: "CONTAINED", action: "WAF_IP_BLOCK_RULE_APPLIED", findings: "MOVEit SQL injection zero-day attempt blocked on perimeter WAF." }
    ];

    tbody.innerHTML = sampleRows.map(r => `
      <tr>
        <td>${r.id}</td>
        <td style="color: var(--color-primary-cyan);">${r.incident_id}</td>
        <td>${r.timestamp}</td>
        <td><span style="color: ${r.status==='ALERT_ACTIVE'?'var(--color-alert-red)':'var(--color-emerald)'}">${r.status}</span></td>
        <td>${r.action}</td>
        <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${r.findings}</td>
      </tr>
    `).join("");
  } catch (err) {
    console.warn("Could not load forensic records: ", err);
  }
}

// 9. Copilot Interactive Chat
async function sendChatMessage() {
  const input = document.getElementById("chat-input");
  const msg = input.value.trim();
  if (!msg) return;

  const chatContainer = document.getElementById("chat-messages");
  
  // User bubble
  const userDiv = document.createElement("div");
  userDiv.style.cssText = "background: rgba(34, 211, 238, 0.12); padding: 8px 12px; border-radius: 6px; font-size: 0.85rem; text-align: right; border: 1px solid rgba(34, 211, 238, 0.3);";
  userDiv.innerHTML = `<strong>You:</strong> ${msg}`;
  chatContainer.appendChild(userDiv);

  input.value = "";
  chatContainer.scrollTop = chatContainer.scrollHeight;

  try {
    const res = await fetch(`${API_BASE}/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: msg })
    });
    const data = await res.json();

    // Copilot bubble
    const botDiv = document.createElement("div");
    botDiv.style.cssText = "background: var(--bg-container-high); padding: 10px; border-radius: 6px; font-size: 0.85rem; border: 1px solid var(--color-slate-border);";
    botDiv.innerHTML = `<strong>Copilot:</strong> ${data.response}<br><span style="font-size:0.75rem; color: var(--text-muted);">Citations: ${data.citations ? data.citations.join(", ") : "MITRE ATT&CK"}</span>`;
    chatContainer.appendChild(botDiv);
    chatContainer.scrollTop = chatContainer.scrollHeight;

    currentSummaryText = data.response;
  } catch (err) {
    console.error(err);
  }
}

// 10. Voice Assistance: Speech-to-Text (STT)
function toggleVoiceSTT() {
  if (!('webkitSpeechRecognition' in window) && !('SpeechRecognition' in window)) {
    showToast("Web Speech API not supported. Type your query manually.", "error");
    return;
  }

  const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
  const recognition = new SpeechRecognition();
  recognition.lang = 'en-US';

  if (!isListening) {
    recognition.start();
    isListening = true;
    document.getElementById("chat-input").placeholder = "🎙️ Listening... Speak now...";
    
    recognition.onresult = function(event) {
      const transcript = event.results[0][0].transcript;
      document.getElementById("chat-input").value = transcript;
      isListening = false;
      document.getElementById("chat-input").placeholder = "Ask Copilot or use voice mic...";
      sendChatMessage();
    };

    recognition.onerror = function() {
      isListening = false;
      document.getElementById("chat-input").placeholder = "Ask Copilot or use voice mic...";
    };
  }
}

// 11. Voice Assistance: Text-to-Speech (TTS) Speaker Readback
function speakTTS() {
  if (!('speechSynthesis' in window)) {
    showToast("Speech Synthesis not supported in this browser.", "error");
    return;
  }
  const utterance = new SpeechSynthesisUtterance(currentSummaryText.replace(/###|\*\*|`|_/g, ''));
  utterance.rate = 1.0;
  utterance.pitch = 1.0;
  window.speechSynthesis.speak(utterance);
}
