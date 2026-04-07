const passwordInput = document.getElementById("password");
const togglePasswordBtn = document.getElementById("togglePassword");
const analyzeBtn = document.getElementById("analyzeBtn");
const statusEl = document.getElementById("status");
const errorEl = document.getElementById("error");
const resultCard = document.getElementById("resultCard");
const scoreValueEl = document.getElementById("scoreValue");
const labelValueEl = document.getElementById("labelValue");
const strengthBar = document.getElementById("strengthBar");
const reasonsList = document.getElementById("reasonsList");
const suggestionsList = document.getElementById("suggestionsList");

function clearMessages() {
  statusEl.textContent = "";
  errorEl.textContent = "";
}

function clearResult() {
  resultCard.classList.add("hidden");
  scoreValueEl.textContent = "0";
  labelValueEl.textContent = "-";
  strengthBar.style.width = "0%";
  reasonsList.innerHTML = "";
  suggestionsList.innerHTML = "";
}

function setBarStyle(score) {
  if (score < 20) return "#dc2626";
  if (score < 40) return "#ea580c";
  if (score < 60) return "#d97706";
  if (score < 80) return "#0284c7";
  return "#16a34a";
}

function renderList(target, items, fallbackText) {
  target.innerHTML = "";
  if (!Array.isArray(items) || items.length === 0) {
    const li = document.createElement("li");
    li.textContent = fallbackText;
    target.appendChild(li);
    return;
  }

  for (const item of items) {
    const li = document.createElement("li");
    li.textContent = item;
    target.appendChild(li);
  }
}

function renderResult(data) {
  const score = Number(data.score || 0);
  scoreValueEl.textContent = String(score);
  labelValueEl.textContent = data.label || "-";
  strengthBar.style.width = `${Math.max(0, Math.min(100, score))}%`;
  strengthBar.style.background = setBarStyle(score);
  renderList(reasonsList, data.reasons, "No reasons returned.");
  renderList(
    suggestionsList,
    data.suggestions,
    "No suggestions. This password is already strong."
  );
  resultCard.classList.remove("hidden");
}

togglePasswordBtn.addEventListener("click", () => {
  const showing = passwordInput.type === "text";
  passwordInput.type = showing ? "password" : "text";
  togglePasswordBtn.textContent = showing ? "Show" : "Hide";
});

analyzeBtn.addEventListener("click", async () => {
  clearMessages();
  clearResult();

  const password = passwordInput.value;
  if (password.length === 0) {
    errorEl.textContent = "Please enter a password.";
    return;
  }

  analyzeBtn.disabled = true;
  analyzeBtn.textContent = "Analyzing...";
  statusEl.textContent = "Analyzing password strength...";

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password }),
    });

    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail =
        typeof payload.detail === "string"
          ? payload.detail
          : "Unable to analyze password.";
      throw new Error(detail);
    }

    renderResult(payload);
    statusEl.textContent = "Analysis complete.";
  } catch (error) {
    errorEl.textContent =
      error instanceof Error ? error.message : "Request failed.";
  } finally {
    analyzeBtn.disabled = false;
    analyzeBtn.textContent = "Analyze";
  }
});
