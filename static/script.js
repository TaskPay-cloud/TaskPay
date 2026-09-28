// --- Countdown to month end (payout day) ---
function getMonthEnd() {
    const now = new Date();
    // Last moment of the current month, in the user's local time.
    return new Date(now.getFullYear(), now.getMonth() + 1, 1, 0, 0, 0) - 1;
}

function tickCountdown() {
    const el = document.getElementById("countdown");
    if (!el) return;

    const target = getMonthEnd();
    const diff = target - Date.now();

    if (diff <= 0) {
        el.textContent = "Payout day is here!";
        return;
    }

    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
    const hours = Math.floor((diff / (1000 * 60 * 60)) % 24);
    const minutes = Math.floor((diff / (1000 * 60)) % 60);
    const seconds = Math.floor((diff / 1000) % 60);

    el.textContent = `${days}d ${hours}h ${minutes}m ${seconds}s`;
}

if (document.getElementById("countdown")) {
    tickCountdown();
    setInterval(tickCountdown, 1000);
}

// --- Countdown to a fixed target date (e.g. public launch day) ---
function tickFixedCountdown(elId) {
    const el = document.getElementById(elId);
    if (!el) return;

    const target = new Date(el.dataset.target).getTime();
    const diff = target - Date.now();

    if (isNaN(target)) {
        el.textContent = "";
        return;
    }

    if (diff <= 0) {
        el.textContent = "It's here!";
        return;
    }

    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
    const hours = Math.floor((diff / (1000 * 60 * 60)) % 24);
    const minutes = Math.floor((diff / (1000 * 60)) % 60);
    const seconds = Math.floor((diff / 1000) % 60);

    el.textContent = `${days}d ${hours}h ${minutes}m ${seconds}s`;
}

if (document.getElementById("launch-countdown")) {
    tickFixedCountdown("launch-countdown");
    setInterval(() => tickFixedCountdown("launch-countdown"), 1000);
}

// --- Tabs (dashboard) ---
function initTabs() {
    const buttons = document.querySelectorAll(".tab-btn");
    if (!buttons.length) return;

    buttons.forEach((btn) => {
        btn.addEventListener("click", () => {
            const target = btn.dataset.tab;

            document.querySelectorAll(".tab-btn").forEach((b) => {
                b.classList.remove("active");
                b.setAttribute("aria-selected", "false");
            });
            btn.classList.add("active");
            btn.setAttribute("aria-selected", "true");

            document.querySelectorAll(".tab-panel").forEach((panel) => {
                panel.classList.toggle("active", panel.id === `tab-${target}`);
            });

            if (history.replaceState) {
                history.replaceState(null, "", `#${target}`);
            }
        });
    });

    const hash = window.location.hash.replace("#", "");
    const match = document.querySelector(`.tab-btn[data-tab="${hash}"]`);
    if (match) match.click();
}
document.addEventListener("DOMContentLoaded", initTabs);

// --- User: resend confirmation email ---
async function resendConfirmation() {
    try {
        const res = await fetch("/resend-confirmation", { method: "POST" });
        const data = await res.json();
        alert(data.message || (data.ok ? "Sent." : "Could not send."));
    } catch (err) {
        alert("Network error. Please try again.");
    }
}

// --- User: complete a task ---
async function completeTask(taskId) {
    try {
        const res = await fetch(`/api/tasks/${taskId}/complete`, { method: "POST" });
        const data = await res.json();

        if (!data.ok) {
            alert(data.error || "Could not complete task.");
            return;
        }

        const card = document.getElementById(`task-${taskId}`);
        if (card) {
            const btn = card.querySelector("button");
            if (btn) {
                btn.textContent = "Completed";
                btn.disabled = true;
            }
        }

        window.location.reload();
    } catch (err) {
        alert("Network error. Please try again.");
    }
}

// --- Admin: toggle a task active/inactive ---
async function toggleTask(taskId) {
    try {
        const res = await fetch(`/api/admin/tasks/${taskId}/toggle`, { method: "POST" });
        const data = await res.json();
        if (!data.ok) {
            alert(data.error || "Could not update task.");
            return;
        }
        window.location.reload();
    } catch (err) {
        alert("Network error. Please try again.");
    }
}

// --- Live currency conversion ---
// Every amount on the page is a <span class="money" data-usd=".." data-cur="..">.
// This polls /api/rates and re-renders them, so balances follow the live
// exchange rate (naira / CFA / dollar) without a reload.
const CURRENCY_FORMAT = {
    NGN: { symbol: "\u20A6", decimals: 2 },
    XOF: { symbol: "CFA ", decimals: 0 },
    USD: { symbol: "$", decimals: 2 },
};

function renderMoney(rates) {
    document.querySelectorAll(".money[data-usd]").forEach((el) => {
        const cur = el.dataset.cur;
        const fmt = CURRENCY_FORMAT[cur];
        const rate = rates[cur];
        if (!fmt || !rate) return;
        const value = parseFloat(el.dataset.usd) * rate;
        el.textContent = fmt.symbol + value.toLocaleString(undefined, {
            minimumFractionDigits: fmt.decimals,
            maximumFractionDigits: fmt.decimals,
        });
    });

    const line = document.getElementById("rate-line");
    if (line) {
        line.textContent =
            `1 USD = \u20A6${Math.round(rates.NGN).toLocaleString()} = CFA ${Math.round(rates.XOF).toLocaleString()}`;
    }
}

async function refreshRates() {
    if (!document.querySelector(".money[data-usd]")) return;
    try {
        const res = await fetch("/api/rates");
        const data = await res.json();
        if (data.ok && data.rates) renderMoney(data.rates);
    } catch (err) {
        /* keep the server-rendered amounts if the feed is unreachable */
    }
}

document.addEventListener("DOMContentLoaded", () => {
    refreshRates();
    setInterval(refreshRates, 60000);
});
