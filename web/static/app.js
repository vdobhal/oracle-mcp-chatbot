const logEl = document.getElementById("log");
const form = document.getElementById("composer");
const questionEl = document.getElementById("question");
const askBtn = form.querySelector("button");

let history = [];
let suggestions = [];

function el(html) {
  const t = document.createElement("template");
  t.innerHTML = html.trim();
  return t.content.firstElementChild;
}

function addBubble(who, text, extra) {
  const wrap = el(`<article class="bubble ${who}"></article>`);
  wrap.innerHTML = `<div class="who">${who === "user" ? "You" : "Assistant"}</div><div class="card"></div>`;
  wrap.querySelector(".card").textContent = text;
  if (extra) wrap.appendChild(extra);
  logEl.appendChild(wrap);
  wrap.scrollIntoView({ block: "end" });
  return wrap;
}

function toolsList(tools) {
  if (!tools || !tools.length) return null;
  const ul = el("<ul class='tools'></ul>");
  for (const t of tools) {
    const li = document.createElement("li");
    li.textContent = `${t.name} — ${t.summary || ""}`;
    ul.appendChild(li);
  }
  return ul;
}

function welcome(session) {
  logEl.innerHTML = "";
  const intro = addBubble(
    "assistant",
    "Ask a business question. I will only use approved Oracle objects, validate every SELECT, and cite the data source.\n\nIf a number is not in a tool result, I will not invent it."
  );
  const row = el("<div class='suggestions'></div>");
  for (const s of session.suggestions || []) {
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = s;
    b.addEventListener("click", () => send(s));
    row.appendChild(b);
  }
  intro.appendChild(row);
}

function fillSession(session, health) {
  const dl = document.getElementById("session-meta");
  dl.innerHTML = `
    <dt>Role</dt><dd>${session.role} (${session.clearance})</dd>
    <dt>User</dt><dd>${session.user_id}</dd>
    <dt>SQL visible</dt><dd>${session.show_sql ? "yes" : "no — omit unless asked"}</dd>
  `;
  const dbs = document.getElementById("db-list");
  dbs.innerHTML = "";
  const healthByName = Object.fromEntries((health.databases || []).map((d) => [d.name, d.ok]));
  for (const db of session.databases || []) {
    const li = document.createElement("li");
    const name = db.database_name || db.name || db.display_name;
    const ok = healthByName[name];
    li.textContent = `${name}${ok === false ? " (unreachable)" : ok ? " (ok)" : ""}`;
    dbs.appendChild(li);
  }
  const tools = document.getElementById("tool-list");
  tools.innerHTML = "";
  for (const name of health.tools || []) {
    const li = document.createElement("li");
    li.textContent = name;
    tools.appendChild(li);
  }
  const hp = document.getElementById("health-pill");
  const allOk = (health.databases || []).every((d) => d.ok);
  hp.textContent = allOk ? "Databases connected" : "Database check failed";
  hp.className = "pill " + (allOk ? "ok" : "bad");
  const lp = document.getElementById("llm-pill");
  lp.textContent = health.llm_configured ? "Language model ready" : "Set CHAT_LLM_API_KEY";
  lp.className = "pill " + (health.llm_configured ? "ok" : "bad");
}

async function boot() {
  const [session, health] = await Promise.all([
    fetch("/api/session").then((r) => r.json()),
    fetch("/api/health").then((r) => r.json()),
  ]);
  suggestions = session.suggestions || [];
  fillSession(session, health);
  welcome(session);
}

async function send(text) {
  const question = (text || questionEl.value).trim();
  if (!question) return;
  questionEl.value = "";
  askBtn.disabled = true;
  addBubble("user", question);
  try {
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question, history }),
    });
    const data = await res.json();
    if (!res.ok) {
      addBubble("assistant", data.detail || "The assistant could not complete that request.");
      return;
    }
    history.push({ role: "user", content: question });
    history.push({ role: "assistant", content: data.answer || "" });
    addBubble("assistant", data.answer || "(empty reply)", toolsList(data.tools));
  } catch (err) {
    addBubble("assistant", String(err));
  } finally {
    askBtn.disabled = false;
    questionEl.focus();
  }
}

form.addEventListener("submit", (e) => {
  e.preventDefault();
  send();
});
questionEl.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    send();
  }
});
document.getElementById("new-chat").addEventListener("click", () => {
  history = [];
  boot();
});

boot();
