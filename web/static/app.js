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

// Database content is untrusted, so every value is escaped before any Markdown
// transform runs. Never move an unescaped fragment into innerHTML below.
function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function inlineMd(s) {
  return s
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/(^|[^*])\*([^*\n]+)\*/g, "$1<em>$2</em>");
}

function splitRow(line) {
  return line
    .replace(/^\s*\|/, "")
    .replace(/\|\s*$/, "")
    .split("|")
    .map((c) => inlineMd(c.trim()));
}

const isTableRow = (l) => /^\s*\|.*\|\s*$/.test(l);
const isTableRule = (l) => /^\s*\|[\s:|-]+\|\s*$/.test(l);

function renderMarkdown(text) {
  const lines = escapeHtml(text).split("\n");
  const out = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];

    if (!line.trim()) {
      i += 1;
      continue;
    }

    const heading = line.match(/^(#{1,6})\s+(.*)$/);
    if (heading) {
      const level = Math.min(heading[1].length + 1, 6);
      out.push(`<h${level}>${inlineMd(heading[2])}</h${level}>`);
      i += 1;
      continue;
    }

    if (isTableRow(line) && isTableRule(lines[i + 1] || "")) {
      const head = splitRow(line);
      i += 2;
      const body = [];
      while (i < lines.length && isTableRow(lines[i])) {
        body.push(splitRow(lines[i]));
        i += 1;
      }
      const thead = `<tr>${head.map((c) => `<th>${c}</th>`).join("")}</tr>`;
      const tbody = body
        .map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`)
        .join("");
      out.push(`<table><thead>${thead}</thead><tbody>${tbody}</tbody></table>`);
      continue;
    }

    if (/^\s*[-*]\s+/.test(line)) {
      const items = [];
      while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) {
        items.push(`<li>${inlineMd(lines[i].replace(/^\s*[-*]\s+/, ""))}</li>`);
        i += 1;
      }
      out.push(`<ul>${items.join("")}</ul>`);
      continue;
    }

    // Always consume the first line: a stray "| x |" with no separator row
    // matches isTableRow but is not a table, and would otherwise never advance.
    const para = [];
    do {
      para.push(inlineMd(lines[i]));
      i += 1;
    } while (
      i < lines.length &&
      lines[i].trim() &&
      !/^#{1,6}\s/.test(lines[i]) &&
      !/^\s*[-*]\s+/.test(lines[i]) &&
      !(isTableRow(lines[i]) && isTableRule(lines[i + 1] || ""))
    );
    out.push(`<p>${para.join("<br>")}</p>`);
  }
  return out.join("");
}

function addBubble(who, text, extra) {
  const wrap = el(`<article class="bubble ${who}"></article>`);
  wrap.innerHTML = `<div class="who">${who === "user" ? "You" : "Assistant"}</div><div class="card"></div>`;
  const card = wrap.querySelector(".card");
  if (who === "assistant") {
    card.innerHTML = renderMarkdown(text);
  } else {
    card.textContent = text;
  }
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
    "Ask a business question about CDM, Install Base (IB), or Collibra governance. I will validate every SELECT against approved MDM objects, search the Collibra catalog when needed, and cite the exact data source.\n\nIf a number is not in a tool result, I will not invent it."
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
  const cp = document.getElementById("collibra-pill");
  if (cp) {
    if (health.collibra_configured) {
      cp.textContent = "Collibra connected";
      cp.className = "pill ok";
      cp.style.display = "";
    } else {
      cp.style.display = "none";
    }
  }
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
