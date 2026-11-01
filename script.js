
/* Cipher Lab: Vigenere, Additive, Multiplicative, Affine and Plaintext-Autokey */
"use strict";

const $ = id => document.getElementById(id);
const ABC = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const MOD = 26;

const state = {
  cipher: "vigenere",
  operation: "encrypt",
  result: "",
  originalMessage: "",
  key: "",
  steps: [],
  selectedStep: null,
  hasRun: false
};

document.addEventListener("DOMContentLoaded", () => {
  addCipherSelector();
  renderAlphabet();
  renderVigenereTable();
  bindEvents();
  updateCipherControls();
  runOperation("encrypt", true);
});

function addCipherSelector() {
  const label = document.createElement("label");
  label.className = "form-label";
  label.htmlFor = "cipherSelect";
  label.textContent = "CIPHER ALGORITHM";

  const select = document.createElement("select");
  select.id = "cipherSelect";
  select.className = "form-control";

  select.innerHTML = `
    <option value="vigenere">Vigenère Cipher</option>
    <option value="additive">Additive Cipher</option>
    <option value="multiplicative">Multiplicative Cipher</option>
    <option value="affine">Affine Cipher</option>
    <option value="autokey">Autokey Cipher (Plaintext)</option>
  `;

  const messageLabel = document.querySelector(
    'label[for="messageInput"]'
  );

  messageLabel.parentNode.insertBefore(label, messageLabel);
  messageLabel.parentNode.insertBefore(select, messageLabel);
}

function bindEvents() {
  $("encryptBtn").addEventListener("click", () =>
    runOperation("encrypt")
  );

  $("decryptBtn").addEventListener("click", () =>
    runOperation("decrypt")
  );

  $("clearBtn").addEventListener("click", clearDashboard);
  $("copyBtn").addEventListener("click", copyResult);
  $("downloadBtn").addEventListener("click", downloadResult);

  $("cipherSelect").addEventListener("change", () => {
    state.cipher = $("cipherSelect").value;
    updateCipherControls();
    $("validationMessage").textContent = "";
  });

  $("messageInput").addEventListener("input", () => {
    $("messageCount").textContent =
      `${$("messageInput").value.length} chars`;

    $("validationMessage").textContent = "";
    $("copyFeedback").textContent = "";
  });

  $("keyInput").addEventListener("input", () => {
    $("validationMessage").textContent = "";
    $("copyFeedback").textContent = "";
  });
}

function updateCipherControls() {
  const c = $("cipherSelect").value;
  const label = document.querySelector('label[for="keyInput"]');
  const input = $("keyInput");
  const hint = document.querySelector(".input-hint");

  const cfg = {
    vigenere: [
      "SECRET KEY",
      "Enter a keyword...",
      "Alphabetic keyword; spaces and symbols in the message do not consume key letters."
    ],

    additive: [
      "SHIFT VALUE (0–25)",
      "Example: 3",
      "Enter an integer from 0 to 25."
    ],

    multiplicative: [
      "MULTIPLICATIVE KEY",
      "Example: 5",
      "Use a value coprime with 26: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23 or 25."
    ],

    affine: [
      "AFFINE KEY (a,b)",
      "Example: 5,8",
      "Enter a,b. The value a must be coprime with 26; b must be 0–25."
    ],

    autokey: [
      "AUTOKEY SEED",
      "Enter a keyword...",
      "Plaintext-autokey: after the seed, the plaintext supplies the remaining key stream."
    ]
  }[c];

  label.textContent = cfg[0];
  input.placeholder = cfg[1];

  hint.innerHTML =
    `<i class="fa-solid fa-circle-info"></i> ${cfg[2]}`;

  input.inputMode =
    ["additive", "multiplicative"].includes(c)
      ? "numeric"
      : "text";
}

function mod(n) {
  return ((n % MOD) + MOD) % MOD;
}

function gcd(a, b) {
  while (b) {
    [a, b] = [b, a % b];
  }

  return Math.abs(a);
}

function inverse(a) {
  for (let x = 1; x < 26; x++) {
    if (mod(a * x) === 1) {
      return x;
    }
  }

  return null;
}

function cleanKey(k) {
  return k.toUpperCase().replace(/[^A-Z]/g, "");
}

function formulaFor(c, op) {
  return ({
    vigenere:
      op === "encrypt"
        ? "C = (P + K) mod 26"
        : "P = (C − K + 26) mod 26",

    additive:
      op === "encrypt"
        ? "C = (P + k) mod 26"
        : "P = (C − k + 26) mod 26",

    multiplicative:
      op === "encrypt"
        ? "C = (P × k) mod 26"
        : "P = (C × k⁻¹) mod 26",

    affine:
      op === "encrypt"
        ? "C = (aP + b) mod 26"
        : "P = a⁻¹(C − b) mod 26",

    autokey:
      op === "encrypt"
        ? "Cᵢ = (Pᵢ + Kᵢ) mod 26"
        : "Pᵢ = (Cᵢ − Kᵢ + 26) mod 26"
  })[c];
}

function parseKey(cipher, raw) {
  if (cipher === "vigenere" || cipher === "autokey") {
    const k = cleanKey(raw);

    if (!k) {
      throw Error(
        "Key must contain at least one alphabetic character."
      );
    }

    return k;
  }

  if (
    cipher === "additive" ||
    cipher === "multiplicative"
  ) {
    if (!/^-?\d+$/.test(raw.trim())) {
      throw Error("Please enter a valid integer key.");
    }

    const n = Number(raw);

    if (
      !Number.isSafeInteger(n) ||
      n < 0 ||
      n > 25
    ) {
      throw Error("Key must be an integer from 0 to 25.");
    }

    if (
      cipher === "multiplicative" &&
      gcd(n, 26) !== 1
    ) {
      throw Error(
        "Multiplicative key must be coprime with 26. Try 5, 7, 11 or 17."
      );
    }

    return n;
  }

  const parts = raw.split(/[\s,]+/).filter(Boolean);

  if (
    parts.length !== 2 ||
    parts.some(x => !/^\d+$/.test(x))
  ) {
    throw Error(
      "Enter Affine key as two integers: a,b (example: 5,8)."
    );
  }

  const [a, b] = parts.map(Number);

  if (a > 25 || gcd(a, 26) !== 1) {
    throw Error(
      "Affine value a must be 0–25 and coprime with 26."
    );
  }

  if (b > 25) {
    throw Error(
      "Affine value b must be between 0 and 25."
    );
  }

  return {
    a,
    b,
    inv: inverse(a)
  };
}

function validateInput(msg, key, cipher) {
  if (!msg.trim()) {
    return "Please enter a message.";
  }

  if (!key.trim()) {
    return "Please enter a key.";
  }

  try {
    parseKey(cipher, key);
  } catch (e) {
    return e.message;
  }

  return "";
}

/* MAIN ENCRYPTION AND DECRYPTION ENGINE */

function transform(message, rawKey, cipher, operation) {
  const key = parseKey(cipher, rawKey);
  const chars = [...message];

  let result = "";
  let steps = [];
  let keyStreamDisplay = [];
  let letterIndex = 0;

  for (let i = 0; i < chars.length; i++) {
    const ch = chars[i];

    // Preserve spaces, numbers and special characters.
    if (!/[a-z]/i.test(ch)) {
      result += ch;
      keyStreamDisplay.push(ch === " " ? " " : "·");
      continue;
    }

    const x = ch.toUpperCase().charCodeAt(0) - 65;

    let kVal = 0;
    let keyLabel = "";
    let y = 0;
    let calc = "";

    /* VIGENERE CIPHER */

    if (cipher === "vigenere") {
      kVal =
        key[letterIndex % key.length].charCodeAt(0) - 65;

      keyLabel = key[letterIndex % key.length];

      y = operation === "encrypt"
        ? mod(x + kVal)
        : mod(x - kVal);

      calc = operation === "encrypt"
        ? `(${x} + ${kVal}) % 26`
        : `(${x} - ${kVal} + 26) % 26`;
    }

    /* ADDITIVE CIPHER */

    else if (cipher === "additive") {
      kVal = key;
      keyLabel = String(key);

      y = operation === "encrypt"
        ? mod(x + kVal)
        : mod(x - kVal);

      calc = operation === "encrypt"
        ? `(${x} + ${kVal}) % 26`
        : `(${x} - ${kVal} + 26) % 26`;
    }

    /* MULTIPLICATIVE CIPHER */

    else if (cipher === "multiplicative") {
      kVal = key;
      keyLabel = String(key);

      const inv = inverse(key);

      y = operation === "encrypt"
        ? mod(x * key)
        : mod(x * inv);

      calc = operation === "encrypt"
        ? `(${x} × ${key}) % 26`
        : `(${x} × ${inv}) % 26`;
    }

    /* AFFINE CIPHER */

    else if (cipher === "affine") {
      kVal = key.b;
      keyLabel = `${key.a},${key.b}`;

      y = operation === "encrypt"
        ? mod(key.a * x + key.b)
        : mod(key.inv * (x - key.b));

      calc = operation === "encrypt"
        ? `(${key.a} × ${x} + ${key.b}) % 26`
        : `${key.inv} × (${x} - ${key.b}) % 26`;
    }

    /* PLAINTEXT AUTOKEY CIPHER */

    else {
      if (letterIndex < key.length) {
        // Initial characters come from the secret seed.
        kVal = key.charCodeAt(letterIndex) - 65;
        keyLabel = key[letterIndex];

      } else if (operation === "encrypt") {
        // Encryption extends the key with previous plaintext.
        kVal = steps[
          letterIndex - key.length
        ].inputValue;

        keyLabel = String.fromCharCode(65 + kVal);

      } else {
        // Decryption extends the key with recovered plaintext.
        kVal = steps[
          letterIndex - key.length
        ].outValue;

        keyLabel =
          `P${letterIndex - key.length + 1}`;
      }

      y = operation === "encrypt"
        ? mod(x + kVal)
        : mod(x - kVal);

      calc = operation === "encrypt"
        ? `(${x} + ${kVal}) % 26`
        : `(${x} - ${kVal} + 26) % 26`;
    }

    const out = String.fromCharCode(65 + y);

    // Preserve original letter case.
    result +=
      ch === ch.toLowerCase()
        ? out.toLowerCase()
        : out;

    keyStreamDisplay.push(keyLabel);

    // Store the actual alphabetic key character for matrix highlighting.
    const keyLetter = String.fromCharCode(65 + kVal);

    steps.push({
      position: letterIndex + 1,
      index: i,
      input: ch,
      inputUpper: ch.toUpperCase(),
      inputValue: x,
      p: x,
      key: keyLabel,
      keyLetter,
      keyValue: kVal,
      k: kVal,
      out,
      outValue: y,
      operation,
      formula: calc
    });

    letterIndex++;
  }

  return {
    result,
    steps,
    repeated: keyStreamDisplay.join("")
  };
}

/* BACKWARD-COMPATIBILITY HELPERS */

function encryptVigenere(message, key) {
  return transform(
    message,
    key,
    "vigenere",
    "encrypt"
  ).result;
}

function decryptVigenere(message, key) {
  return transform(
    message,
    key,
    "vigenere",
    "decrypt"
  ).result;
}

function repeatKey(message, key) {
  const k = cleanKey(key);

  let out = "";
  let i = 0;

  for (const ch of message) {
    out += /[a-z]/i.test(ch)
      ? k[i++ % k.length]
      : (ch === " " ? " " : "·");
  }

  return out;
}

function calculateSteps(message, key, operation) {
  return transform(
    message,
    key,
    state.cipher,
    operation
  ).steps;
}

/* RUN ENCRYPTION OR DECRYPTION */

function runOperation(operation, isDemo = false) {
  const message = $("messageInput").value;
  const rawKey = $("keyInput").value;
  const cipher = $("cipherSelect").value;

  const error = validateInput(
    message,
    rawKey,
    cipher
  );

  $("validationMessage").textContent = error;
  $("copyFeedback").textContent = "";

  if (error) {
    if (!isDemo) {
      resetOutputForError(
        message,
        rawKey,
        operation
      );
    }

    return;
  }

  const data = transform(
    message,
    rawKey,
    cipher,
    operation
  );

  Object.assign(state, {
    cipher,
    operation,
    result: data.result,
    originalMessage: message,
    key: rawKey,
    steps: data.steps,
    selectedStep: data.steps.length ? 0 : null,
    hasRun: true
  });

  $("resultOutput").textContent =
    data.result || "(empty result)";

  $("resultTitle").textContent =
    operation === "encrypt"
      ? "ENCRYPTED RESULT"
      : "DECRYPTED RESULT";

  $("resultChip").textContent =
    operation === "encrypt"
      ? "OUTPUT TEXT"
      : "RECOVERED TEXT";

  $("resultStatus").innerHTML =
    '<span class="status-dot"></span> OPERATION COMPLETE';

  $("formulaDisplay").textContent =
    formulaFor(cipher, operation);

  $("repeatedKeyDisplay").textContent =
    data.repeated || "—";

  $("traceMessage").textContent = message;
  $("traceKey").textContent = data.repeated || "—";

  $("traceFormula").textContent =
    formulaFor(cipher, operation);

  $("stepCount").textContent =
    `${data.steps.length} STEPS`;

  renderCalculationTable();

  updateStatistics(
    message,
    rawKey,
    operation,
    data.steps.length
  );

  updateFlow(
    message,
    data.result,
    data.steps,
    operation
  );

  highlightAlphabet(data.steps[0] || null);
  updateMatrixHighlight(data.steps[0] || null);

  $("flowInputTitle").textContent =
    operation === "encrypt"
      ? "Plaintext"
      : "Ciphertext";

  $("flowOutputTitle").textContent =
    operation === "encrypt"
      ? "Ciphertext"
      : "Plaintext";

  $("flowFormula").textContent =
    formulaFor(cipher, operation);
}

function resetOutputForError(message, key, operation) {
  state.hasRun = false;
  state.result = "";
  state.steps = [];

  $("resultOutput").textContent = "—";
  $("resultTitle").textContent = "NO RESULT GENERATED";
  $("resultChip").textContent = "WAITING FOR INPUT";

  $("resultStatus").innerHTML =
    '<span class="status-dot"></span> INPUT REQUIRED';

  $("calculationBody").innerHTML = "";

  $("emptyTrace").classList.remove("d-none");

  updateStatistics(
    message,
    key,
    operation,
    0
  );
}

/* CALCULATION TABLE */

function renderCalculationTable() {
  const body = $("calculationBody");
  body.innerHTML = "";

  if (!state.steps.length) {
    $("emptyTrace").classList.remove("d-none");
    return;
  }

  $("emptyTrace").classList.add("d-none");

  state.steps.forEach((s, i) => {
    const row = document.createElement("tr");

    if (i === state.selectedStep) {
      row.classList.add("selected-row");
    }

    const cells = [
      s.position,
      `<span class="letter-cell">${escapeHTML(s.input)}</span>`,
      `<span class="key-cell">${escapeHTML(s.key)}</span>`,
      s.inputValue,
      s.keyValue,
      `<span class="formula-cell">${escapeHTML(s.formula)}</span>`,
      `<span class="output-letter">${s.out}</span>`
    ];

    cells.forEach(v => {
      const td = document.createElement("td");
      td.innerHTML = v;
      row.appendChild(td);
    });

    row.addEventListener("click", () =>
      selectStep(i)
    );

    body.appendChild(row);
  });
}

function selectStep(i) {
  state.selectedStep = i;

  document
    .querySelectorAll("#calculationBody tr")
    .forEach((r, n) => {
      r.classList.toggle(
        "selected-row",
        n === i
      );
    });

  highlightAlphabet(state.steps[i]);
  updateMatrixHighlight(state.steps[i]);
}

/* STATISTICS */

function updateStatistics(
  message,
  key,
  operation,
  letters
) {
  $("statCharacters").textContent =
    message.length;

  $("statLetters").textContent =
    letters;

  $("statKey").textContent =
    state.cipher === "affine"
      ? "2"
      : (
          ["additive", "multiplicative"].includes(state.cipher)
            ? "1"
            : cleanKey(key).length
        );

  $("statOperation").textContent =
    operation === "encrypt"
      ? "Encrypt"
      : "Decrypt";

  $("statOperationSub").textContent =
    state.hasRun
      ? "Transformation complete"
      : "Ready to transform";

  $("messageCount").textContent =
    `${message.length} chars`;
}

/* FLOW VISUALIZATION */

function updateFlow(
  message,
  result,
  steps,
  operation
) {
  $("flowInput").textContent =
    message || "—";

  $("flowOutput").textContent =
    result || "—";

  $("flowNumbers").textContent =
    steps
      .slice(0, 6)
      .map(s => s.inputValue)
      .join(" · ") +
    (steps.length > 6 ? " · …" : "");

  $("flowFormula").textContent =
    formulaFor(state.cipher, operation);

  $("flowFormulaText").textContent =
    `${$("cipherSelect").selectedOptions[0].textContent}: ${formulaFor(state.cipher, operation)}`;
}

/* ALPHABET VISUALIZATION */

function renderAlphabet() {
  const grid = $("alphabetGrid");
  grid.innerHTML = "";

  [...ABC].forEach((l, i) => {
    const d = document.createElement("div");

    d.className = "alphabet-cell";
    d.dataset.letter = l;

    d.innerHTML = `
      <strong>${l}</strong>
      <span>${i}</span>
    `;

    grid.appendChild(d);
  });
}

function highlightAlphabet(s) {
  document
    .querySelectorAll(".alphabet-cell")
    .forEach(d => {
      const l = d.dataset.letter;

      d.classList.toggle(
        "is-highlight",
        !!s && (
          l === s.inputUpper ||
          l === s.out ||
          (s.key.length === 1 && l === s.key)
        )
      );
    });
}

/* VIGENERE TABULA RECTA */

function renderVigenereTable() {
  const t = $("vigenereTable");

  let h = '<thead><tr><th class="corner">+</th>';

  for (const l of ABC) {
    h += `<th data-col="${l}">${l}</th>`;
  }

  h += "</tr></thead><tbody>";

  for (let r = 0; r < 26; r++) {
    h += `<tr><th data-row="${ABC[r]}">${ABC[r]}</th>`;

    for (let c = 0; c < 26; c++) {
      const o = ABC[(r + c) % 26];

      h += `
        <td
          data-row="${ABC[r]}"
          data-col="${ABC[c]}"
          data-result="${o}"
        >${o}</td>
      `;
    }

    h += "</tr>";
  }

  t.innerHTML = h + "</tbody>";
}

/* CORRECTED MATRIX HIGHLIGHTING */

function updateMatrixHighlight(s) {
  const t = $("vigenereTable");

  t.querySelectorAll("td").forEach(c => {
    c.classList.remove(
      "highlight-row",
      "highlight-column",
      "highlight-intersection"
    );
  });

  t.querySelectorAll("th").forEach(c => {
    c.classList.remove("active-header");
  });

  if (
    !s ||
    !["vigenere", "autokey"].includes(state.cipher)
  ) {
    $("matrixSelection").textContent =
      "Tabula Recta applies to Vigenère and Autokey modes.";

    return;
  }

  // Tabula Recta:
  // Key row + plaintext column = ciphertext.
  const r = s.keyLetter;

  const c =
    state.operation === "encrypt"
      ? s.inputUpper
      : s.out;

  t.querySelectorAll(
    `td[data-row="${r}"]`
  ).forEach(x => {
    x.classList.add("highlight-row");
  });

  t.querySelectorAll(
    `td[data-col="${c}"]`
  ).forEach(x => {
    x.classList.add("highlight-column");
  });

  const hit = t.querySelector(
    `td[data-row="${r}"][data-col="${c}"]`
  );

  if (hit) {
    hit.classList.add("highlight-intersection");
  }

  const rh = t.querySelector(
    `th[data-row="${r}"]`
  );

  const ch = t.querySelector(
    `thead th[data-col="${c}"]`
  );

  if (rh) rh.classList.add("active-header");
  if (ch) ch.classList.add("active-header");

  const expected =
    state.operation === "encrypt"
      ? s.out
      : s.inputUpper;

  $("matrixSelection").textContent =
    `Step ${s.position}: key row ${r} × plaintext column ${c} → ${hit ? hit.dataset.result : expected}`;
}

/* COPY RESULT */

async function copyResult() {
  if (!state.hasRun) {
    $("copyFeedback").textContent =
      "Generate a result first.";

    return;
  }

  try {
    if (
      navigator.clipboard &&
      window.isSecureContext
    ) {
      await navigator.clipboard.writeText(
        state.result
      );

    } else {
      const x = document.createElement("textarea");

      x.value = state.result;
      x.style.position = "fixed";
      x.style.opacity = "0";

      document.body.appendChild(x);
      x.select();

      const ok = document.execCommand("copy");
      x.remove();

      if (!ok) {
        throw Error("Clipboard unavailable");
      }
    }

    $("copyFeedback").textContent =
      "✓ Result copied!";

  } catch {
    $("copyFeedback").textContent =
      "Clipboard access blocked. Select and copy manually.";
  }
}

/* DOWNLOAD RESULT */

function downloadResult() {
  if (!state.hasRun) {
    $("copyFeedback").textContent =
      "Generate a result before downloading.";

    return;
  }

  const op =
    state.operation === "encrypt"
      ? "Encryption"
      : "Decryption";

  const content = [
    `Cipher: ${$("cipherSelect").selectedOptions[0].textContent}`,
    `Operation: ${op}`,
    `Input: ${state.originalMessage}`,
    `Key: ${state.key}`,
    `Formula: ${formulaFor(state.cipher, state.operation)}`,
    `Result: ${state.result}`
  ].join("\n") + "\n";

  const blob = new Blob(
    [content],
    { type: "text/plain;charset=utf-8" }
  );

  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");

  a.href = url;
  a.download =
    `${state.cipher}-${state.operation}-result.txt`;

  document.body.appendChild(a);
  a.click();
  a.remove();

  URL.revokeObjectURL(url);

  $("copyFeedback").textContent =
    "✓ Download started.";
}

/* CLEAR DASHBOARD */

function clearDashboard() {
  [
    "messageInput",
    "keyInput"
  ].forEach(id => {
    $(id).value = "";
  });

  [
    "resultOutput",
    "formulaDisplay",
    "repeatedKeyDisplay",
    "traceMessage",
    "traceKey",
    "traceFormula",
    "flowInput",
    "flowOutput",
    "flowNumbers",
    "flowFormula"
  ].forEach(id => {
    $(id).textContent = "—";
  });

  $("resultTitle").textContent =
    "NO RESULT GENERATED";

  $("resultChip").textContent =
    "WAITING FOR INPUT";

  $("resultStatus").innerHTML =
    '<span class="status-dot"></span> STANDBY';

  $("calculationBody").innerHTML = "";

  $("emptyTrace").classList.remove("d-none");

  $("validationMessage").textContent = "";
  $("copyFeedback").textContent = "";

  $("messageCount").textContent = "0 chars";
  $("stepCount").textContent = "0 STEPS";

  [
    "statCharacters",
    "statLetters",
    "statKey"
  ].forEach(id => {
    $(id).textContent = "0";
  });

  $("statOperation").textContent = "—";

  $("statOperationSub").textContent =
    "Ready to transform";

  $("matrixSelection").textContent =
    "Select a step from the trace table";

  document
    .querySelectorAll(".alphabet-cell")
    .forEach(x => {
      x.classList.remove("is-highlight");
    });

  $("vigenereTable")
    .querySelectorAll("td")
    .forEach(x => {
      x.classList.remove(
        "highlight-row",
        "highlight-column",
        "highlight-intersection"
      );
    });

  $("vigenereTable")
    .querySelectorAll("th")
    .forEach(x => {
      x.classList.remove("active-header");
    });

  Object.assign(state, {
    operation: "encrypt",
    result: "",
    originalMessage: "",
    key: "",
    steps: [],
    selectedStep: null,
    hasRun: false
  });
}

/* HTML ESCAPING */

function escapeHTML(v) {
  return String(v).replace(
    /[&<>"']/g,
    c => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;"
    })[c]
  );
}
