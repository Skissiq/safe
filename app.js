const methods = [
  { id: "base64", name: "Base64 轉碼", type: "codec" },
  { id: "caesar", name: "文字位移", type: "classic" },
  { id: "atbash", name: "反向字母", type: "classic" },
  { id: "rot13", name: "13 位位移", type: "classic" },
  { id: "vigenere", name: "口令加密", type: "classic" },
  { id: "railfence", name: "鐵欄排列", type: "classic" },
  { id: "xor", name: "字節混合", type: "symmetric" },
  { id: "aes", name: "進階密碼", type: "symmetric" },
  { id: "rsa", name: "公私鑰加密", type: "asymmetric" },
  { id: "sha256", name: "內容摘要", type: "utility" },
  { id: "utf8hex", name: "文字轉十六進位", type: "codec" },
];

const el = (id) => document.getElementById(id);
const methodEl = el("method");
const modeEl = el("mode");
const keyEl = el("key");
const paramEl = el("param");
const inputEl = el("input");
const outputEl = el("output");
const hintEl = el("hint");
const statusEl = el("status");
const keyRow = el("keyRow");
const asymActions = el("asymActions");
const generateKeysBtn = el("generateKeys");
const exportPublicBtn = el("exportPublic");
const exportPrivateBtn = el("exportPrivate");

let rsaKeys = null;

methods.forEach((m) => {
  const option = document.createElement("option");
  option.value = m.id;
  option.textContent = `${m.name} (${m.type})`;
  methodEl.appendChild(option);
});

el("methodList").innerHTML = methods.map((m) => `<span class="method-pill">${m.name}</span>`).join("");

const utf8 = new TextEncoder();
const utf8d = new TextDecoder();
const b64 = {
  enc: (bytes) => btoa(String.fromCharCode(...bytes)),
  dec: (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0)),
};
const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const unhex = (s) => {
  if (s.length % 2) throw new Error("十六進位長度必須是偶數");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < s.length; i += 2) out[i / 2] = parseInt(s.slice(i, i + 2), 16);
  return out;
};

function sanitizeLetters(s) {
  return s.normalize("NFKD").replace(/[\u0300-\u036f]/g, "");
}

function caesar(text, shift, decrypt = false) {
  const n = ((decrypt ? -shift : shift) % 26 + 26) % 26;
  return text.replace(/[A-Za-z]/g, (ch) => {
    const base = ch <= "Z" ? 65 : 97;
    return String.fromCharCode(base + ((ch.charCodeAt(0) - base + n) % 26));
  });
}

function atbash(text) {
  return text.replace(/[A-Za-z]/g, (ch) => {
    const base = ch <= "Z" ? 65 : 97;
    return String.fromCharCode(base + (25 - (ch.charCodeAt(0) - base)));
  });
}

function vigenere(text, key, decrypt = false) {
  const k = sanitizeLetters(key).toUpperCase().replace(/[^A-Z]/g, "");
  if (!k) throw new Error("口令加密需要英文字母金鑰");
  let i = 0;
  return text.replace(/[A-Za-z]/g, (ch) => {
    const shift = k.charCodeAt(i++ % k.length) - 65;
    return caesar(ch, shift, decrypt);
  });
}

function railFence(text, rails, decrypt = false) {
  rails = Math.max(2, parseInt(rails || "2", 10));
  if (!decrypt) {
    const rows = Array.from({ length: rails }, () => []);
    let r = 0;
    let d = 1;
    for (const ch of text) {
      rows[r].push(ch);
      if (r === 0) d = 1;
      else if (r === rails - 1) d = -1;
      r += d;
    }
    return rows.flat().join("");
  }

  const pattern = [];
  let r = 0;
  let d = 1;
  for (let i = 0; i < text.length; i++) {
    pattern.push(r);
    if (r === 0) d = 1;
    else if (r === rails - 1) d = -1;
    r += d;
  }

  const counts = Array.from({ length: rails }, (_, rr) => pattern.filter((p) => p === rr).length);
  const slices = [];
  let idx = 0;
  for (const c of counts) {
    slices.push(text.slice(idx, idx + c).split(""));
    idx += c;
  }
  const pos = Array(rails).fill(0);
  return pattern.map((rr) => slices[rr][pos[rr]++]).join("");
}

function xorCipher(text, key, decrypt = false) {
  const k = utf8.encode(key || "default-key");
  if (!k.length) throw new Error("字節混合需要金鑰");
  if (decrypt) {
    const bytes = b64.dec(text.trim());
    const out = bytes.map((b, i) => b ^ k[i % k.length]);
    return utf8d.decode(out);
  }
  const bytes = utf8.encode(text);
  const out = bytes.map((b, i) => b ^ k[i % k.length]);
  return b64.enc(out);
}

async function aesEncrypt(text, key) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const material = await crypto.subtle.importKey("raw", utf8.encode(key || "default-key"), "PBKDF2", false, ["deriveKey"]);
  const aesKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 120000, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, utf8.encode(text)));
  return `${b64.enc(salt)}.${b64.enc(iv)}.${b64.enc(cipher)}`;
}

async function aesDecrypt(text, key) {
  const [s, i, c] = text.split(".");
  if (!s || !i || !c) throw new Error("進階密碼格式應為 salt.iv.ciphertext");
  const salt = b64.dec(s);
  const iv = b64.dec(i);
  const cipher = b64.dec(c);
  const material = await crypto.subtle.importKey("raw", utf8.encode(key || "default-key"), "PBKDF2", false, ["deriveKey"]);
  const aesKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 120000, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, cipher);
  return utf8d.decode(plain);
}

async function rsaGenerate() {
  rsaKeys = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );
  exportPublicBtn.disabled = false;
  exportPrivateBtn.disabled = false;
  setStatus("RSA 金鑰已產生");
}

async function rsaEncrypt(text) {
  if (!rsaKeys?.publicKey) throw new Error("請先產生 RSA 金鑰");
  const enc = new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, rsaKeys.publicKey, utf8.encode(text)));
  return b64.enc(enc);
}

async function rsaDecrypt(text) {
  if (!rsaKeys?.privateKey) throw new Error("請先產生 RSA 金鑰");
  const plain = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, rsaKeys.privateKey, b64.dec(text));
  return utf8d.decode(plain);
}

async function exportKey(key, type) {
  const format = type === "public" ? "spki" : "pkcs8";
  const exported = await crypto.subtle.exportKey(format, key);
  return `-----BEGIN ${type.toUpperCase()} KEY-----\n${b64.enc(new Uint8Array(exported))}\n-----END ${type.toUpperCase()} KEY-----`;
}

function sha256(text) {
  return crypto.subtle.digest("SHA-256", utf8.encode(text)).then((buf) => hex(new Uint8Array(buf)));
}

function utf8Hex(text, decrypt = false) {
  return decrypt ? utf8d.decode(unhex(text.replace(/\s+/g, ""))) : hex(utf8.encode(text));
}

function setStatus(msg) {
  statusEl.textContent = msg;
}

function setHint(msg) {
  hintEl.textContent = msg || "";
}

function updateUI() {
  const method = methodEl.value;
  const asym = method === "rsa";
  asymActions.classList.toggle("hidden", !asym);
  keyRow.classList.toggle("hidden", method === "rsa");
  keyEl.placeholder = method === "vigenere" ? "例如：LEMON" : "例如：my-secret-key";
  const labels = {
    base64: "轉碼",
    caesar: "位移量",
    atbash: "反向規則",
    rot13: "固定 13 位移",
    vigenere: "英文字母口令",
    railfence: "欄數",
    xor: "金鑰",
    aes: "密碼",
    rsa: "公鑰 / 私鑰",
    sha256: "無需參數",
    utf8hex: "無需參數",
  };
  el("keyLabel").textContent = labels[method] || "金鑰 / 參數";
  paramEl.parentElement.classList.toggle("hidden", !["caesar", "railfence"].includes(method));

  const isSymmetric = ["base64", "caesar", "atbash", "rot13", "vigenere", "railfence", "xor", "aes", "sha256", "utf8hex"].includes(method);
  const isDecrypt = modeEl.value === "decrypt";
  if (method === "rsa") {
    keyEl.placeholder = isDecrypt ? "貼上 RSA 密文" : "輸入明文";
  } else if (isSymmetric) {
    keyEl.placeholder = isDecrypt
      ? "輸入對稱金鑰或密碼"
      : "輸入對稱金鑰或密碼";
  }

  generateKeysBtn.disabled = method !== "rsa";
  exportPublicBtn.disabled = method !== "rsa" || !rsaKeys;
  exportPrivateBtn.disabled = method !== "rsa" || !rsaKeys;
}

async function run() {
  const method = methodEl.value;
  const mode = modeEl.value;
  const input = inputEl.value;
  const key = keyEl.value.trim();
  const param = paramEl.value;
  setHint("");
  try {
    let result = "";
    if (method === "base64") result = mode === "encrypt" ? b64.enc(utf8.encode(input)) : utf8d.decode(b64.dec(input.trim()));
    else if (method === "caesar") result = caesar(input, parseInt(param || "3", 10), mode === "decrypt");
    else if (method === "atbash") result = atbash(input);
    else if (method === "rot13") result = caesar(input, 13, false);
    else if (method === "vigenere") result = vigenere(input, key, mode === "decrypt");
    else if (method === "railfence") result = railFence(input, parseInt(param || "2", 10), mode === "decrypt");
    else if (method === "xor") {
      if (mode === "encrypt") result = xorCipher(input, key, false);
      else result = xorCipher(input, key, true);
    } else if (method === "aes") result = mode === "encrypt" ? await aesEncrypt(input, key) : await aesDecrypt(input.trim(), key);
    else if (method === "rsa") result = mode === "encrypt" ? await rsaEncrypt(input) : await rsaDecrypt(input.trim());
    else if (method === "sha256") result = await sha256(input);
    else if (method === "utf8hex") result = utf8Hex(input, mode === "decrypt");

    outputEl.value = result;
    setStatus("完成");
    setHint(method === "rsa" ? "這是公鑰 / 私鑰非對稱加密，先產生金鑰再使用。" : "支援中文、英文與 UTF-8 內容。");
  } catch (err) {
    outputEl.value = "";
    setStatus("發生錯誤");
    setHint(err.message || String(err));
  }
}

methodEl.addEventListener("change", updateUI);
el("run").addEventListener("click", run);
el("copy").addEventListener("click", async () => {
  await navigator.clipboard.writeText(outputEl.value);
  setStatus("已複製結果");
});
el("swap").addEventListener("click", () => {
  [inputEl.value, outputEl.value] = [outputEl.value, inputEl.value];
});
generateKeysBtn.addEventListener("click", async () => {
  await rsaGenerate();
});
exportPublicBtn.addEventListener("click", async () => {
  if (!rsaKeys) return;
  outputEl.value = await exportKey(rsaKeys.publicKey, "public");
  setStatus("已匯出公鑰");
});
exportPrivateBtn.addEventListener("click", async () => {
  if (!rsaKeys) return;
  outputEl.value = await exportKey(rsaKeys.privateKey, "private");
  setStatus("已匯出私鑰");
});

updateUI();
setStatus("準備完成");
