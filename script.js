const enc = new TextEncoder();
const dec = new TextDecoder();

const byId = (id) => document.getElementById(id);
const publicKeyField = byId("publicKey");
const privateKeyField = byId("privateKey");
const statusToast = byId("statusToast");

const toBase64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const fromBase64 = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)).buffer;

let toastTimer;
function showStatus(message, type = "success") {
  statusToast.textContent = message;
  statusToast.className = `status-toast show ${type}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    statusToast.className = "status-toast";
  }, 2200);
}

function setLoading(button, loading) {
  button.classList.toggle("loading", loading);
}

async function withFeedback(button, action, successMessage) {
  try {
    setLoading(button, true);
    const value = await action();
    showStatus(successMessage, "success");
    return value;
  } catch {
    showStatus("Operation failed. Please check keys and input.", "error");
    throw new Error("operation_failed");
  } finally {
    setLoading(button, false);
  }
}

function downloadText(name, text) {
  const blob = new Blob([text], { type: "application/json" });
  downloadBlob(name, blob);
}

function downloadBlob(name, blob) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

async function importPublicKey(base64Spki) {
  return crypto.subtle.importKey(
    "spki",
    fromBase64(base64Spki.trim()),
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt"],
  );
}

async function importPrivateKey(base64Pkcs8) {
  return crypto.subtle.importKey(
    "pkcs8",
    fromBase64(base64Pkcs8.trim()),
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["decrypt"],
  );
}

async function generateKeys() {
  const pair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"],
  );
  const spki = await crypto.subtle.exportKey("spki", pair.publicKey);
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", pair.privateKey);
  return { publicKey: toBase64(spki), privateKey: toBase64(pkcs8) };
}

async function hybridEncrypt(bytes, base64PublicKey, metadata = {}) {
  const rsaKey = await importPublicKey(base64PublicKey);
  const aesKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const rawAes = await crypto.subtle.exportKey("raw", aesKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, bytes);
  const encryptedKey = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, rsaKey, rawAes);

  return JSON.stringify({
    encryptedKey: toBase64(encryptedKey),
    iv: toBase64(iv),
    ciphertext: toBase64(ciphertext),
    metadata,
  }, null, 2);
}

async function hybridDecrypt(payload, base64PrivateKey) {
  const parsed = typeof payload === "string" ? JSON.parse(payload) : payload;
  const rsaPrivate = await importPrivateKey(base64PrivateKey);

  const rawAes = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, rsaPrivate, fromBase64(parsed.encryptedKey));
  const aesKey = await crypto.subtle.importKey("raw", rawAes, { name: "AES-GCM" }, false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(fromBase64(parsed.iv)) },
    aesKey,
    fromBase64(parsed.ciphertext),
  );
  return { plain, metadata: parsed.metadata || {} };
}

byId("generateKeys").onclick = async (event) => {
  const button = event.currentTarget;
  const { publicKey, privateKey } = await withFeedback(button, () => generateKeys(), "RSA key pair generated.");
  publicKeyField.value = publicKey;
  privateKeyField.value = privateKey;
};

byId("downloadPublic").onclick = (event) => {
  if (!publicKeyField.value) return showStatus("Generate or paste a public key first.", "error");
  setLoading(event.currentTarget, true);
  downloadText("public_key.spki.b64", publicKeyField.value);
  setTimeout(() => setLoading(event.currentTarget, false), 250);
  showStatus("Public key downloaded.");
};

byId("downloadPrivate").onclick = (event) => {
  if (!privateKeyField.value) return showStatus("Generate or paste a private key first.", "error");
  setLoading(event.currentTarget, true);
  downloadText("private_key.pkcs8.b64", privateKeyField.value);
  setTimeout(() => setLoading(event.currentTarget, false), 250);
  showStatus("Private key downloaded.");
};

byId("encryptText").onclick = async (event) => {
  const button = event.currentTarget;
  const payload = await withFeedback(
    button,
    () => hybridEncrypt(enc.encode(byId("plainText").value), publicKeyField.value, { type: "text" }),
    "Text encrypted and downloaded.",
  );
  downloadText("encrypted_text.enc.json", payload);
};

byId("decryptText").onclick = async (event) => {
  const button = event.currentTarget;
  try {
    const { plain } = await withFeedback(
      button,
      () => hybridDecrypt(byId("encryptedTextInput").value, privateKeyField.value),
      "Text decrypted successfully.",
    );
    byId("decryptedTextOutput").textContent = dec.decode(plain);
  } catch {
    byId("decryptedTextOutput").textContent = "Unable to decrypt. Check key and payload.";
  }
};

byId("encryptFile").onclick = async (event) => {
  const button = event.currentTarget;
  const file = byId("fileToEncrypt").files[0];
  if (!file) return showStatus("Choose a file first.", "error");

  const payload = await withFeedback(button, async () => {
    const buffer = await file.arrayBuffer();
    return hybridEncrypt(buffer, publicKeyField.value, {
      type: "file",
      filename: file.name,
      mimeType: file.type || "application/octet-stream",
    });
  }, "File encrypted and downloaded.");

  downloadText(`${file.name}.enc.json`, payload);
};

byId("decryptFile").onclick = async (event) => {
  const button = event.currentTarget;
  const encryptedFile = byId("encryptedFileToDecrypt").files[0];
  if (!encryptedFile) return showStatus("Choose an encrypted JSON file first.", "error");

  try {
    const result = await withFeedback(button, async () => {
      const raw = await encryptedFile.text();
      const parsed = JSON.parse(raw);
      return hybridDecrypt(parsed, privateKeyField.value);
    }, "File decrypted and downloaded.");

    const blob = new Blob([result.plain], { type: result.metadata.mimeType || "application/octet-stream" });
    downloadBlob(result.metadata.filename || "decrypted.bin", blob);
  } catch {
    // handled by withFeedback
  }
};
