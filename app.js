const mainInput = document.getElementById("main-input");
const mainLabel = document.getElementById("main-label");
const creatorTools = document.getElementById("creator-tools");
const caseSensitiveInput = document.getElementById("case-sensitive");
const shareUrlInput = document.getElementById("share-url");
const copyBtn = document.getElementById("copy-btn");
const statusEl = document.getElementById("status");

const HASH_VERSION = "v2";
const HASH_ALGO = "SHA-256";

let mode = "create";
let target = null;
let suppressHashSync = false;

function toHex(buffer) {
    const bytes = new Uint8Array(buffer);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function digestSha256(text) {
    const enc = new TextEncoder();
    const data = enc.encode(text);
    const digest = await crypto.subtle.digest(HASH_ALGO, data);
    return toHex(digest);
}

function normalizeSecret(text, caseSensitive) {
    return caseSensitive ? text : text.toLowerCase();
}

function buildFragment(caseSensitive, hash) {
    return `${HASH_VERSION};${caseSensitive ? "1" : "0"};${hash}`;
}

function parseFragment(fragment) {
    if (!fragment) return null;

    const raw = fragment.replace(/^#/, "");
    if (!raw) return null;

    const parts = raw.split(";");
    if (parts.length === 3) {
        const [version, cs, hash] = parts;
        if (version !== "v2") return null;
        if (cs !== "0" && cs !== "1") return null;
        if (!/^[0-9a-f]{64}$/i.test(hash)) return null;

        return {
            caseSensitive: cs === "1",
            hash: hash.toLowerCase(),
        };
    }

    if (parts.length === 4) {
        const [version, algo, cs, hash] = parts;
        if (version !== "v1") return null;
        if (algo !== "sha256") return null;
        if (cs !== "0" && cs !== "1") return null;
        if (!/^[0-9a-f]{64}$/i.test(hash)) return null;

        return {
            caseSensitive: cs === "1",
            hash: hash.toLowerCase(),
        };
    }

    return null;
}

function baseUrl() {
    const url = new URL(window.location.href);
    url.hash = "";
    url.searchParams.delete("g");
    return url.toString();
}

function replaceUrl({ fragment, guess }) {
    const url = new URL(window.location.href);

    if (typeof fragment === "string") {
        url.hash = fragment;
    }

    if (typeof guess === "string") {
        if (guess) {
            url.searchParams.set("g", guess);
        } else {
            url.searchParams.delete("g");
        }
    } else if (mode === "create") {
        url.searchParams.delete("g");
    }

    const releaseSyncLock = () => {
        if (typeof queueMicrotask === "function") {
            queueMicrotask(() => {
                suppressHashSync = false;
            });
            return;
        }

        Promise.resolve().then(() => {
            suppressHashSync = false;
        });
    };

    suppressHashSync = true;

    try {
        // Relative URL avoids browser-specific origin checks on file:// paths.
        const relativeUrl = `${url.pathname}${url.search}${url.hash}`;
        history.replaceState({}, "", relativeUrl);
        releaseSyncLock();
        return;
    } catch {
        // Fallback for restrictive file:// environments: update only hash.
        if (typeof fragment === "string") {
            const nextHash = fragment ? `#${fragment}` : "";
            if (window.location.hash !== nextHash) {
                window.location.hash = nextHash;
            }
        }

        releaseSyncLock();
    }
}

function setStatus(text, type = "") {
    statusEl.textContent = text;
    statusEl.className = "status";
    if (type) {
        statusEl.classList.add(type);
    }
}

function applyMode(nextMode) {
    mode = nextMode;
    creatorTools.hidden = mode !== "create";

    if (mode === "create") {
        mainLabel.textContent = "Geheime Eingabe";
        mainInput.placeholder = "Geheime Eingabe";
        mainInput.value = "";
        shareUrlInput.value = baseUrl();
        setStatus("");
        return;
    }

    mainLabel.textContent = "Testeingabe";
    mainInput.placeholder = "Testeingabe";
    mainInput.value = new URL(window.location.href).searchParams.get("g") || "";
    setStatus(mainInput.value ? "" : "Teste eine Eingabe.");
}

async function updateCreatorState() {
    const secret = mainInput.value;
    const caseSensitive = caseSensitiveInput.checked;

    if (!secret) {
        shareUrlInput.value = baseUrl();
        replaceUrl({ fragment: "", guess: "" });
        setStatus("");
        return;
    }

    const normalized = normalizeSecret(secret, caseSensitive);
    const hash = await digestSha256(normalized);
    const fragment = buildFragment(caseSensitive, hash);
    const shareUrl = `${baseUrl()}#${fragment}`;

    shareUrlInput.value = shareUrl;
    replaceUrl({ fragment, guess: "" });
}

async function updateGuessState() {
    if (!target) {
        setStatus("Kein gueltiger Hash in URL.", "error");
        return;
    }

    const guess = mainInput.value;
    replaceUrl({ guess });

    if (!guess) {
        setStatus("Teste eine Eingabe.");
        return;
    }

    const directHash = await digestSha256(guess);
    const lowerHash = await digestSha256(guess.toLowerCase());

    if (directHash === target.hash || lowerHash === target.hash) {
        setStatus("Treffer.", "ok");
        return;
    }

    setStatus("Nicht korrekt.", "error");
}

async function syncFromUrl() {
    target = parseFragment(window.location.hash);
    applyMode(target ? "guess" : "create");

    if (mode === "create") {
        await updateCreatorState();
    } else {
        await updateGuessState();
    }
}

mainInput.addEventListener("input", () => {
    const task = mode === "create" ? updateCreatorState() : updateGuessState();
    task.catch((err) => {
        setStatus(`Fehler: ${err.message}`, "error");
    });
});

caseSensitiveInput.addEventListener("change", () => {
    if (mode !== "create") return;

    updateCreatorState().catch((err) => {
        setStatus(`Fehler: ${err.message}`, "error");
    });
});

copyBtn.addEventListener("click", async () => {
    if (!shareUrlInput.value) return;

    try {
        await navigator.clipboard.writeText(shareUrlInput.value);
        setStatus("URL kopiert.", "ok");
    } catch {
        setStatus("Kopieren nicht moeglich.", "error");
    }
});

window.addEventListener("hashchange", () => {
    if (suppressHashSync) return;

    syncFromUrl().catch((err) => {
        setStatus(`Fehler: ${err.message}`, "error");
    });
});

syncFromUrl().catch((err) => {
    setStatus(`Fehler: ${err.message}`, "error");
});
