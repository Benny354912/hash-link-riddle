const mainInput = document.getElementById("main-input");
const mainLabel = document.getElementById("main-label");
const creatorTools = document.getElementById("creator-tools");
const algoSelect = document.getElementById("algo-select");
const caseSensitiveInput = document.getElementById("case-sensitive");
const useSaltInput = document.getElementById("use-salt");
const saltRow = document.getElementById("salt-row");
const saltValueInput = document.getElementById("salt-value");
const regenSaltBtn = document.getElementById("regen-salt-btn");
const saltNoteEl = document.getElementById("salt-note");
const shareUrlInput = document.getElementById("share-url");
const copyBtn = document.getElementById("copy-btn");
const statusEl = document.getElementById("status");

const ALGORITHMS = {
    "sha256": {
        label: "SHA-256",
        kind: "fast",
        hashLength: 64,
        webCryptoName: "SHA-256",
    },
    "md5": {
        label: "MD5",
        kind: "fast",
        hashLength: 32,
    },
    "pbkdf2-sha256": {
        label: "PBKDF2-SHA-256",
        kind: "password",
        hashLength: 64,
        pbkdf2Hash: "SHA-256",
        keyBytes: 32,
        defaultIterations: 180000,
    },
    "pbkdf2-sha512": {
        label: "PBKDF2-SHA-512",
        kind: "password",
        hashLength: 128,
        pbkdf2Hash: "SHA-512",
        keyBytes: 64,
        defaultIterations: 210000,
    },
};

const DEFAULT_ALGORITHM = "sha256";
const DEFAULT_FAST_SALT_ENABLED = true;

let mode = "create";
let target = null;
let suppressHashSync = false;
let creatorRunId = 0;
let guessRunId = 0;

const creatorSaltByAlgorithm = {};
const creatorSaltEnabledByAlgorithm = {};

function toHex(buffer) {
    const bytes = new Uint8Array(buffer);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function isHexOfLength(value, expectedLength) {
    const matcher = new RegExp(`^[0-9a-f]{${expectedLength}}$`, "i");
    return matcher.test(value);
}

function bytesToBase64Url(bytes) {
    let binary = "";

    for (let i = 0; i < bytes.length; i += 1) {
        binary += String.fromCharCode(bytes[i]);
    }

    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(value) {
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const padding = "=".repeat((4 - (normalized.length % 4 || 4)) % 4);
    const binary = atob(normalized + padding);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i += 1) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
}

function randomSaltBase64Url(byteLength = 16) {
    const bytes = new Uint8Array(byteLength);
    crypto.getRandomValues(bytes);
    return bytesToBase64Url(bytes);
}

async function digestSha(text, algorithm) {
    const enc = new TextEncoder();
    const data = enc.encode(text);
    const digest = await crypto.subtle.digest(algorithm, data);
    return toHex(digest);
}

async function digestPbkdf2(text, algorithmConfig, saltB64Url, iterations) {
    const saltBytes = base64UrlToBytes(saltB64Url);
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(text),
        { name: "PBKDF2" },
        false,
        ["deriveBits"]
    );

    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            hash: algorithmConfig.pbkdf2Hash,
            salt: saltBytes,
            iterations,
        },
        keyMaterial,
        algorithmConfig.keyBytes * 8
    );

    return toHex(derivedBits);
}

function safeAdd(x, y) {
    const lsw = (x & 0xffff) + (y & 0xffff);
    const msw = (x >>> 16) + (y >>> 16) + (lsw >>> 16);
    return (msw << 16) | (lsw & 0xffff);
}

function rotateLeft(value, amount) {
    return (value << amount) | (value >>> (32 - amount));
}

function md5Cmn(q, a, b, x, s, t) {
    return safeAdd(rotateLeft(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b);
}

function md5Ff(a, b, c, d, x, s, t) {
    return md5Cmn((b & c) | (~b & d), a, b, x, s, t);
}

function md5Gg(a, b, c, d, x, s, t) {
    return md5Cmn((b & d) | (c & ~d), a, b, x, s, t);
}

function md5Hh(a, b, c, d, x, s, t) {
    return md5Cmn(b ^ c ^ d, a, b, x, s, t);
}

function md5Ii(a, b, c, d, x, s, t) {
    return md5Cmn(c ^ (b | ~d), a, b, x, s, t);
}

function wordsToHex(words) {
    let result = "";

    for (let i = 0; i < words.length; i += 1) {
        const word = words[i];

        for (let j = 0; j < 4; j += 1) {
            const byte = (word >>> (j * 8)) & 0xff;
            result += byte.toString(16).padStart(2, "0");
        }
    }

    return result;
}

function md5Hex(input) {
    const inputBytes = new TextEncoder().encode(input);
    const words = [];

    for (let i = 0; i < inputBytes.length; i += 1) {
        words[i >> 2] = (words[i >> 2] || 0) | (inputBytes[i] << ((i % 4) * 8));
    }

    const bitLength = inputBytes.length * 8;
    words[bitLength >> 5] = (words[bitLength >> 5] || 0) | (0x80 << (bitLength % 32));
    words[(((bitLength + 64) >>> 9) << 4) + 14] = bitLength;

    let a = 1732584193;
    let b = -271733879;
    let c = -1732584194;
    let d = 271733878;

    for (let i = 0; i < words.length; i += 16) {
        const oldA = a;
        const oldB = b;
        const oldC = c;
        const oldD = d;

        a = md5Ff(a, b, c, d, words[i] || 0, 7, -680876936);
        d = md5Ff(d, a, b, c, words[i + 1] || 0, 12, -389564586);
        c = md5Ff(c, d, a, b, words[i + 2] || 0, 17, 606105819);
        b = md5Ff(b, c, d, a, words[i + 3] || 0, 22, -1044525330);
        a = md5Ff(a, b, c, d, words[i + 4] || 0, 7, -176418897);
        d = md5Ff(d, a, b, c, words[i + 5] || 0, 12, 1200080426);
        c = md5Ff(c, d, a, b, words[i + 6] || 0, 17, -1473231341);
        b = md5Ff(b, c, d, a, words[i + 7] || 0, 22, -45705983);
        a = md5Ff(a, b, c, d, words[i + 8] || 0, 7, 1770035416);
        d = md5Ff(d, a, b, c, words[i + 9] || 0, 12, -1958414417);
        c = md5Ff(c, d, a, b, words[i + 10] || 0, 17, -42063);
        b = md5Ff(b, c, d, a, words[i + 11] || 0, 22, -1990404162);
        a = md5Ff(a, b, c, d, words[i + 12] || 0, 7, 1804603682);
        d = md5Ff(d, a, b, c, words[i + 13] || 0, 12, -40341101);
        c = md5Ff(c, d, a, b, words[i + 14] || 0, 17, -1502002290);
        b = md5Ff(b, c, d, a, words[i + 15] || 0, 22, 1236535329);

        a = md5Gg(a, b, c, d, words[i + 1] || 0, 5, -165796510);
        d = md5Gg(d, a, b, c, words[i + 6] || 0, 9, -1069501632);
        c = md5Gg(c, d, a, b, words[i + 11] || 0, 14, 643717713);
        b = md5Gg(b, c, d, a, words[i] || 0, 20, -373897302);
        a = md5Gg(a, b, c, d, words[i + 5] || 0, 5, -701558691);
        d = md5Gg(d, a, b, c, words[i + 10] || 0, 9, 38016083);
        c = md5Gg(c, d, a, b, words[i + 15] || 0, 14, -660478335);
        b = md5Gg(b, c, d, a, words[i + 4] || 0, 20, -405537848);
        a = md5Gg(a, b, c, d, words[i + 9] || 0, 5, 568446438);
        d = md5Gg(d, a, b, c, words[i + 14] || 0, 9, -1019803690);
        c = md5Gg(c, d, a, b, words[i + 3] || 0, 14, -187363961);
        b = md5Gg(b, c, d, a, words[i + 8] || 0, 20, 1163531501);
        a = md5Gg(a, b, c, d, words[i + 13] || 0, 5, -1444681467);
        d = md5Gg(d, a, b, c, words[i + 2] || 0, 9, -51403784);
        c = md5Gg(c, d, a, b, words[i + 7] || 0, 14, 1735328473);
        b = md5Gg(b, c, d, a, words[i + 12] || 0, 20, -1926607734);

        a = md5Hh(a, b, c, d, words[i + 5] || 0, 4, -378558);
        d = md5Hh(d, a, b, c, words[i + 8] || 0, 11, -2022574463);
        c = md5Hh(c, d, a, b, words[i + 11] || 0, 16, 1839030562);
        b = md5Hh(b, c, d, a, words[i + 14] || 0, 23, -35309556);
        a = md5Hh(a, b, c, d, words[i + 1] || 0, 4, -1530992060);
        d = md5Hh(d, a, b, c, words[i + 4] || 0, 11, 1272893353);
        c = md5Hh(c, d, a, b, words[i + 7] || 0, 16, -155497632);
        b = md5Hh(b, c, d, a, words[i + 10] || 0, 23, -1094730640);
        a = md5Hh(a, b, c, d, words[i + 13] || 0, 4, 681279174);
        d = md5Hh(d, a, b, c, words[i] || 0, 11, -358537222);
        c = md5Hh(c, d, a, b, words[i + 3] || 0, 16, -722521979);
        b = md5Hh(b, c, d, a, words[i + 6] || 0, 23, 76029189);
        a = md5Hh(a, b, c, d, words[i + 9] || 0, 4, -640364487);
        d = md5Hh(d, a, b, c, words[i + 12] || 0, 11, -421815835);
        c = md5Hh(c, d, a, b, words[i + 15] || 0, 16, 530742520);
        b = md5Hh(b, c, d, a, words[i + 2] || 0, 23, -995338651);

        a = md5Ii(a, b, c, d, words[i] || 0, 6, -198630844);
        d = md5Ii(d, a, b, c, words[i + 7] || 0, 10, 1126891415);
        c = md5Ii(c, d, a, b, words[i + 14] || 0, 15, -1416354905);
        b = md5Ii(b, c, d, a, words[i + 5] || 0, 21, -57434055);
        a = md5Ii(a, b, c, d, words[i + 12] || 0, 6, 1700485571);
        d = md5Ii(d, a, b, c, words[i + 3] || 0, 10, -1894986606);
        c = md5Ii(c, d, a, b, words[i + 10] || 0, 15, -1051523);
        b = md5Ii(b, c, d, a, words[i + 1] || 0, 21, -2054922799);
        a = md5Ii(a, b, c, d, words[i + 8] || 0, 6, 1873313359);
        d = md5Ii(d, a, b, c, words[i + 15] || 0, 10, -30611744);
        c = md5Ii(c, d, a, b, words[i + 6] || 0, 15, -1560198380);
        b = md5Ii(b, c, d, a, words[i + 13] || 0, 21, 1309151649);
        a = md5Ii(a, b, c, d, words[i + 4] || 0, 6, -145523070);
        d = md5Ii(d, a, b, c, words[i + 11] || 0, 10, -1120210379);
        c = md5Ii(c, d, a, b, words[i + 2] || 0, 15, 718787259);
        b = md5Ii(b, c, d, a, words[i + 9] || 0, 21, -343485551);

        a = safeAdd(a, oldA);
        b = safeAdd(b, oldB);
        c = safeAdd(c, oldC);
        d = safeAdd(d, oldD);
    }

    return wordsToHex([a, b, c, d]);
}

async function hashByAlgorithm(text, algorithmId, params = {}) {
    const algorithmConfig = ALGORITHMS[algorithmId];

    if (!algorithmConfig) {
        throw new Error("Unbekanntes Hash-Verfahren.");
    }

    const fastInput = params.saltB64Url ? `${params.saltB64Url}:${text}` : text;

    if (algorithmId === "md5") {
        return md5Hex(fastInput);
    }

    if (algorithmConfig.kind === "fast") {
        return digestSha(fastInput, algorithmConfig.webCryptoName);
    }

    if (!params.saltB64Url || !params.iterations) {
        throw new Error("PBKDF2-Parameter fehlen.");
    }

    return digestPbkdf2(text, algorithmConfig, params.saltB64Url, params.iterations);
}

function normalizeSecret(text, caseSensitive) {
    return caseSensitive ? text : text.toLowerCase();
}

function getCreatorAlgorithmId() {
    const selected = (algoSelect.value || "").toLowerCase();
    return ALGORITHMS[selected] ? selected : DEFAULT_ALGORITHM;
}

function isPasswordAlgorithm(algorithmId) {
    const cfg = ALGORITHMS[algorithmId];
    return cfg?.kind === "password";
}

function ensureCreatorSalt(algorithmId) {
    if (!creatorSaltByAlgorithm[algorithmId]) {
        creatorSaltByAlgorithm[algorithmId] = randomSaltBase64Url(16);
    }

    return creatorSaltByAlgorithm[algorithmId];
}

function getCreatorSaltEnabled(algorithmId) {
    if (isPasswordAlgorithm(algorithmId)) {
        return true;
    }

    if (typeof creatorSaltEnabledByAlgorithm[algorithmId] !== "boolean") {
        creatorSaltEnabledByAlgorithm[algorithmId] = DEFAULT_FAST_SALT_ENABLED;
    }

    return creatorSaltEnabledByAlgorithm[algorithmId];
}

function setCreatorSaltEnabled(algorithmId, enabled) {
    if (isPasswordAlgorithm(algorithmId)) {
        creatorSaltEnabledByAlgorithm[algorithmId] = true;
        return;
    }

    creatorSaltEnabledByAlgorithm[algorithmId] = Boolean(enabled);
}

function getOrCreateCreatorHashParams(algorithmId) {
    const algorithmConfig = ALGORITHMS[algorithmId];
    if (!algorithmConfig) {
        return {};
    }

    const shouldUseSalt = getCreatorSaltEnabled(algorithmId);
    const params = {};

    if (shouldUseSalt) {
        params.saltB64Url = ensureCreatorSalt(algorithmId);
    }

    if (algorithmConfig.kind === "password") {
        params.iterations = algorithmConfig.defaultIterations;
    }

    return params;
}

function refreshCreatorSettingsUI() {
    const algorithmId = getCreatorAlgorithmId();
    const isPassword = isPasswordAlgorithm(algorithmId);
    const saltEnabled = getCreatorSaltEnabled(algorithmId);

    if (saltEnabled) {
        ensureCreatorSalt(algorithmId);
    }

    useSaltInput.checked = saltEnabled;
    useSaltInput.disabled = isPassword;

    saltRow.hidden = !saltEnabled;
    regenSaltBtn.disabled = !saltEnabled;
    saltValueInput.value = saltEnabled ? creatorSaltByAlgorithm[algorithmId] : "";

    if (isPassword) {
        saltNoteEl.textContent = "Bei PBKDF2 ist Salt fest aktiv (sicher empfohlen).";
        return;
    }

    if (saltEnabled) {
        saltNoteEl.textContent = "Salt ist aktiv und wird in der URL uebergeben.";
    } else {
        saltNoteEl.textContent = "Ohne Salt ist die Challenge leichter angreifbar.";
    }
}

function buildFragment(targetConfig) {
    const params = new URLSearchParams();

    params.set("a", targetConfig.algorithmId);
    params.set("c", targetConfig.caseSensitive ? "1" : "0");
    params.set("h", targetConfig.hash);

    if (targetConfig.saltB64Url) {
        params.set("s", targetConfig.saltB64Url);
    }

    if (targetConfig.iterations) {
        params.set("i", String(targetConfig.iterations));
    }

    return params.toString();
}

function parseLegacyFragment(raw) {
    const parts = raw.split(";");

    if (parts.length === 3) {
        const [version, cs, hash] = parts;
        if (version !== "v2") return null;
        if (cs !== "0" && cs !== "1") return null;
        if (!isHexOfLength(hash, 64)) return null;

        return {
            algorithmId: "sha256",
            caseSensitive: cs === "1",
            hash: hash.toLowerCase(),
        };
    }

    if (parts.length === 4) {
        const [version, algo, cs, hash] = parts;
        if (version !== "v1") return null;
        if (algo !== "sha256") return null;
        if (cs !== "0" && cs !== "1") return null;
        if (!isHexOfLength(hash, 64)) return null;

        return {
            algorithmId: "sha256",
            caseSensitive: cs === "1",
            hash: hash.toLowerCase(),
        };
    }

    return null;
}

function parseModernFragment(raw) {
    const params = new URLSearchParams(raw);
    const algorithmId = (params.get("a") || "").toLowerCase();
    const caseFlag = params.get("c");
    const hash = (params.get("h") || "").toLowerCase();
    const saltB64Url = params.get("s") || "";

    const algorithmConfig = ALGORITHMS[algorithmId];
    if (!algorithmConfig) return null;
    if (caseFlag !== "0" && caseFlag !== "1") return null;
    if (!isHexOfLength(hash, algorithmConfig.hashLength)) return null;

    const parsed = {
        algorithmId,
        caseSensitive: caseFlag === "1",
        hash,
    };

    if (saltB64Url) {
        if (!/^[A-Za-z0-9_-]{8,}$/.test(saltB64Url)) return null;

        try {
            base64UrlToBytes(saltB64Url);
        } catch {
            return null;
        }

        parsed.saltB64Url = saltB64Url;
    }

    if (algorithmConfig.kind === "password") {
        const iterationRaw = params.get("i") || "";
        const iterations = Number.parseInt(iterationRaw, 10);

        if (!saltB64Url) return null;
        if (!Number.isInteger(iterations) || iterations < 50000 || iterations > 2000000) return null;
        parsed.iterations = iterations;
    }

    return parsed;
}

function parseFragment(fragment) {
    if (!fragment) return null;

    const raw = fragment.replace(/^#/, "");
    if (!raw) return null;

    if (raw.includes("=")) {
        return parseModernFragment(raw);
    }

    return parseLegacyFragment(raw);
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
                return;
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
        refreshCreatorSettingsUI();
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
    const runId = ++creatorRunId;
    const secret = mainInput.value;
    const caseSensitive = caseSensitiveInput.checked;
    const algorithmId = getCreatorAlgorithmId();

    if (algoSelect.value !== algorithmId) {
        algoSelect.value = algorithmId;
    }

    refreshCreatorSettingsUI();

    if (!secret) {
        shareUrlInput.value = baseUrl();
        replaceUrl({ fragment: "", guess: "" });
        setStatus("");
        return;
    }

    const normalized = normalizeSecret(secret, caseSensitive);
    const creatorHashParams = getOrCreateCreatorHashParams(algorithmId);
    const hash = await hashByAlgorithm(normalized, algorithmId, creatorHashParams);

    if (runId !== creatorRunId || mode !== "create") {
        return;
    }

    const fragmentConfig = {
        algorithmId,
        caseSensitive,
        hash,
        ...creatorHashParams,
    };

    const fragment = buildFragment(fragmentConfig);
    const shareUrl = `${baseUrl()}#${fragment}`;

    shareUrlInput.value = shareUrl;
    replaceUrl({ fragment, guess: "" });
}

async function updateGuessState() {
    const runId = ++guessRunId;

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

    const hashParams = {
        saltB64Url: target.saltB64Url,
        iterations: target.iterations,
    };

    const [directHash, lowerHash] = await Promise.all([
        hashByAlgorithm(guess, target.algorithmId, hashParams),
        hashByAlgorithm(guess.toLowerCase(), target.algorithmId, hashParams),
    ]);

    if (runId !== guessRunId || mode !== "guess") {
        return;
    }

    if (directHash === target.hash || lowerHash === target.hash) {
        setStatus("Treffer.", "ok");
        return;
    }

    setStatus("Nicht korrekt.", "error");
}

async function syncFromUrl() {
    target = parseFragment(window.location.hash);

    if (target) {
        if (ALGORITHMS[target.algorithmId]) {
            algoSelect.value = target.algorithmId;
        }
        caseSensitiveInput.checked = target.caseSensitive;

        if (target.saltB64Url) {
            creatorSaltByAlgorithm[target.algorithmId] = target.saltB64Url;
        }

        if (!isPasswordAlgorithm(target.algorithmId)) {
            setCreatorSaltEnabled(target.algorithmId, Boolean(target.saltB64Url));
        } else {
            setCreatorSaltEnabled(target.algorithmId, true);
        }
    }

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

algoSelect.addEventListener("change", () => {
    if (mode !== "create") return;

    updateCreatorState().catch((err) => {
        setStatus(`Fehler: ${err.message}`, "error");
    });
});

useSaltInput.addEventListener("change", () => {
    if (mode !== "create") return;

    const algorithmId = getCreatorAlgorithmId();
    setCreatorSaltEnabled(algorithmId, useSaltInput.checked);

    if (getCreatorSaltEnabled(algorithmId)) {
        ensureCreatorSalt(algorithmId);
    }

    refreshCreatorSettingsUI();

    updateCreatorState().catch((err) => {
        setStatus(`Fehler: ${err.message}`, "error");
    });
});

regenSaltBtn.addEventListener("click", () => {
    if (mode !== "create") return;

    const algorithmId = getCreatorAlgorithmId();
    if (!getCreatorSaltEnabled(algorithmId)) return;

    creatorSaltByAlgorithm[algorithmId] = randomSaltBase64Url(16);
    refreshCreatorSettingsUI();

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
    if (suppressHashSync) {
        suppressHashSync = false;
        return;
    }

    syncFromUrl().catch((err) => {
        setStatus(`Fehler: ${err.message}`, "error");
    });
});

syncFromUrl().catch((err) => {
    setStatus(`Fehler: ${err.message}`, "error");
});
