
/* =========================================
   HN SECURE — PASSWORD ANALYZER
   Client-side password analysis
   ========================================= */

"use strict";

/* =========================================
   DOM ELEMENTS
   ========================================= */

const passwordInput = document.getElementById("passwordInput");
const togglePassword = document.getElementById("togglePassword");
const eyeIcon = document.getElementById("eyeIcon");

const characterCount = document.getElementById("characterCount");
const clearPassword = document.getElementById("clearPassword");

const strengthName = document.getElementById("strengthName");
const strengthMessage = document.getElementById("strengthMessage");

const meterFill = document.getElementById("meterFill");
const strengthMeter = document.getElementById("strengthMeter");

const scoreValue = document.getElementById("scoreValue");
const lengthValue = document.getElementById("lengthValue");
const entropyValue = document.getElementById("entropyValue");
const charsetValue = document.getElementById("charsetValue");

const requirements = document.getElementById("requirements");
const recommendations = document.getElementById("recommendations");

const generateButton = document.getElementById("generateButton");

const generatorModal = document.getElementById("generatorModal");
const closeModal = document.getElementById("closeModal");

const generatedPassword = document.getElementById("generatedPassword");
const copyGenerated = document.getElementById("copyGenerated");

const passwordLength = document.getElementById("passwordLength");
const passwordLengthLabel = document.getElementById("passwordLengthLabel");

const regenerateButton = document.getElementById("regenerateButton");
const useGenerated = document.getElementById("useGenerated");


/* =========================================
   CONFIGURATION
   ========================================= */

const CHARACTER_SETS = {
    lowercase: "abcdefghijklmnopqrstuvwxyz",

    uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",

    numbers: "0123456789",

    symbols: "!@#$%^&*()-_=+[]{};:,.?/\\|~`'\"<>"
};

const COMMON_PASSWORDS = new Set([
    "password",
    "password1",
    "password123",
    "123456",
    "12345678",
    "123456789",
    "1234567890",
    "qwerty",
    "qwerty123",
    "qwertyuiop",
    "admin",
    "admin123",
    "letmein",
    "welcome",
    "welcome123",
    "iloveyou",
    "monkey",
    "dragon",
    "football",
    "abc123",
    "passw0rd",
    "changeme",
    "secret",
    "root",
    "toor"
]);

const COMMON_WORDS = [
    "password",
    "admin",
    "welcome",
    "qwerty",
    "letmein",
    "secret",
    "login",
    "summer",
    "winter",
    "spring",
    "autumn",
    "football",
    "cricket",
    "iloveyou",
    "monkey",
    "dragon"
];

const SEQUENTIAL_PATTERNS = [
    "123456",
    "234567",
    "345678",
    "456789",
    "abcdef",
    "bcdefg",
    "qwerty",
    "asdfgh",
    "zxcvbn",
    "password"
];


/* =========================================
   STATE
   ========================================= */

let currentAnalysis = null;


/* =========================================
   UTILITY FUNCTIONS
   ========================================= */

/**
 * Clamp a number to a defined range.
 */
function clamp(value, min, max) {
    return Math.min(Math.max(value, min), max);
}


/**
 * Escape HTML before inserting user-derived text.
 */
function escapeHTML(value) {
    return String(value).replace(/[&<>"']/g, function (character) {
        const entities = {
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#039;"
        };

        return entities[character];
    });
}


/**
 * Return the number of Unicode code points.
 * This is more accurate than string.length for emoji.
 */
function getCharacterLength(value) {
    return Array.from(value).length;
}


/**
 * Check whether a password contains a repeated character.
 */
function hasRepeatedCharacters(password) {
    return /(.)\1{2,}/u.test(password);
}


/**
 * Check for simple sequential patterns.
 */
function hasSequentialPattern(password) {
    const normalized = password.toLowerCase();

    return SEQUENTIAL_PATTERNS.some(function (pattern) {
        return normalized.includes(pattern);
    });
}


/**
 * Check for a simple keyboard pattern.
 */
function hasKeyboardPattern(password) {
    const normalized = password.toLowerCase();

    const patterns = [
        "qwerty",
        "asdfgh",
        "zxcvbn",
        "qazwsx",
        "1qaz",
        "2wsx"
    ];

    return patterns.some(function (pattern) {
        return normalized.includes(pattern);
    });
}


/**
 * Check for common weak words.
 */
function containsCommonWord(password) {
    const normalized = password.toLowerCase();

    return COMMON_WORDS.some(function (word) {
        return normalized.includes(word);
    });
}


/**
 * Check whether a password is made only from one repeated
 * character or a small repeated sequence.
 */
function isRepeatedPattern(password) {
    if (!password) {
        return false;
    }

    if (/^(.)\1+$/u.test(password)) {
        return true;
    }

    if (password.length >= 4) {
        const half = Math.floor(password.length / 2);

        if (
            password.length % 2 === 0 &&
            password.slice(0, half) === password.slice(half)
        ) {
            return true;
        }
    }

    return false;
}


/**
 * Approximate the size of the character pool.
 *
 * This is a rough estimate, not a password-cracking benchmark.
 */
function getCharacterPool(password) {
    let pool = 0;
    let charset = [];

    if (/[a-z]/.test(password)) {
        pool += 26;
        charset.push("lowercase");
    }

    if (/[A-Z]/.test(password)) {
        pool += 26;
        charset.push("uppercase");
    }

    if (/[0-9]/.test(password)) {
        pool += 10;
        charset.push("numbers");
    }

    if (/[^a-zA-Z0-9]/.test(password)) {
        pool += 33;
        charset.push("symbols");
    }

    return {
        pool: pool,
        charset: charset
    };
}


/**
 * Calculate a rough theoretical entropy estimate.
 *
 * Entropy = length × log2(character pool)
 *
 * This assumes random independent characters and is NOT
 * a guarantee of real-world password strength.
 */
function calculateEntropy(password) {
    const length = getCharacterLength(password);
    const characterPool = getCharacterPool(password);

    if (!length || !characterPool.pool) {
        return 0;
    }

    return Math.round(
        length * Math.log2(characterPool.pool) * 10
    ) / 10;
}


/**
 * Check if password contains obvious date-like patterns.
 */
function hasDatePattern(password) {
    return /(?:19|20)\d{2}|(?:0?[1-9]|[12]\d|3[01])(?:0?[1-9]|1[0-2])/.test(password);
}


/**
 * Check if a password is a common password.
 */
function isCommonPassword(password) {
    return COMMON_PASSWORDS.has(password.toLowerCase());
}


/**
 * Detect whether the password is made entirely of digits.
 */
function isNumericOnly(password) {
    return /^\d+$/.test(password);
}


/**
 * Detect whether the password is made entirely of letters.
 */
function isLettersOnly(password) {
    return /^[a-zA-Z]+$/.test(password);
}


/* =========================================
   PASSWORD ANALYSIS
   ========================================= */

function analyzePassword(password) {

    const length = getCharacterLength(password);

    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSymbol = /[^a-zA-Z0-9]/.test(password);

    const characterPool = getCharacterPool(password);

    const entropy = calculateEntropy(password);

    const common = isCommonPassword(password);
    const commonWord = containsCommonWord(password);
    const repeated = hasRepeatedCharacters(password);
    const sequential = hasSequentialPattern(password);
    const keyboard = hasKeyboardPattern(password);
    const repeatedPattern = isRepeatedPattern(password);
    const datePattern = hasDatePattern(password);

    let score = 0;

    /*
     * Length scoring.
     * Length is important, but not the only factor.
     */
    if (length >= 8) {
        score += 10;
    }

    if (length >= 12) {
        score += 15;
    }

    if (length >= 16) {
        score += 15;
    }

    if (length >= 20) {
        score += 10;
    }

    /*
     * Character diversity.
     */
    if (hasLower) {
        score += 10;
    }

    if (hasUpper) {
        score += 10;
    }

    if (hasNumber) {
        score += 10;
    }

    if (hasSymbol) {
        score += 10;
    }

    /*
     * Approximate entropy contribution.
     */
    if (entropy >= 40) {
        score += 5;
    }

    if (entropy >= 60) {
        score += 5;
    }

    /*
     * Penalties for obvious patterns.
     */
    if (common) {
        score -= 55;
    }

    if (commonWord) {
        score -= 10;
    }

    if (sequential) {
        score -= 12;
    }

    if (keyboard) {
        score -= 10;
    }

    if (repeated) {
        score -= 8;
    }

    if (repeatedPattern) {
        score -= 20;
    }

    if (datePattern) {
        score -= 5;
    }

    if (isNumericOnly(password)) {
        score -= 20;
    }

    if (isLettersOnly(password) && length < 16) {
        score -= 8;
    }

    score = Math.round(clamp(score, 0, 100));

    /*
     * Empty password.
     */
    if (!password) {
        score = 0;
    }

    let strength;
    let message;
    let color;

    if (!password) {

        strength = "No Password";

        message =
            "Enter a password to begin your security analysis.";

        color = "#35d4ff";

    } else if (common || score < 20) {

        strength = "Very Weak";

        message =
            "This password is highly predictable. Choose a unique, longer password.";

        color = "#ff557b";

    } else if (score < 40) {

        strength = "Weak";

        message =
            "This password needs improvement. Increase length and avoid common patterns.";

        color = "#ff557b";

    } else if (score < 60) {

        strength = "Fair";

        message =
            "Some useful characteristics are present, but this password can be stronger.";

        color = "#ff9c52";

    } else if (score < 80) {

        strength = "Strong";

        message =
            "Good password characteristics. Keep it unique and consider using a password manager.";

        color = "#f6c85f";

    } else {

        strength = "Very Strong";

        message =
            "Strong characteristics detected. Make sure this password is unique and not reused.";

        color = "#35e69a";

    }

    return {
        password: password,
        length: length,

        score: score,
        strength: strength,
        message: message,
        color: color,

        entropy: entropy,
        pool: characterPool.pool,
        charset: characterPool.charset,

        hasLower: hasLower,
        hasUpper: hasUpper,
        hasNumber: hasNumber,
        hasSymbol: hasSymbol,

        common: common,
        commonWord: commonWord,
        repeated: repeated,
        sequential: sequential,
        keyboard: keyboard,
        repeatedPattern: repeatedPattern,
        datePattern: datePattern,
        numericOnly: isNumericOnly(password),
        lettersOnly: isLettersOnly(password)
    };
}


/* =========================================
   UPDATE REQUIREMENTS
   ========================================= */

function updateRequirements(analysis) {

    const rules = {
        length: analysis.length >= 12,
        long: analysis.length >= 16,
        lower: analysis.hasLower,
        upper: analysis.hasUpper,
        number: analysis.hasNumber,
        symbol: analysis.hasSymbol
    };

    Object.keys(rules).forEach(function (rule) {

        const element = requirements.querySelector(
            '[data-rule="' + rule + '"]'
        );

        if (!element) {
            return;
        }

        const icon = element.querySelector(".requirement-icon");

        if (rules[rule]) {

            element.classList.add("passed");

            icon.textContent = "✓";

        } else {

            element.classList.remove("passed");

            icon.textContent = "○";

        }

    });
}


/* =========================================
   UPDATE RECOMMENDATIONS
   ========================================= */

function createRecommendation(type, message) {

    const element = document.createElement("div");

    element.className = "recommendation " + type;

    const icon = type === "good"
        ? "✓"
        : type === "warning"
            ? "⚠"
            : "✕";

    element.innerHTML =
        '<span class="recommendation-icon">' +
        icon +
        '</span>' +
        '<span>' +
        escapeHTML(message) +
        '</span>';

    return element;
}


function updateRecommendations(analysis) {

    recommendations.innerHTML = "";

    if (!analysis.password) {

        const empty = document.createElement("div");

        empty.className = "empty-recommendation";

        empty.innerHTML =
            "<span>◈</span>" +
            "<p>Your recommendations will appear here.</p>";

        recommendations.appendChild(empty);

        return;
    }

    const findings = [];

    if (analysis.common) {

        findings.push({
            type: "danger",
            message:
                "This password matches a common password pattern. Avoid using it."
        });

    }

    if (analysis.length < 12) {

        findings.push({
            type: "warning",
            message:
                "Increase password length to at least 12 characters."
        });

    }

    if (analysis.length < 16) {

        findings.push({
            type: "warning",
            message:
                "Consider using 16 or more characters for important accounts."
        });

    }

    if (!analysis.hasLower) {

        findings.push({
            type: "warning",
            message:
                "Add lowercase letters, or use a longer passphrase."
        });

    }

    if (!analysis.hasUpper) {

        findings.push({
            type: "warning",
            message:
                "Add uppercase letters if they fit your password strategy."
        });

    }

    if (!analysis.hasNumber) {

        findings.push({
            type: "warning",
            message:
                "Consider including numbers, especially when using a mixed-character password."
        });

    }

    if (!analysis.hasSymbol) {

        findings.push({
            type: "warning",
            message:
                "Special characters can add diversity, if supported by the service."
        });

    }

    if (analysis.sequential || analysis.keyboard) {

        findings.push({
            type: "danger",
            message:
                "Avoid predictable keyboard or sequential patterns."
        });

    }

    if (analysis.repeatedPattern || analysis.repeated) {

        findings.push({
            type: "warning",
            message:
                "Avoid repeated characters and repeated blocks."
        });

    }

    if (analysis.commonWord) {

        findings.push({
            type: "warning",
            message:
                "Avoid common words, names, and familiar phrases."
        });

    }

    if (analysis.numericOnly) {

        findings.push({
            type: "danger",
            message:
                "Number-only passwords are easy to guess. Use a longer unique password."
        });

    }

    if (analysis.datePattern) {

        findings.push({
            type: "warning",
            message:
                "Avoid dates and other personal information."
        });

    }

    if (
        analysis.score >= 80 &&
        !analysis.common &&
        !analysis.sequential &&
        !analysis.keyboard
    ) {

        findings.push({
            type: "good",
            message:
                "Good characteristics detected. Keep this password unique and never reuse it."
        });

    }

    findings.push({
        type: "good",
        message:
            "Use a password manager and enable multi-factor authentication where available."
    });

    /*
     * Display only the first six findings.
     */
    findings.slice(0, 6).forEach(function (finding) {

        recommendations.appendChild(
            createRecommendation(
                finding.type,
                finding.message
            )
        );

    });
}


/* =========================================
   UPDATE UI
   ========================================= */

function updateUI() {

    const password = passwordInput.value;

    currentAnalysis = analyzePassword(password);

    const analysis = currentAnalysis;

    characterCount.textContent =
        analysis.length + (analysis.length === 1 ? " character" : " characters");

    strengthName.textContent = analysis.strength;

    strengthName.style.color = analysis.color;

    strengthMessage.textContent = analysis.message;

    meterFill.style.width = analysis.score + "%";

    meterFill.style.background = analysis.color;

    meterFill.style.boxShadow =
        "0 0 14px " + analysis.color + "55";

    strengthMeter.setAttribute(
        "aria-valuenow",
        String(analysis.score)
    );

    scoreValue.textContent = analysis.score;

    lengthValue.textContent = analysis.length;

    entropyValue.textContent = analysis.entropy;

    charsetValue.textContent =
        analysis.charset.length
            ? analysis.charset.length + " types"
            : "—";

    updateRequirements(analysis);

    updateRecommendations(analysis);
}


/* =========================================
   SHOW / HIDE PASSWORD
   ========================================= */

togglePassword.addEventListener("click", function () {

    const isPassword = passwordInput.type === "password";

    passwordInput.type = isPassword
        ? "text"
        : "password";

    togglePassword.setAttribute(
        "aria-label",
        isPassword ? "Hide password" : "Show password"
    );

    togglePassword.setAttribute(
        "aria-pressed",
        String(isPassword)
    );

    eyeIcon.textContent = isPassword ? "◉" : "◌";

});


/* =========================================
   INPUT EVENTS
   ========================================= */

passwordInput.addEventListener("input", updateUI);

clearPassword.addEventListener("click", function () {

    passwordInput.value = "";

    updateUI();

    passwordInput.focus();

});


/* =========================================
   SECURE RANDOM GENERATOR
   ========================================= */

/**
 * Generate a cryptographically secure random integer.
 *
 * Uses crypto.getRandomValues().
 */
function secureRandomInt(max) {

    if (!Number.isInteger(max) || max <= 0) {
        throw new Error("Invalid random range.");
    }

    const cryptoObject = window.crypto;

    if (
        !cryptoObject ||
        typeof cryptoObject.getRandomValues !== "function"
    ) {
        throw new Error(
            "Secure random generation is unavailable in this browser."
        );
    }

    const maxUint32 = 0x100000000;

    const limit = Math.floor(maxUint32 / max) * max;

    const array = new Uint32Array(1);

    let randomValue;

    do {

        cryptoObject.getRandomValues(array);

        randomValue = array[0];

    } while (randomValue >= limit);

    return randomValue % max;
}


/**
 * Shuffle an array using cryptographically secure randomness.
 */
function secureShuffle(array) {

    const result = array.slice();

    for (let i = result.length - 1; i > 0; i--) {

        const j = secureRandomInt(i + 1);

        const temporary = result[i];

        result[i] = result[j];

        result[j] = temporary;

    }

    return result;
}


/**
 * Generate a password containing all four character categories.
 */
function generateSecurePassword(length) {

    const lower = CHARACTER_SETS.lowercase;
    const upper = CHARACTER_SETS.uppercase;
    const numbers = CHARACTER_SETS.numbers;
    const symbols = CHARACTER_SETS.symbols;

    const allCharacters =
        lower + upper + numbers + symbols;

    const requiredCharacters = [
        lower[secureRandomInt(lower.length)],
        upper[secureRandomInt(upper.length)],
        numbers[secureRandomInt(numbers.length)],
        symbols[secureRandomInt(symbols.length)]
    ];

    const remainingLength = Math.max(
        0,
        length - requiredCharacters.length
    );

    const result = requiredCharacters.slice();

    for (let i = 0; i < remainingLength; i++) {

        result.push(
            allCharacters[
                secureRandomInt(allCharacters.length)
            ]
        );

    }

    return secureShuffle(result).join("");
}


/* =========================================
   GENERATOR MODAL
   ========================================= */

function showModal() {

    generatorModal.hidden = false;

    document.body.style.overflow = "hidden";

    generateNewPassword();

    closeModal.focus();

}


function hideModal() {

    generatorModal.hidden = true;

    document.body.style.overflow = "";

    generateButton.focus();

}


function generateNewPassword() {

    const length = Number(passwordLength.value);

    passwordLengthLabel.textContent = length;

    try {

        const password = generateSecurePassword(length);

        generatedPassword.textContent = password;

        copyGenerated.textContent = "Copy";

    } catch (error) {

        generatedPassword.textContent =
            "Secure generation unavailable";

        copyGenerated.textContent = "Error";

        console.error(error);

    }

}


generateButton.addEventListener("click", showModal);

closeModal.addEventListener("click", hideModal);

regenerateButton.addEventListener("click", generateNewPassword);

passwordLength.addEventListener("input", generateNewPassword);

generatorModal.addEventListener("click", function (event) {

    if (event.target === generatorModal) {
        hideModal();
    }

});


/* =========================================
   USE GENERATED PASSWORD
   ========================================= */

useGenerated.addEventListener("click", function () {

    const password = generatedPassword.textContent;

    if (
        !password ||
        password === "Secure generation unavailable"
    ) {
        return;
    }

    passwordInput.value = password;

    passwordInput.type = "password";

    togglePassword.setAttribute(
        "aria-label",
        "Show password"
    );

    togglePassword.setAttribute(
        "aria-pressed",
        "false"
    );

    eyeIcon.textContent = "◉";

    updateUI();

    hideModal();

});


/* =========================================
   COPY GENERATED PASSWORD
   ========================================= */

copyGenerated.addEventListener("click", async function () {

    const password = generatedPassword.textContent;

    if (
        !password ||
        password === "Secure generation unavailable"
    ) {
        return;
    }

    /*
     * Clipboard API is optional.
     * The app continues working without it.
     */
    try {

        if (
            navigator.clipboard &&
            typeof navigator.clipboard.writeText === "function"
        ) {

            await navigator.clipboard.writeText(password);

            copyGenerated.textContent = "Copied ✓";

            setTimeout(function () {
                copyGenerated.textContent = "Copy";
            }, 1500);

        } else {

            copyGenerated.textContent = "Copy manually";

        }

    } catch (error) {

        copyGenerated.textContent = "Copy manually";

        console.warn(
            "Clipboard unavailable:",
            error
        );

    }

});


/* =========================================
   ESCAPE KEY
   ========================================= */

document.addEventListener("keydown", function (event) {

    if (
        event.key === "Escape" &&
        !generatorModal.hidden
    ) {
        hideModal();
    }

});


/* =========================================
   INITIALIZE
   ========================================= */

updateUI();

console.log(
    "%cHN Secure Password Analyzer",
    "color:#35d4ff;font-size:16px;font-weight:bold"
);

console.log(
    "Local password analysis initialized."
);
