"use strict";

const SECRET_PATTERNS = [
  { name: "AWS Access Key", confidence: "high", regex: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: "Google API Key", confidence: "high", regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
  { name: "GitHub Token", confidence: "high", regex: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { name: "OpenAI-style key", confidence: "high", regex: /\bsk-[A-Za-z0-9]{20,}\b/g },
  { name: "Slack Token", confidence: "high", regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { name: "Generic JWT", confidence: "high", regex: /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g },
  { name: "Private key block", confidence: "high", regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g },
  { name: "Hardcoded password assignment", confidence: "medium", regex: /(?:^|[\s,{;])(?:pass|password)\s*[:=]\s*["']?([^\s"'#,;}]{4,})["']?/gim },
  { name: "possible secret (high entropy)", confidence: "low", custom: true }
];

function shannonEntropy(value) {
  if (!value) return 0;
  const counts = new Map();
  for (const char of value) counts.set(char, (counts.get(char) || 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) { const p = count / value.length; entropy -= p * Math.log2(p); }
  return entropy;
}

const NON_SECRET_KEYS = /^(id|uuid|guid|hash|checksum|digest|version|name|title|description|path|url|host|hostname|filename|file|slug|keyid|key_id)$/i;
const ASSIGNMENT = /(?:^|[\n\r])\s*([A-Za-z_$][\w$.-]*)\s*(?:=|:|=>)\s*(?:["']([^"'\n\r]{24,})["']|([A-Za-z0-9+/=_-]{24,}))/g;

function findHighEntropy(text) {
  const findings = [];
  let match;
  ASSIGNMENT.lastIndex = 0;
  while ((match = ASSIGNMENT.exec(text))) {
    const key = match[1]; const value = match[2] || match[3] || "";
    if (NON_SECRET_KEYS.test(key) || /(?:hash|checksum|digest)/i.test(key)) continue;
    if (value.length < 24 || shannonEntropy(value) <= 4.0) continue;
    const full = match[0]; const valueStart = match.index + full.lastIndexOf(value);
    findings.push({ pattern: "possible secret (high entropy)", confidence: "low", value, start: valueStart, end: valueStart + value.length });
  }
  return findings;
}

function detectSecrets(text) {
  const findings = [];
  for (const pattern of SECRET_PATTERNS) {
    if (pattern.custom) { findings.push(...findHighEntropy(text)); continue; }
    pattern.regex.lastIndex = 0;
    let match;
    while ((match = pattern.regex.exec(text))) {
      const value = pattern.name === "Hardcoded password assignment" ? (match[1] || match[0]) : match[0];
      const start = match.index + (pattern.name === "Hardcoded password assignment" ? match[0].lastIndexOf(value) : 0);
      findings.push({ pattern: pattern.name, confidence: pattern.confidence, value, start, end: start + value.length });
      if (match[0].length === 0) pattern.regex.lastIndex += 1;
    }
  }
  return findings.sort((a, b) => a.start - b.start || b.end - a.end);
}

function redactPreview(value) {
  const raw = String(value || "");
  if (raw.length < 8) return "[redacted]";
  return `${raw.slice(0, 4)}...${raw.slice(-4)}`;
}

function runPatternSelfTest() {
  const sample = [
    "key = placeholder_value_1234567890",
    "id = 550e8400-e29b-41d4-a716-446655440000",
    "token = sk-abcdefghijklmnopqrstuvwxyz1234",
    "aws = AKIAIOSFODNN7EXAMPLE"
  ].join("\n");
  const findings = detectSecrets(sample);
  console.assert(findings.some(f => f.pattern === "OpenAI-style key"), "OpenAI-style key self-test failed");
  console.assert(findings.some(f => f.pattern === "AWS Access Key"), "AWS key self-test failed");
  console.assert(!findings.some(f => f.value === "550e8400-e29b-41d4-a716-446655440000"), "UUID false-positive self-test failed");
  console.assert(redactPreview("short") === "[redacted]", "Preview minimum-length self-test failed");
  return findings.length;
}

window.secretSweepPatterns = { SECRET_PATTERNS, shannonEntropy, detectSecrets, redactPreview, runPatternSelfTest };
runPatternSelfTest();
