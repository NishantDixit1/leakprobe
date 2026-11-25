/**
 * Secret detection.
 *
 * The highest-risk logic here. A false positive on a security report is
 * worse than a miss: tell someone their public Supabase anon key is a
 * leak and they stop believing the rest of the report, including the
 * parts that are real. The anon key is a JWT and is meant to be in the
 * browser. Only a service_role token matters.
 */

export type SecretHit = { name: string; redacted: string; note: string };

const JWT = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}/g;

const PATTERNS: { name: string; re: RegExp; note: string }[] = [
  { name: "OpenAI API key", re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g, note: "lets anyone spend on your OpenAI account" },
  { name: "Anthropic API key", re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g, note: "lets anyone spend on your Anthropic account" },
  { name: "Stripe secret key", re: /\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b/g, note: "can move money and read customer records" },
  { name: "AWS access key", re: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, note: "can reach your AWS account" },
  { name: "Google API key", re: /\bAIza[A-Za-z0-9_-]{35}\b/g, note: "can be billed against your Google account" },
  { name: "GitHub token", re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, note: "can read and push to your repositories" },
  { name: "Slack token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, note: "can read and post in your workspace" },
  { name: "SendGrid API key", re: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g, note: "can send email as you" },
  { name: "Twilio API key", re: /\bSK[0-9a-fA-F]{32}\b/g, note: "can send messages and calls billed to you" },
  { name: "Private key file", re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g, note: "is a credential that should never leave your server" },
];

/** A JWT's role claim. The signature is not verified; only the claim is needed. */
export function jwtRole(token: string): string | null {
  try {
    const payload = token.split(".")[1];
    if (!payload) return null;
    const json: unknown = JSON.parse(
      Buffer.from(payload.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"),
    );
    const role = (json as { role?: unknown } | null)?.role;
    return typeof role === "string" ? role : null;
  } catch {
    return null;
  }
}

export function redact(secret: string): string {
  if (secret.length <= 12) return `${secret.slice(0, 3)}…`;
  return `${secret.slice(0, 6)}…${secret.slice(-4)}`;
}

/** Find the Supabase anon key, which is what the database probe needs. */
export function findAnonKey(bundle: string): string | null {
  for (const token of new Set(bundle.match(JWT) ?? [])) {
    if (jwtRole(token) === "anon") return token;
  }
  return null;
}

export function findSecrets(bundle: string): SecretHit[] {
  const out: SecretHit[] = [];

  for (const token of new Set(bundle.match(JWT) ?? [])) {
    if (jwtRole(token) === "service_role") {
      out.push({
        name: "Supabase service_role key",
        redacted: redact(token),
        note: "bypasses every database permission rule you have",
      });
    }
  }

  for (const p of PATTERNS) {
    for (const hit of new Set(bundle.match(p.re) ?? [])) {
      out.push({ name: p.name, redacted: redact(hit), note: p.note });
    }
  }

  return out;
}
