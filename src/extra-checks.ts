import type { Finding } from "./types.js";
import { get } from "./fetch.js";

/**
 * Checks beyond the original five.
 *
 * Same rule as the rest: read only what is already public, never print
 * anyone's data, and prefer a skipped check over a guessed one.
 */

// ── Firebase: the database that answers anyone ──────────────────────
//
// The Realtime Database exposes every path as JSON. With default rules
// left open, a GET on /.json returns the whole tree. shallow=true asks
// for key names only, which is enough to prove the door is open without
// pulling anyone's records through it.
export async function firebaseCheck(bundle: string): Promise<Finding | null> {
  const host = bundle.match(/https:\/\/[a-z0-9-]+(?:-default-rtdb)?\.(?:firebaseio\.com|[a-z0-9-]+\.firebasedatabase\.app)/i)?.[0];
  if (!host) return null;

  const res = await get(`${host}/.json?shallow=true&limitToFirst=1`, { maxBytes: 20_000, timeoutMs: 8_000 });
  if (!res || res.status !== 200) return null;

  // "null" means the database is reachable but empty at the root, which
  // is not proof of anything. Permission denied arrives as 401.
  const body = res.body.trim();
  if (body === "null" || body === "" || body === "{}") return null;

  let keys: string[] = [];
  try {
    const parsed: unknown = JSON.parse(body);
    if (parsed && typeof parsed === "object") keys = Object.keys(parsed).slice(0, 8);
  } catch {
    return null;
  }
  if (keys.length === 0) return null;

  return {
    id: "firebase-rules",
    severity: "critical",
    title: "Your Firebase database is readable by anyone",
    what: `We read the top level of your Realtime Database without signing in, and it listed ${keys.length} path${keys.length > 1 ? "s" : ""}.`,
    risk:
      "Firebase rules default to open while you are developing and there is no warning when you ship. Anyone who finds the database URL in your app's JavaScript, which is everyone, can read the whole tree.",
    evidence: [`${host} returned: ${keys.join(", ")}`],
    fixPrompt: `My Firebase Realtime Database is readable without authentication. Lock it down.

1. Open the Rules tab for the database and replace any rule using ".read": true at the root.
2. Scope every path to its owner, normally "auth != null && auth.uid == $uid" for per-user data.
3. Write the rules per path rather than one rule at the root, and tell me which paths you made public on purpose.
4. If any path must stay public, such as published content, leave only .read open on that path and keep .write closed.

Then give me the rules JSON and a test showing a signed-out request is refused.`,
  };
}

// ── Supabase Storage: buckets anyone can list ───────────────────────
export async function storageCheck(supaUrl: string, anonKey: string): Promise<Finding | null> {
  const auth = { apikey: anonKey, Authorization: `Bearer ${anonKey}` };
  const res = await get(`${supaUrl}/storage/v1/bucket`, { headers: auth, maxBytes: 50_000, timeoutMs: 8_000 });
  if (!res || res.status !== 200) return null;

  let buckets: { name?: string; public?: boolean }[] = [];
  try {
    const parsed: unknown = JSON.parse(res.body);
    if (Array.isArray(parsed)) buckets = parsed as typeof buckets;
  } catch {
    return null;
  }
  if (buckets.length === 0) return null;

  const names = buckets.map((b) => b.name).filter((n): n is string => typeof n === "string");
  const open = buckets.filter((b) => b.public === true).map((b) => b.name).filter(Boolean);

  return {
    id: "storage-buckets",
    severity: open.length > 0 ? "high" : "medium",
    title:
      open.length > 0
        ? "Your storage buckets are listed, and some are public"
        : "Anyone can list your storage buckets",
    what:
      open.length > 0
        ? `An anonymous request listed your buckets, and ${open.length} of them ${open.length > 1 ? "are" : "is"} marked public: ${open.join(", ")}.`
        : "An anonymous request was able to list the names of every storage bucket in your project.",
    risk:
      "A public bucket serves every file in it to anyone with the URL, and listing bucket names tells someone exactly where to look. Uploads, invoices and user avatars commonly end up in one.",
    evidence: [`buckets visible: ${names.join(", ")}`],
    fixPrompt: `My Supabase storage buckets are listable by anonymous requests${open.length ? ` and these are public: ${open.join(", ")}` : ""}. Fix this.

1. For every bucket that does not need to serve files to the open internet, turn off the public flag.
2. Add storage policies scoping objects to their owner, normally on the owner column or a path prefix containing auth.uid().
3. For files that must be shareable, use signed URLs with an expiry instead of a public bucket.
4. Tell me which buckets you left public and why.

Then give me the SQL for the storage policies.`,
  };
}

// ── Cookies: session flags ──────────────────────────────────────────
export function cookieCheck(cookies: string[], isHttps: boolean): Finding | null {
  if (cookies.length === 0) return null;

  const problems: string[] = [];
  for (const raw of cookies.slice(0, 12)) {
    const name = raw.split("=")[0]?.trim() ?? "cookie";
    const lower = raw.toLowerCase();
    // Only judge cookies that plausibly carry a session. A theme
    // preference without HttpOnly is not a finding.
    const sessionish = /sess|auth|token|sid|jwt|login|user/i.test(name);
    if (!sessionish) continue;

    const missing: string[] = [];
    if (!lower.includes("httponly")) missing.push("HttpOnly");
    if (isHttps && !lower.includes("secure")) missing.push("Secure");
    if (!lower.includes("samesite")) missing.push("SameSite");
    if (missing.length > 0) problems.push(`${name} is missing ${missing.join(", ")}`);
  }

  if (problems.length === 0) return null;

  return {
    id: "cookie-flags",
    severity: "medium",
    title: "Session cookies are missing protective flags",
    what: `${problems.length} cookie${problems.length > 1 ? "s that look like they carry a session are" : " that looks like it carries a session is"} set without the usual flags.`,
    risk:
      "Without HttpOnly a script on the page can read the cookie and take over the session. Without Secure it can travel over plain http. Without SameSite another site can make requests as the logged-in user.",
    evidence: problems,
    fixPrompt: `My app sets session cookies without the right flags: ${problems.join("; ")}. Set HttpOnly, Secure and SameSite=Lax on every cookie carrying authentication, and tell me which file you changed. If I am using a hosted auth provider, check whether this is configuration on their side rather than mine.`,
  };
}

// ── CORS: who is allowed to call your API as the user ───────────────
export async function corsCheck(origin: string): Promise<Finding | null> {
  const probe = "https://leakprobe-cors-test.example";
  const res = await get(origin, { headers: { origin: probe }, maxBytes: 10_000, timeoutMs: 8_000 });
  if (!res) return null;

  const allow = res.headers.get("access-control-allow-origin");
  const creds = res.headers.get("access-control-allow-credentials");
  if (!allow) return null;

  // Reflecting an arbitrary origin while allowing credentials is the
  // combination that actually lets another site act as the signed-in
  // user. A bare * cannot carry credentials, so it is far less serious.
  const reflects = allow === probe;
  const wildcardWithCreds = allow === "*" && creds === "true";
  if (!reflects && !wildcardWithCreds) return null;

  return {
    id: "cors",
    severity: reflects && creds === "true" ? "high" : "medium",
    title: "Any website is allowed to call your app",
    what: reflects
      ? `Your app echoed back an origin we invented, which means it accepts requests from any site${creds === "true" ? ", and allows them to send the user's credentials" : ""}.`
      : "Your app allows any origin and permits credentials to be sent with the request.",
    risk:
      "A page the user visits elsewhere can make requests to your app in their browser. Where credentials are allowed, those requests run as the signed-in user and the response is readable by the attacking page.",
    evidence: [`Access-Control-Allow-Origin: ${allow}`, `Access-Control-Allow-Credentials: ${creds ?? "not set"}`],
    fixPrompt: `My app reflects any Origin in Access-Control-Allow-Origin${creds === "true" ? " while also allowing credentials" : ""}. Replace this with an allow-list of the exact origins that need access, reject everything else, and never combine a reflected or wildcard origin with Access-Control-Allow-Credentials. Tell me which file sets these headers and show me the diff.`,
  };
}

// ── Plain http that does not go to https ────────────────────────────
export async function httpsRedirectCheck(hostname: string): Promise<Finding | null> {
  const res = await get(`http://${hostname}/`, { redirect: "manual", maxBytes: 5_000, timeoutMs: 8_000 });
  if (!res) return null;

  const location = res.headers.get("location") ?? "";
  const redirectsToHttps = res.status >= 300 && res.status < 400 && location.startsWith("https://");
  if (redirectsToHttps) return null;
  // A host that simply refuses plain http is doing the right thing.
  if (res.status >= 400) return null;

  return {
    id: "https-redirect",
    severity: "medium",
    title: "Plain http is served instead of redirecting to https",
    what: `http://${hostname} answered with ${res.status} rather than sending the browser to the secure address.`,
    risk:
      "Anyone on the same network as your user can read and change traffic on that first request, including the page that asks for their password.",
    evidence: [`http://${hostname} returned ${res.status}${location ? ` to ${location}` : ""}`],
    fixPrompt: `Requests to my site over plain http are served instead of redirecting to https. Add a permanent redirect from http to https for every path, and add a Strict-Transport-Security header so browsers stop trying http at all. Tell me where to configure this for my host, whether that is Vercel, Netlify, Cloudflare or nginx.`,
  };
}

/** Files that should never be reachable, beyond the env and git ones. */
export const EXTRA_PATHS: { path: string; label: string; looksReal: RegExp }[] = [
  { path: "/.DS_Store", label: "macOS folder index", looksReal: /^\x00\x00\x00\x01Bud1/ },
  { path: "/backup.sql", label: "database backup", looksReal: /CREATE TABLE|INSERT INTO|PostgreSQL database dump/i },
  { path: "/dump.sql", label: "database backup", looksReal: /CREATE TABLE|INSERT INTO|PostgreSQL database dump/i },
  { path: "/db.sqlite", label: "SQLite database", looksReal: /^SQLite format 3/ },
  { path: "/.npmrc", label: "npm credentials", looksReal: /_authToken|registry=/ },
  { path: "/config.json", label: "configuration file", looksReal: /"(?:password|secret|apiKey|api_key|token)"\s*:/i },
];
