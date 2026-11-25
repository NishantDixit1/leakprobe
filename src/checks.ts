import type { Finding, ScanResult } from "./types.js";
import { get, parseTarget } from "./fetch.js";
import { findAnonKey, findSecrets } from "./secrets.js";

/**
 * What a stranger can see, reported in language you can act on.
 *
 * Every check observes something already public: the JavaScript the
 * browser downloads, the response headers, and what the database hands
 * to an anonymous request. Nothing is exploited and nothing is brute
 * forced. The same information is available to anyone who opens dev
 * tools, which is exactly why it is worth checking.
 *
 * Findings never include your data. A table that leaks is reported by
 * name and column names only, never row contents.
 */
export async function runScan(rawUrl: string): Promise<ScanResult | { error: string }> {
  const started = Date.now();

  const target = parseTarget(rawUrl);
  if (!target.ok) return { error: target.reason };

  const origin = target.url.origin;
  const findings: Finding[] = [];
  const passed: string[] = [];
  const skipped: { check: string; reason: string }[] = [];
  const stack = new Set<string>();

  const page = await get(target.url.toString());
  if (!page) {
    return { error: "Could not load that page. Check the address is live and reachable." };
  }

  // ── Security headers ───────────────────────────────────────────────
  const h = page.headers;
  const csp = h.get("content-security-policy");
  const missingHeaders: string[] = [];
  if (!csp) missingHeaders.push("Content-Security-Policy");
  if (!h.get("strict-transport-security")) missingHeaders.push("Strict-Transport-Security");
  if (!h.get("x-content-type-options")) missingHeaders.push("X-Content-Type-Options");
  if (!h.get("x-frame-options") && !csp?.includes("frame-ancestors")) {
    missingHeaders.push("X-Frame-Options or frame-ancestors");
  }

  if (missingHeaders.length > 0) {
    findings.push({
      id: "headers",
      severity: "medium",
      title: "Missing security headers",
      what: `Your site does not send ${missingHeaders.length} standard protective header${missingHeaders.length > 1 ? "s" : ""}.`,
      risk:
        "These headers stop another site embedding yours to trick your users, and limit the damage if a malicious script ever reaches a page. They are a few lines of config.",
      evidence: missingHeaders,
      fixPrompt: `Add security headers to my app. Set these response headers on every route:

${missingHeaders.map((m) => `- ${m}`).join("\n")}

If this is a Next.js project, add a headers() function in next.config.ts. If it is Vite or plain React on Vercel or Netlify, add them in vercel.json or netlify.toml. Use a Content-Security-Policy that allows only the third-party domains my app actually calls, and tell me which domains you allowed and why.`,
    });
  } else {
    passed.push("Security headers are present");
  }

  if (target.url.protocol === "https:") passed.push("Served over HTTPS");

  // ── Collect the JavaScript the browser downloads ───────────────────
  const scriptSrcs = [...page.body.matchAll(/<script[^>]+src=["']([^"']+)["']/g)]
    .map((m) => m[1])
    .map((src) => {
      try {
        return src ? new URL(src, origin).toString() : null;
      } catch {
        return null;
      }
    })
    .filter((u): u is string => u !== null && u.startsWith(origin))
    .slice(0, 12); // bounded: enough to find a leak, not a full crawl

  if (/_next\//.test(page.body)) stack.add("Next.js");
  if (/\/assets\/index-[A-Za-z0-9]+\.js/.test(page.body)) stack.add("Vite");

  let bundle = page.body;
  for (const src of scriptSrcs) {
    const js = await get(src, { maxBytes: 1_500_000 });
    if (js?.body) bundle += "\n" + js.body;
  }

  if (/supabase\.co/i.test(bundle)) stack.add("Supabase");
  if (/firebaseio|firebaseapp/i.test(bundle)) stack.add("Firebase");
  if (/js\.stripe\.com/i.test(bundle)) stack.add("Stripe");
  if (/clerk\./i.test(bundle)) stack.add("Clerk");

  // ── Exposed secrets ────────────────────────────────────────────────
  const leaked = findSecrets(bundle).map((s) => `${s.name} (${s.redacted}) — ${s.note}`);

  if (leaked.length > 0) {
    findings.push({
      id: "secrets",
      severity: "critical",
      title: "Secret keys are published in your website code",
      what:
        "These keys are inside the JavaScript every visitor downloads. Anyone can read them with the browser's developer tools in about ten seconds.",
      risk:
        "Each of these can be used by a stranger right now. Changing the code is not enough on its own, because the old key is already out there and may be in your git history. Every key below must be replaced with a new one and the old one switched off.",
      evidence: leaked,
      fixPrompt: `My deployed site has secret keys visible in the browser bundle. Fix this.

Keys found:
${leaked.map((l) => `- ${l.split(" — ")[0]}`).join("\n")}

Do all of the following:
1. Find every place these keys are used in my codebase.
2. Move each one to a server-only environment variable. In Next.js that means a variable WITHOUT the NEXT_PUBLIC_ prefix, used only in a route handler, server action or server component. In Vite, anything prefixed VITE_ is public, so it must move to a backend endpoint instead.
3. Create a server-side API route for each piece of work that needs the key, and have the frontend call that route instead of calling the third-party service directly.
4. Confirm no secret remains anywhere under a NEXT_PUBLIC_ or VITE_ prefix.
5. List every key I now need to rotate in the provider dashboard, and the exact page to do it on.

Then show me the diff before applying it.`,
    });
  } else {
    passed.push("No secret keys found in the published JavaScript");
  }

  // ── Source maps ────────────────────────────────────────────────────
  const mapRef = bundle.match(/\/\/# sourceMappingURL=([^\s*]+)/)?.[1];
  const firstScript = scriptSrcs[0];
  if (mapRef && firstScript) {
    const mapUrl = new URL(mapRef, firstScript).toString();
    const map = await get(mapUrl, { maxBytes: 200_000 });
    if (map && map.status === 200 && map.body.includes('"sources"')) {
      findings.push({
        id: "sourcemaps",
        severity: "medium",
        title: "Your original source code is downloadable",
        what:
          "Source maps are published alongside your site, so anyone can reconstruct your original, uncompressed code including comments.",
        risk:
          "It does not break anything by itself, but it hands a stranger a readable map of your app: route names, internal API calls, and any comment you would not want read aloud.",
        evidence: [mapUrl],
        fixPrompt: `My production build is publishing source maps publicly. Turn them off for production builds only, keeping them for local development. If this is Next.js set productionBrowserSourceMaps to false in next.config.ts. If it is Vite set build.sourcemap to false. Confirm which file you changed.`,
      });
    } else {
      passed.push("Source maps are not public");
    }
  }

  // ── The decisive check: does the database answer a stranger? ───────
  const supaUrl = bundle.match(/https:\/\/([a-z0-9]{20})\.supabase\.co/)?.[0];
  const anonKey = findAnonKey(bundle);

  if (supaUrl && anonKey) {
    stack.add("Supabase");
    const auth = { apikey: anonKey, Authorization: `Bearer ${anonKey}` };
    const spec = await get(`${supaUrl}/rest/v1/`, { headers: auth, maxBytes: 500_000 });

    let tables: string[] = [];
    try {
      const parsed: unknown = JSON.parse(spec?.body ?? "{}");
      const p = parsed as { definitions?: object; components?: { schemas?: object } };
      tables = Object.keys(p?.definitions ?? p?.components?.schemas ?? {});
    } catch {
      /* no spec, falls through to skipped */
    }

    if (tables.length === 0) {
      skipped.push({
        check: "Database permissions",
        reason: "Supabase was detected but the table list was not readable, which is usually a good sign.",
      });
    } else {
      const open: string[] = [];
      for (const table of tables.slice(0, 25)) {
        const probe = await get(
          `${supaUrl}/rest/v1/${encodeURIComponent(table)}?select=*&limit=1`,
          { headers: auth, maxBytes: 50_000, timeoutMs: 5_000 },
        );
        if (!probe || probe.status !== 200) continue;
        try {
          const rows: unknown = JSON.parse(probe.body);
          if (Array.isArray(rows) && rows.length > 0 && rows[0] && typeof rows[0] === "object") {
            // Column names only. Row contents are never surfaced.
            const cols = Object.keys(rows[0] as object).slice(0, 8).join(", ");
            open.push(`${table} — returned a row to an anonymous request (columns: ${cols})`);
          }
        } catch {
          /* not JSON, ignore */
        }
      }

      if (open.length > 0) {
        findings.push({
          id: "rls",
          severity: "critical",
          title: "Your database is answering strangers",
          what: `We asked your database for a row from ${open.length} table${open.length > 1 ? "s" : ""} without logging in, and it handed ${open.length > 1 ? "them" : "it"} over. Anyone on the internet can do the same.`,
          risk:
            "Whatever is in these tables is effectively public: customer records, emails, orders, messages. This is the most common serious problem in apps built with AI tools, because the code works perfectly while the data sits wide open.",
          evidence: open,
          fixPrompt: `My Supabase database is returning rows to anonymous requests. Lock it down.

Affected tables:
${open.map((o) => `- ${o.split(" — ")[0]}`).join("\n")}

For each table:
1. Enable row level security.
2. Write explicit policies for SELECT, INSERT, UPDATE and DELETE separately. Do not write one policy and assume it covers all four.
3. Each policy must scope rows to the owner, normally with auth.uid() = user_id. Never use a USING clause of true on a table holding user data.
4. If a table is genuinely meant to be public, such as a published blog post, say so explicitly and leave only SELECT open.

Then give me the SQL, and give me a test I can run as a logged-in user to confirm I cannot read another user's rows.`,
        });
      } else {
        passed.push("Database refused anonymous read requests");
      }
    }
  } else if (stack.has("Supabase")) {
    skipped.push({
      check: "Database permissions",
      reason: "Supabase detected but no public key was found to test with.",
    });
  }

  // ── Files that should never be served ──────────────────────────────
  const exposed: string[] = [];
  for (const path of ["/.env", "/.env.local", "/.env.production", "/.git/config"]) {
    const res = await get(`${origin}${path}`, { maxBytes: 20_000, timeoutMs: 5_000 });
    if (res && res.status === 200 && /=|\[core\]/.test(res.body)) exposed.push(path);
  }

  if (exposed.length > 0) {
    findings.push({
      id: "exposed-files",
      severity: "critical",
      title: "Configuration files are downloadable",
      what: `These files are being served to anyone who asks for them: ${exposed.join(", ")}.`,
      risk:
        "Environment files hold your database password and API keys. This is the most direct way an app gets taken over.",
      evidence: exposed,
      fixPrompt: `My deployed site is serving these files publicly: ${exposed.join(", ")}. Stop serving them, make sure they are in .gitignore, confirm whether they were ever committed to git history, and list every credential inside them that I now need to rotate.`,
    });
  } else {
    passed.push("No configuration files exposed");
  }

  const order = ["critical", "high", "medium", "info"];
  return {
    url: target.url.toString(),
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    findings: findings.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity)),
    passed,
    skipped,
    stack: [...stack],
  };
}
