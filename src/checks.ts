import type { Finding, ScanResult } from "./types.js";
import { get, parseTarget } from "./fetch.js";
import { findAnonKey, findSecrets } from "./secrets.js";
import {
  cookieCheck,
  corsCheck,
  firebaseCheck,
  httpsRedirectCheck,
  classifyProbe,
  storageCheck,
  tableCoverage,
  EXTRA_PATHS,
} from "./extra-checks.js";

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
/** Names the protection in front of a site, if the response is its page. */
function detectShield(status: number, headers: Headers, body: string): string | null {
  const h = (k: string) => headers.get(k)?.toLowerCase() ?? "";

  if (h("x-vercel-mitigated").includes("challenge")) return "Vercel bot protection";
  if (h("cf-mitigated").includes("challenge")) return "Cloudflare bot protection";

  if (status === 403 || status === 429 || status === 503) {
    const server = h("server");
    const b = body.slice(0, 4000).toLowerCase();
    if (server.includes("cloudflare") || b.includes("cf-chl") || b.includes("just a moment"))
      return "Cloudflare bot protection";
    if (server.includes("vercel")) return "Vercel bot protection";
    if (b.includes("captcha") || b.includes("access denied") || b.includes("attention required"))
      return "A bot protection or firewall";
  }
  return null;
}

export type ScanOptions = {
  /**
   * How many database tables to probe. Each one is a request, so the
   * default keeps a scan quick on a large schema. Whatever it is set
   * to, the number checked and the number skipped are always reported:
   * a cap nobody is told about turns "nothing found" into a claim the
   * scan never made.
   */
  maxTables?: number;
};

export async function runScan(
  rawUrl: string,
  options: ScanOptions = {},
): Promise<ScanResult | { error: string }> {
  const started = Date.now();
  const maxTables = Math.max(1, options.maxTables ?? 25);

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

  // Bot protection answers with its own page, and every check below
  // would then be describing the challenge rather than the app: no
  // security headers, no bundle, no secrets, all of it wrong and all of
  // it stated confidently. Refuse to report instead.
  const shield = detectShield(page.status, page.headers, page.body);
  if (shield) {
    return {
      error: `${shield} answered instead of your app, so there is nothing real to check. This usually means the scan is being treated as a bot. Try from a different network, or allow your own address in the protection settings while you run it.`,
    };
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

  // ── Session cookie flags ───────────────────────────────────────────
  const cookieFinding = cookieCheck(page.cookies, target.url.protocol === "https:");
  if (cookieFinding) findings.push(cookieFinding);
  else if (page.cookies.length > 0) passed.push("Session cookies carry the usual flags");
  else
    skipped.push({
      check: "Session cookie flags",
      reason:
        "This request set no cookies, so there was nothing to judge. A site that only sets a session after sign-in will not be covered by a scan of the public page.",
    });

  // ── Plain http, and who may call the app ───────────────────────────
  if (target.url.protocol === "https:") {
    const redirectFinding = await httpsRedirectCheck(target.url.hostname);
    if (redirectFinding) findings.push(redirectFinding);
    else passed.push("Plain http redirects to https");
  }

  const corsFinding = await corsCheck(target.url.toString());
  if (corsFinding) findings.push(corsFinding);
  else passed.push("No site is allowed to call your app on a user's behalf");

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

  // ── Firebase, which fails the same way Supabase does ───────────────
  const firebaseFinding = await firebaseCheck(bundle);
  if (firebaseFinding) {
    stack.add("Firebase");
    findings.push(firebaseFinding);
  } else if (stack.has("Firebase")) {
    passed.push("Firebase database refused an anonymous read");
  } else {
    skipped.push({ check: "Firebase rules", reason: "No Firebase database found in this app." });
  }

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
  if (!mapRef || !firstScript) {
    passed.push("Source maps are not referenced in the published bundle");
  }
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
      const cover = tableCoverage(tables.length, maxTables);
      const coverage = cover.label;

      const open: string[] = [];
      // A 200 with an empty array means the request was permitted and
      // there was simply nothing to hand back. That is what an
      // unprotected empty table looks like, and also what a correctly
      // scoped policy looks like when auth.uid() filters every row for
      // an anonymous caller. The two are indistinguishable from
      // outside, so neither "leaking" nor "refused" is an honest
      // answer. Reported by a reader: counting these as refused meant a
      // pre-launch app with empty tables scanned clean and opened up
      // the moment real users signed up.
      const answeredEmpty: string[] = [];

      for (const table of tables.slice(0, cover.checked)) {
        const probe = await get(
          `${supaUrl}/rest/v1/${encodeURIComponent(table)}?select=*&limit=1`,
          { headers: auth, maxBytes: 50_000, timeoutMs: 5_000 },
        );
        if (!probe) continue;
        const outcome = classifyProbe(probe.status, probe.body);
        if (outcome === "answered-empty") {
          answeredEmpty.push(table);
        } else if (outcome === "open") {
          // Column names only. Row contents are never surfaced.
          const rows = JSON.parse(probe.body) as object[];
          const cols = Object.keys(rows[0] as object).slice(0, 8).join(", ");
          open.push(`${table} — returned a row to an anonymous request (columns: ${cols})`);
        }
      }

      if (open.length > 0) {
        findings.push({
          id: "rls",
          severity: "critical",
          title: "Your database is answering strangers",
          what: `We asked your database for a row from ${open.length} table${open.length > 1 ? "s" : ""} without logging in, and it handed ${open.length > 1 ? "them" : "it"} over. Anyone on the internet can do the same. We ${coverage}.`,
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
      } else if (answeredEmpty.length === 0) {
        passed.push(`Database refused anonymous read requests (${coverage})`);
      }

      if (answeredEmpty.length > 0) {
        skipped.push({
          check: "Database permissions on tables that answered with no rows",
          reason: `${answeredEmpty.length} table${answeredEmpty.length > 1 ? "s" : ""} accepted an anonymous request and returned no rows: ${answeredEmpty.slice(0, 8).join(", ")}${answeredEmpty.length > 8 ? ", and others" : ""}. That is what a correctly scoped policy looks like, and also what an unprotected empty table looks like, and the two cannot be told apart from outside. If ${answeredEmpty.length > 1 ? "any of these are" : "this is"} empty right now rather than protected, ${answeredEmpty.length > 1 ? "they" : "it"} will start handing rows over as soon as real users sign up. Check the policies in the Supabase dashboard.`,
        });
      }

      if (cover.note) skipped.push(cover.note);
    }
    const storageFinding = await storageCheck(supaUrl, anonKey);
    if (storageFinding) findings.push(storageFinding);
    else passed.push("Storage buckets are not listable anonymously");
  } else if (stack.has("Supabase")) {
    skipped.push({
      check: "Database permissions and storage",
      reason: "Supabase detected but no public key was found to test with.",
    });
  } else {
    skipped.push({
      check: "Database permissions and storage",
      reason: "No Supabase project found in this app.",
    });
  }

  // ── Files that should never be served ──────────────────────────────
  //
  // A single-page app answers 200 with index.html for every unknown
  // path, which is most of the audience for this tool: Vite, React
  // Router, anything built in Lovable or Bolt. Testing status alone, or
  // testing the body loosely, reports every one of them as leaking a
  // .env file. A critical false positive on the common case is worse
  // than missing the finding entirely.
  //
  // So: establish the host's behaviour on a path that certainly does
  // not exist, then require the response to differ from it AND to
  // actually look like the file being asked for.
  const decoy = await get(`${origin}/leakprobe-${Date.now().toString(36)}-404`, {
    maxBytes: 20_000,
    timeoutMs: 5_000,
  });
  const spaFallback = decoy?.status === 200;

  const ENV_SHAPE = /^\s*(?:export\s+)?[A-Z_][A-Z0-9_]*\s*=/m;
  const SENSITIVE: { path: string; looksReal: RegExp }[] = [
    // An env file is KEY=value lines, not markup.
    { path: "/.env", looksReal: ENV_SHAPE },
    { path: "/.env.local", looksReal: ENV_SHAPE },
    { path: "/.env.production", looksReal: ENV_SHAPE },
    { path: "/.git/config", looksReal: /\[core\]/ },
    ...EXTRA_PATHS.map(({ path, looksReal }) => ({ path, looksReal })),
  ];

  const exposed: string[] = [];
  for (const { path, looksReal } of SENSITIVE) {
    const res = await get(`${origin}${path}`, { maxBytes: 20_000, timeoutMs: 5_000 });
    if (!res || res.status !== 200) continue;
    // Markup is the app answering, never the file itself.
    if (/html/i.test(res.headers.get("content-type") ?? "")) continue;
    if (/^\s*<(?:!doctype|html)/i.test(res.body)) continue;
    // Same bytes as a path that does not exist means a catch-all route.
    if (spaFallback && decoy && res.body === decoy.body) continue;
    if (!looksReal.test(res.body)) continue;
    exposed.push(path);
  }

  if (spaFallback && exposed.length === 0) {
    skipped.push({
      check: "Exposed configuration files",
      reason:
        "This host answers 200 for paths that do not exist, so a served file cannot be told apart from the app's catch-all route by status alone. Checked the response contents instead and none looked like a real config file.",
    });
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
  } else if (!spaFallback) {
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
