# leakprobe

**Is your deployed app leaking anything?** One command, no install, no signup, no account.

```bash
npx leakprobe https://myapp.com
```

Built something with Lovable, Bolt, Replit, v0 or Claude Code? It works. That is what those tools are good at. What they do not reliably produce is the part that makes software safe for strangers, and none of it is visible from using the app.

A missing database permission does not break anything. The app works perfectly for you, for your test account, and for your first ten customers. It works right up until somebody types a different URL.

This tells you, in about five seconds, whether that somebody would get anything.

---

## What it checks

| Check | What it means |
| --- | --- |
| **Database answers strangers** | Asks your Supabase database for a row without logging in. If it hands one over, that table is public. |
| **Firebase rules left open** | Reads the top level of your Realtime Database as an anonymous visitor. Key names only, never your records. |
| **Secret keys in your bundle** | Reads the JavaScript every visitor downloads, looking for keys that should have stayed on your server. |
| **Public storage buckets** | Checks whether your Supabase buckets can be listed anonymously, and which are serving files to anyone. |
| **Downloadable config files** | Requests `.env`, `.git/config`, `backup.sql`, `db.sqlite`, `.npmrc` and others the way anyone could. |
| **Session cookie flags** | HttpOnly, Secure and SameSite on the cookies that carry a login. |
| **CORS that trusts anyone** | Sends an invented Origin to see whether your app will take requests, and credentials, from any site. |
| **Plain http served** | Checks that http redirects to https instead of answering. |
| **Public source maps** | Checks whether your original, uncompressed source is republished alongside the build. |
| **Security headers** | CSP, HSTS, `X-Content-Type-Options`, frame protection. |

Detects Next.js, Vite, Supabase, Firebase, Stripe and Clerk, and adapts what it runs to what it finds.

## Example

```
leakprobe  https://myapp.com
detected: Vite, Supabase

CRITICAL  Your database is answering strangers
  We asked your database for a row from 3 tables without logging in,
  and it handed them over. Anyone on the internet can do the same.
    · profiles — returned a row to an anonymous request (columns: id, email, full_name)
    · orders — returned a row to an anonymous request (columns: id, user_id, total)
    · messages — returned a row to an anonymous request (columns: id, body, sender)

CRITICAL  Secret keys are published in your website code
    · OpenAI API key (sk-pro…bQ3f) — lets anyone spend on your OpenAI account

ok  Served over HTTPS
ok  No configuration files exposed
```

## Getting the fix, not just the diagnosis

Knowing that row level security is off does not help if you do not know what row level security is.

```bash
npx leakprobe https://myapp.com --fix
```

Every finding comes with a paste-ready prompt written for the assistant that built your app. Copy it into Claude Code, Cursor, Lovable or Bolt and it makes the change in your codebase. You do not need to understand the fix to apply it, though you should read what the assistant proposes before accepting it.

## In CI

Exit codes are chosen for this:

| Code | Meaning |
| --- | --- |
| `0` | Clean, or only findings below your threshold |
| `1` | Could not run: bad address, host unreachable |
| `2` | Found something at or above `--fail-on` |

```yaml
- name: Check the deploy is not leaking
  run: npx leakprobe https://myapp.com --fail-on=high
```

## Options

```
--json              Machine-readable output
--fix               Print the paste-ready fix prompt for each finding
--fail-on=<level>   critical | high | medium   (default: high)
--quiet             Only print findings, not what passed
-h, --help
-v, --version
```

## Programmatic use

```ts
import { runScan } from "leakprobe";

const result = await runScan("https://myapp.com");
if ("error" in result) throw new Error(result.error);

const critical = result.findings.filter((f) => f.severity === "critical");
```

Fully typed. Zero runtime dependencies. Node 18 or newer.

## What it does not do

Every check reports itself as passed, failed or skipped, so a short report is never mistaken for a clean one. If your app has no Supabase project, you will see that written down rather than silently omitted.

If the site is behind Cloudflare or Vercel bot protection, the scan refuses to run rather than describing the challenge page, which would otherwise look like an app with no security headers and no JavaScript.

It does not test anything that needs the app actually running: how your login flow behaves in use, file uploads, or bugs that only appear under real traffic. It does not judge whether your business rules are correct, because that is a question about your intent rather than your code. Known vulnerabilities in your packages are better handled by GitHub's Dependabot, which is free.

It is a smoke test for the failures that end companies rather than embarrass them. It is not a penetration test.

## Is this safe to run on production?

Yes. Every check is read-only.

- It reads **only what is already public**: the pages and scripts any browser downloads, the response headers, and what your database hands to an anonymous request.
- It asks your database for **one row** from each table, the same way your own app does.
- **Nothing is written, changed or deleted.** No vulnerability is exploited and nothing is brute forced.
- **Your data never leaves your machine.** A leaking table is reported by name and column names only. Row contents are never printed, stored or transmitted. Secrets are redacted to first and last characters.
- There is no server. The scan runs entirely in your terminal.

Everything it finds is already visible to anyone who opens developer tools. That is the point.

**Only point it at a site you own or are authorised to test.**

## Why this exists

We kept being handed apps built in a weekend with an AI builder, live, with real customers in them, and the same four things were wrong every time. This is those four checks, extracted so you can run them yourself before you need us.

There is a hosted version at [stackwrights.com/tools/launch-check](https://stackwrights.com/tools/launch-check) if you would rather paste a URL into a page, and it can also read a connected repository, which goes considerably deeper than a scan from outside.

## Tests

```bash
npm test
```

60 tests. The secret patterns are tested against real key formats and
against source that must *not* trip them, because a false positive is
the failure mode that matters here. The scan itself is tested end to end
against a deliberately leaking fixture server rather than a mocked
fetch, including an assertion that no finding ever contains row data or
an unredacted secret.

## Contributing

Issues and pull requests welcome, particularly:

- More secret patterns. The list in `src/secrets.ts` is deliberately conservative, because a false positive on a security report costs more than a miss.
- Firestore rules. The Realtime Database is covered; Firestore needs collection names to probe and there is no reliable way to discover them from outside yet.
- Checks for stacks beyond Supabase and Firebase.

## Licence

MIT. Built by [Stackwrights](https://stackwrights.com).
