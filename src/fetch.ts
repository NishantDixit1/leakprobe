/**
 * A bounded fetch.
 *
 * Everything this tool reads is already public, but it still reads from
 * addresses the caller supplies, so each request is capped on time and
 * on bytes. Without the byte cap one oversized bundle hangs the scan;
 * without the timeout one unresponsive host does.
 */

export type Fetched = { status: number; body: string; headers: Headers };

export async function get(
  url: string,
  opts: { headers?: Record<string, string>; maxBytes?: number; timeoutMs?: number } = {},
): Promise<Fetched | null> {
  const { headers = {}, maxBytes = 1_000_000, timeoutMs = 10_000 } = opts;
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      headers: { "user-agent": "leakprobe (+https://github.com/NishantDixit1/leakprobe)", ...headers },
      redirect: "follow",
      signal: ctl.signal,
    });

    const reader = res.body?.getReader();
    if (!reader) return { status: res.status, body: "", headers: res.headers };

    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      chunks.push(value);
      if (total >= maxBytes) {
        await reader.cancel();
        break;
      }
    }

    const buf = Buffer.concat(chunks.map((c) => Buffer.from(c)));
    return { status: res.status, body: buf.toString("utf8"), headers: res.headers };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export type UrlCheck = { ok: true; url: URL } | { ok: false; reason: string };

export function parseTarget(raw: string): UrlCheck {
  let url: URL;
  try {
    url = new URL(raw.includes("://") ? raw : `https://${raw}`);
  } catch {
    return { ok: false, reason: "That does not look like a web address." };
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    return { ok: false, reason: "Only http and https addresses can be checked." };
  }
  return { ok: true, url };
}
