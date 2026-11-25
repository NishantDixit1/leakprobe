export type Severity = "critical" | "high" | "medium" | "info";

export type Finding = {
  id: string;
  severity: Severity;
  title: string;
  /** Plain English, for someone who has never read a stack trace. */
  what: string;
  /** Why it matters, in consequences rather than jargon. */
  risk: string;
  /** Evidence actually observed. Never contains your data. */
  evidence?: string[];
  /**
   * Paste-ready instructions for Claude Code, Cursor, Lovable or Bolt.
   *
   * The point of the tool: knowing that RLS is off does not help if you
   * do not know what RLS is. The prompt is written so the assistant
   * that built the app can fix its own work.
   */
  fixPrompt: string;
};

export type ScanResult = {
  url: string;
  scannedAt: string;
  durationMs: number;
  findings: Finding[];
  /** Checks that ran and found nothing, so a clean pass is visible. */
  passed: string[];
  /** Checks that could not run, and why. Never silently dropped. */
  skipped: { check: string; reason: string }[];
  /** What the site appears to be built with. */
  stack: string[];
};
