/** An owner-supplied IANA zone name, trimmed, or undefined when Intl cannot use it.
 *
 *  Write-side guard only: a bad value must never reach the owners row, because every later calendar/freebusy
 *  answer formats dates with it. A trailing/leading space is a paste artefact, not a different zone, so it is
 *  trimmed and accepted — the trimmed name is what gets stored. Strings Intl rejects ("UTC+8", "GMT+8",
 *  "Mars/Olympus") are undefined, and the caller answers 400 invalid_timezone. Rows written before this
 *  existed are deliberately neither rewritten nor reinterpreted here. */
export function ianaTimezone(raw: unknown): string | undefined {
  if (typeof raw !== "string") return undefined;
  const tz = raw.trim();
  if (!tz) return undefined;
  try { new Intl.DateTimeFormat("en-US", { timeZone: tz }); } catch { return undefined; }
  return tz;
}

/** Minutes since local midnight of an instant in an IANA timezone. */
export function localMinutes(ms: number, tz: string): number {
  const parts = new Intl.DateTimeFormat("en-GB", { timeZone: tz, hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).formatToParts(new Date(ms));
  const h = +(parts.find((p) => p.type === "hour")?.value ?? 0);
  const m = +(parts.find((p) => p.type === "minute")?.value ?? 0);
  return h * 60 + m;
}

export function localWeekday(ms: number, tz: string): number {
  const wd = new Intl.DateTimeFormat("en-US", { timeZone: tz, weekday: "short" }).format(new Date(ms));
  return ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].indexOf(wd);
}

export function parseHours(h: string | undefined): [number, number] | null {
  if (!h) return null;
  const m = /^(\d{1,2}):(\d{2})-(\d{1,2}):(\d{2})$/.exec(h);
  if (!m) return null;
  return [+m[1] * 60 + +m[2], +m[3] * 60 + +m[4]];
}

/** Format an instant as ISO-8601 with the timezone's offset, e.g. 2026-10-21T15:00:00+08:00 */
export function isoInTz(ms: number, tz: string): string {
  const d = new Date(ms);
  const p = Object.fromEntries(new Intl.DateTimeFormat("en-CA", { timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" }).formatToParts(d).map((x) => [x.type, x.value]));
  const asUtc = Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour, +p.minute, +p.second);
  const off = Math.round((asUtc - Math.floor(ms / 1000) * 1000) / 60000);
  const sign = off >= 0 ? "+" : "-";
  const a = Math.abs(off);
  return `${p.year}-${p.month}-${p.day}T${p.hour}:${p.minute}:${p.second}${sign}${String(Math.floor(a / 60)).padStart(2, "0")}:${String(a % 60).padStart(2, "0")}`;
}

export const overlaps = (a0: number, a1: number, b0: number, b1: number) => a0 < b1 && b0 < a1;
