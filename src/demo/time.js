// Demo-clock helpers: all demo timestamps are anchored to "now" at module
// load so the demonstration never appears stale. Each helper takes an offset
// in milliseconds *before* the current moment.

const MINUTE = 60_000;
const HOUR = 3_600_000;
const DAY = 86_400_000;

export { MINUTE, HOUR, DAY };

export function demoDate(offsetMs = 0) {
  return new Date(Date.now() - offsetMs).toISOString().slice(0, 10);
}

export function demoStamp(offsetMs = 0) {
  // "YYYY-MM-DD HH:MM:SS UTC"
  return new Date(Date.now() - offsetMs).toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

export function demoTime(offsetMs = 0) {
  // "HH:MM:SS" (UTC)
  return new Date(Date.now() - offsetMs).toISOString().slice(11, 19);
}

export function demoCompactDate(offsetMs = 0) {
  // "YYYYMMDD" for transmission/case identifiers
  return demoDate(offsetMs).replaceAll("-", "");
}

export function demoInstant(offsetMs = 0) {
  // JavaScript Date for clocks that tick from a fixed starting point
  return new Date(Date.now() - offsetMs);
}
