export function trafficSeries(rows, now = Date.now()) {
  const buckets = Array(12).fill(0);
  for (const row of rows) {
    const age = now - Date.parse(row.eventTime);
    if (Number.isFinite(age) && age >= 0 && age < 60_000) buckets[11 - Math.floor(age / 5000)] += 1;
  }
  return buckets;
}

export function trafficGroups(rows, field) {
  const counts = new Map();
  for (const row of rows) {
    const name = String(row[field] || (field === "protocolValue" ? row.protocol?.split("/")[0] : null) || "Unknown");
    counts.set(name, (counts.get(name) || 0) + 1);
  }
  return [...counts].sort((a, b) => b[1] - a[1]).slice(0, 5);
}
