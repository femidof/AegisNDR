export async function loadDashboard(api) {
  const reads = [
    ["overview", () => api.getOverview(), null],
    ["alerts", () => api.listAlerts(), []],
    ["cases", () => api.listCases(), []],
    ["sensors", () => api.listSensors(), []],
    ["traffic", () => api.searchEvents(), []],
    ["transmissions", () => api.listTransmissions(), []],
    ["audit", () => api.listAudit(), { events: [], chainValid: undefined }],
    ["policy", () => api.getModelPolicy(), null],
    ["investigations", () => api.listInvestigations(), []],
    ["session", () => api.getSession(), null],
    ["rules", () => api.listDetectionRules(), null],
    ["suppressions", () => api.listSuppressions(), []],
    ["integrations", () => api.listIntegrations(), null],
    ["systemSettings", () => api.getSystemSettings(), null],
    ["exports", () => api.listEvidenceExports(), []],
    ["supportBundles", () => api.listSupportBundles(), null],
  ];
  const settled = await Promise.allSettled(reads.map(([, read]) => Promise.resolve().then(read)));
  const result = { errors: {}, dataSource: settled.some((item) => item.status === "fulfilled") ? "backend" : "error" };
  reads.forEach(([name, , empty], index) => {
    const item = settled[index];
    result[name] = item.status === "fulfilled" ? item.value : empty;
    if (item.status === "rejected") result.errors[name] = item.reason;
  });
  return result;
}

export function trustStatus({ demoMode, dataSource, health, observedAt, policy }, currentTime = Date.now()) {
  const age = currentTime - observedAt;
  const fresh = Boolean(health && observedAt && age >= 0 && age < 30_000);
  return {
    node: demoMode ? "Preview" : fresh && health.status === "healthy" ? "Healthy" : fresh && health.status === "degraded" ? "Degraded" : "Health unavailable",
    healthy: !demoMode && fresh && health.status === "healthy",
    data: demoMode ? "Explicit Demo" : dataSource === "backend" ? "Local API" : dataSource === "loading" ? "Loading" : "Unavailable",
    policy: demoMode ? "Demo" : !policy ? "Unavailable" : policy.enabled === false ? "Disabled" : policy.level || "Configured",
  };
}
