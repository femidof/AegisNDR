const ALERT_STATUS_TO_DISPLAY = {
  open: "New",
  triaged: "Acknowledged",
  investigating: "Under Investigation",
  resolved: "Closed",
  dismissed: "Dismissed",
};

const DISPLAY_TO_ALERT_STATUS = Object.fromEntries(
  Object.entries(ALERT_STATUS_TO_DISPLAY).map(([api, display]) => [display, api]),
);

const CASE_STATUS_TO_DISPLAY = {
  open: "Open",
  in_progress: "In progress",
  resolved: "Resolved",
  closed: "Closed",
};

const DISPLAY_TO_CASE_STATUS = Object.fromEntries(
  Object.entries(CASE_STATUS_TO_DISPLAY).map(([api, display]) => [display, api]),
);

const CASE_PRIORITY_TO_DISPLAY = { critical: "P1", high: "P2", medium: "P3", low: "P4" };

function titleCase(value) {
  return String(value || "").replaceAll("_", " ").replaceAll("-", " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

export function formatUtc(value, { seconds = true } = {}) {
  if (!value) return "—";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return String(value);
  return parsed.toISOString().replace("T", " ").slice(0, seconds ? 19 : 16) + " UTC";
}

export function mapAlert(record) {
  if (!record || typeof record.alert_id !== "string") throw new TypeError("Invalid alert response record");
  const entity = String(record.entity_id || "Unknown entity");
  return {
    id: record.alert_id,
    title: String(record.title || "Untitled alert"),
    severity: titleCase(record.severity),
    status: ALERT_STATUS_TO_DISPLAY[record.status] || titleCase(record.status),
    apiStatus: record.status,
    source: entity,
    sourceIp: entity,
    destination: "See local evidence",
    detector: titleCase(record.detector_id),
    detectorId: record.detector_id,
    entityType: record.entity_type,
    entityId: entity,
    score: Number(record.score || 0),
    evidenceIds: Array.isArray(record.evidence_ids) ? record.evidence_ids : [],
    baseline: record.baseline && typeof record.baseline === "object" ? record.baseline : {},
    features: record.features && typeof record.features === "object" ? record.features : {},
    firstSeen: formatUtc(record.created_at),
    lastSeen: formatUtc(record.created_at),
    createdAt: record.created_at,
  };
}

export function alertStatusForApi(displayStatus) {
  const status = DISPLAY_TO_ALERT_STATUS[displayStatus] || String(displayStatus || "").toLowerCase();
  if (!Object.hasOwn(ALERT_STATUS_TO_DISPLAY, status)) throw new TypeError(`Unsupported alert status: ${displayStatus}`);
  return status;
}

export function mapCase(record) {
  if (!record || typeof record.case_id !== "string") throw new TypeError("Invalid case response record");
  const alertIds = Array.isArray(record.alert_ids) ? record.alert_ids : [];
  return {
    id: record.case_id,
    alertId: alertIds[0] || null,
    alertIds,
    title: String(record.title || "Untitled case"),
    priority: CASE_PRIORITY_TO_DISPLAY[record.priority] || titleCase(record.priority),
    apiPriority: record.priority,
    owner: record.assignee || "Unassigned",
    status: CASE_STATUS_TO_DISPLAY[record.status] || titleCase(record.status),
    apiStatus: record.status,
    updated: formatUtc(record.updated_at, { seconds: false }),
    updatedAt: record.updated_at,
  };
}

export function caseStatusForApi(displayStatus) {
  const status = DISPLAY_TO_CASE_STATUS[displayStatus] || String(displayStatus || "").toLowerCase();
  if (!Object.hasOwn(CASE_STATUS_TO_DISPLAY, status)) throw new TypeError(`Unsupported case status: ${displayStatus}`);
  return status;
}

export function mapInvestigation(record) {
  if (!record || typeof record.investigation_id !== "string") throw new TypeError("Invalid investigation response record");
  return {
    id: record.investigation_id,
    alertId: record.alert_id,
    status: record.status,
    assessment: record.assessment && typeof record.assessment === "object" ? record.assessment : null,
    errorCode: record.error_code || null,
    createdAt: record.created_at,
    updatedAt: record.updated_at,
  };
}

export function mapTransmission(record) {
  if (!record || typeof record.transmission_id !== "string") throw new TypeError("Invalid transmission response record");
  const payloadBytes = new TextEncoder().encode(JSON.stringify(record.payload || {})).byteLength;
  return {
    id: record.transmission_id,
    requestId: record.request_id,
    investigationId: record.investigation_id,
    alertId: record.alert_id,
    time: formatUtc(record.created_at),
    createdAt: record.created_at,
    purpose: "Alert assessment",
    status: record.result === "success" ? "Completed" : "Blocked by policy",
    mode: `Zero-Retention (${titleCase(record.retention_mode)})`,
    direction: payloadBytes ? "Outbound (Minimized Only)" : "None",
    bytes: payloadBytes < 1024 ? `${payloadBytes} B` : `${(payloadBytes / 1024).toFixed(2)} KB`,
    duration: `${(Number(record.latency_ms || 0) / 1000).toFixed(1)}s`,
    result: titleCase(record.result),
    failState: "Fail-Closed",
    model: [record.provider, record.model].filter(Boolean).join(" / "),
    provider: record.provider,
    region: record.region,
    retentionMode: record.retention_mode,
    fieldsIncluded: Array.isArray(record.fields_included) ? record.fields_included : [],
    fieldsRemoved: Array.isArray(record.fields_removed) ? record.fields_removed : [],
    fieldsTokenized: Array.isArray(record.fields_tokenized) ? record.fields_tokenized : [],
    promptHash: record.prompt_hash || "",
    responseHash: record.response_hash || "",
    inputTokens: Number(record.input_tokens || 0),
    outputTokens: Number(record.output_tokens || 0),
    latencyMs: Number(record.latency_ms || 0),
    errorCode: record.error_code || null,
    payload: record.payload || {},
  };
}

export function mapSensor(record) {
  return {
    name: record.sensor_id,
    type: titleCase(record.sensor_type),
    site: record.deployment_id,
    status: record.status === "online" ? "Healthy" : titleCase(record.status),
    eps: Number(record.events_per_second || 0).toLocaleString("en-US", { maximumFractionDigits: 1 }),
    lastSeen: formatUtc(record.last_seen),
  };
}

export function mapEvent(record) {
  const details = record.details && typeof record.details === "object" ? record.details : {};
  const destination = details.query || record.dst_ip || "—";
  const bytes = Number(record.bytes_out || 0) + Number(record.bytes_in || 0);
  return {
    id: record.event_id,
    eventId: record.event_id,
    eventTime: record.event_time,
    eventType: record.event_type,
    sensorId: record.sensor_id,
    eventSource: record.source,
    srcIp: record.src_ip || "",
    dstIp: record.dst_ip || "",
    srcPort: Number(record.src_port || 0),
    dstPort: Number(record.dst_port || 0),
    protocolValue: String(record.protocol || ""),
    byteCount: bytes,
    time: formatUtc(record.event_time).slice(11, 19),
    source: record.src_ip || record.entity_id || "—",
    destination,
    protocol: [String(record.protocol || "").toUpperCase(), record.dst_port].filter(Boolean).join("/"),
    bytes: bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(1)} KB`,
    verdict: record.event_type === "network.alert" ? "Suspicious" : "Allowed",
    type: titleCase(record.event_type),
    detail: details.signature || details.query || `${record.source || "local"} event`,
    captured: formatUtc(record.event_time),
  };
}

export function mapAuditEvent(record) {
  return {
    id: record.audit_id,
    time: formatUtc(record.created_at),
    actor: record.actor_id,
    action: titleCase(String(record.action || "").replaceAll(".", " ")),
    object: record.resource_id,
    outcome: titleCase(record.result),
  };
}

export class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

function items(payload) {
  if (!payload || !Array.isArray(payload.items) || !Number.isInteger(payload.count) || payload.count < 0) {
    throw new ApiError(502, "invalid_api_response", "The local API returned an invalid collection.");
  }
  return payload.items;
}

export function createDashboardApi({ baseUrl = "", deploymentId, getAccessToken, fetchImpl = globalThis.fetch?.bind(globalThis) }) {
  if (!deploymentId || !getAccessToken || !fetchImpl) throw new TypeError("Dashboard API requires deploymentId, getAccessToken, and fetch.");
  const normalizedBase = String(baseUrl).replace(/\/+$/, "");

  async function request(path, { method = "GET", body, retry = true, signal = AbortSignal.timeout(15_000) } = {}) {
    const token = await getAccessToken({ forceRefresh: false });
    const response = await fetchImpl(`${normalizedBase}${path}`, {
      method,
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${token}`,
        "X-Deployment-ID": deploymentId,
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "same-origin",
      ...(signal ? { signal } : {}),
    });
    if (response.status === 401 && retry) {
      await getAccessToken({ forceRefresh: true });
      return request(path, { method, body, retry: false, signal });
    }
    let payload = null;
    if (response.status !== 204) {
      try {
        payload = await response.json();
      } catch {
        throw new ApiError(502, "invalid_api_response", "The local API returned a non-JSON response.");
      }
    }
    if (!response.ok) {
      const error = payload?.error;
      throw new ApiError(response.status, error?.code || "api_request_failed", error?.message || "The local API request failed.");
    }
    return payload;
  }

  return {
    request,
    async getSession() { return request("/api/v1/session"); },
    async getSystemHealth() { return request("/api/v1/system/health", { signal: AbortSignal.timeout(12_000) }); },
    async getResponseCapabilities() { return request("/api/v1/response/capabilities"); },
    async getResponsePolicy() { return request("/api/v1/response/policy"); },
    async updateResponsePolicy(changes) { return request("/api/v1/response/policy", { method: "PATCH", body: changes }); },
    async stopResponse() { return request("/api/v1/response/emergency-stop", { method: "POST", body: {} }); },
    async listResponseAssets(offset = 0) { return items(await request(`/api/v1/response/assets?limit=500&offset=${offset}`)); },
    async registerResponseAsset(asset) { return request("/api/v1/response/assets", { method: "POST", body: asset }); },
    async listResponseActions(offset = 0) { return items(await request(`/api/v1/response/actions?limit=50&offset=${offset}`)); },
    async getResponseAction(id) { return request(`/api/v1/response/actions/${encodeURIComponent(id)}`); },
    async proposeResponse(proposal) { return request("/api/v1/response/actions", { method: "POST", body: proposal }); },
    async simulateResponseAlerts(body) { return request("/api/v1/response/simulations", { method: "POST", body }); },
    async transitionResponse(id, operation, proposalHash) {
      if (!["approve", "cancel", "release"].includes(operation)) throw new TypeError("Unsupported response action.");
      return request(`/api/v1/response/actions/${encodeURIComponent(id)}/${operation}`, {
        method: "POST", body: { proposal_hash: proposalHash },
      });
    },
    async listResponseJournal(offset = 0) { return items(await request(`/api/v1/response/journal?limit=50&offset=${offset}`)); },
    async recordSession() { return request("/api/v1/session/audit", { method: "POST", body: {} }); },
    async getOverview() { return request("/api/v1/overview"); },
    async listAlerts() { return items(await request("/api/v1/alerts?limit=50")).map(mapAlert); },
    async updateAlert(id, changes) {
      const payload = { ...changes };
      if (payload.status) payload.status = alertStatusForApi(payload.status);
      return mapAlert(await request(`/api/v1/alerts/${encodeURIComponent(id)}`, { method: "PATCH", body: payload }));
    },
    async startInvestigation(alertId) {
      return mapInvestigation(await request(`/api/v1/alerts/${encodeURIComponent(alertId)}/investigate`, { method: "POST", body: {} }));
    },
    async listInvestigations() { return items(await request("/api/v1/investigations")).map(mapInvestigation); },
    async getInvestigation(id) { return mapInvestigation(await request(`/api/v1/investigations/${encodeURIComponent(id)}`)); },
    async getInvestigationTransmission(id) { return mapTransmission(await request(`/api/v1/investigations/${encodeURIComponent(id)}/transmission`)); },
    async listTransmissions() { return items(await request("/api/v1/transmissions")).map(mapTransmission); },
    async listCases() { return items(await request("/api/v1/cases")).map(mapCase); },
    async createCase(value) { return mapCase(await request("/api/v1/cases", { method: "POST", body: value })); },
    async updateCase(id, changes) {
      const payload = { ...changes };
      if (payload.status) payload.status = caseStatusForApi(payload.status);
      return mapCase(await request(`/api/v1/cases/${encodeURIComponent(id)}`, { method: "PATCH", body: payload }));
    },
    async getCase(id) { return request(`/api/v1/cases/${encodeURIComponent(id)}`); },
    async listCaseComments(id) { return items(await request(`/api/v1/cases/${encodeURIComponent(id)}/comments`)); },
    async addCaseComment(id, body) { return request(`/api/v1/cases/${encodeURIComponent(id)}/comments`, { method: "POST", body: { body } }); },
    async listSensors() { return items(await request("/api/v1/sensors")).map(mapSensor); },
    async searchEvents(criteria = {}) { return items(await request("/api/v1/events/search", { method: "POST", body: { limit: 100, ...criteria } })).map(mapEvent); },
    async listAudit() {
      const payload = await request("/api/v1/audit?limit=200");
      return { events: items(payload).map(mapAuditEvent), chainValid: payload.chain_valid === true };
    },
    async getModelPolicy() { return request("/api/v1/model-policy"); },
    async updateModelPolicy(changes) { return request("/api/v1/model-policy", { method: "PATCH", body: changes }); },
    async listDetectionRules() { return items(await request("/api/v1/detection-rules")); },
    async createDetectionRule(value) { return request("/api/v1/detection-rules", { method: "POST", body: value }); },
    async updateDetectionRule(id, changes) { return request(`/api/v1/detection-rules/${encodeURIComponent(id)}`, { method: "PATCH", body: changes }); },
    async deleteDetectionRule(id) { return request(`/api/v1/detection-rules/${encodeURIComponent(id)}`, { method: "DELETE" }); },
    async listSuppressions() { return items(await request("/api/v1/detection-suppressions")); },
    async createSuppression(value) { return request("/api/v1/detection-suppressions", { method: "POST", body: value }); },
    async updateSuppression(id, changes) { return request(`/api/v1/detection-suppressions/${encodeURIComponent(id)}`, { method: "PATCH", body: changes }); },
    async deleteSuppression(id) { return request(`/api/v1/detection-suppressions/${encodeURIComponent(id)}`, { method: "DELETE" }); },
    async listIntegrations() { return items(await request("/api/v1/integrations")); },
    async createIntegration(value) { return request("/api/v1/integrations", { method: "POST", body: value }); },
    async updateIntegration(id, changes) { return request(`/api/v1/integrations/${encodeURIComponent(id)}`, { method: "PATCH", body: changes }); },
    async deleteIntegration(id) { return request(`/api/v1/integrations/${encodeURIComponent(id)}`, { method: "DELETE" }); },
    async getSystemSettings() { return request("/api/v1/system/settings"); },
    async updateSystemSettings(changes) { return request("/api/v1/system/settings", { method: "PATCH", body: changes }); },
    async listEvidenceExports() { return items(await request("/api/v1/evidence/exports")); },
    async requestEvidenceExport(value) { return request("/api/v1/evidence/exports", { method: "POST", body: value }); },
    async approveEvidenceExport(id, justification) {
      return request(`/api/v1/evidence/exports/${encodeURIComponent(id)}/approve`, { method: "POST", body: { approved: true, justification } });
    },
    async downloadEvidenceExport(id) { return request(`/api/v1/evidence/exports/${encodeURIComponent(id)}/download`); },
    async listSupportBundles() { return items(await request("/api/v1/support-bundles")); },
    async createSupportBundle(options = {}) { return request("/api/v1/support-bundles", { method: "POST", body: options }); },
    async downloadSupportBundle(id) { return request(`/api/v1/support-bundles/${encodeURIComponent(id)}/download`); },
  };
}

export { ALERT_STATUS_TO_DISPLAY, CASE_STATUS_TO_DISPLAY };
