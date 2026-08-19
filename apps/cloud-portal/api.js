export class PortalApiError extends Error {
  constructor(message, status = 0, code = "portal_api_error") {
    super(message);
    this.name = "PortalApiError";
    this.status = status;
    this.code = code;
  }
}

export function createPortalApi({ apiBase = "/api", getAccessToken, fetchImpl = globalThis.fetch?.bind(globalThis) }) {
  if (!getAccessToken || !fetchImpl) throw new Error("Portal API requires authentication and fetch implementations.");

  async function request(path, { method = "GET", body, retry = true } = {}) {
    const token = await getAccessToken({ forceRefresh: false });
    const response = await fetchImpl(`${apiBase}${path}`, {
      method,
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${token}`,
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "omit",
    });
    if (response.status === 401 && retry) {
      await getAccessToken({ forceRefresh: true });
      return request(path, { method, body, retry: false });
    }
    let payload = null;
    try { payload = await response.json(); } catch { /* safe generic error below */ }
    if (!response.ok) {
      throw new PortalApiError(
        payload?.error?.message || "The cloud control plane could not complete the request.",
        response.status,
        payload?.error?.code || "portal_api_error",
      );
    }
    return payload;
  }

  return {
    session: () => request("/v1/portal/session"),
    organization: () => request("/v1/portal/organization"),
    updateOrganization: (values) => request("/v1/portal/organization", { method: "PATCH", body: values }),
    deployments: () => request("/v1/portal/deployments"),
    deployment: (id) => request(`/v1/portal/deployments/${encodeURIComponent(id)}`),
    enrollments: () => request("/v1/portal/enrollments"),
    createDeployment: (values) => request("/v1/portal/deployments", { method: "POST", body: values }),
    entitlements: (id) => request(`/v1/portal/deployments/${encodeURIComponent(id)}/entitlements`),
    updateEntitlements: (id, values) => request(`/v1/portal/deployments/${encodeURIComponent(id)}/entitlements`, { method: "PATCH", body: values }),
    policy: (id) => request(`/v1/portal/deployments/${encodeURIComponent(id)}/model-policy`),
    updatePolicy: (id, values) => request(`/v1/portal/deployments/${encodeURIComponent(id)}/model-policy`, { method: "PATCH", body: values }),
    updates: () => request("/v1/portal/updates"),
    updateChannel: (id, update_channel) => request(`/v1/portal/deployments/${encodeURIComponent(id)}/update-channel`, { method: "PATCH", body: { update_channel } }),
  };
}
