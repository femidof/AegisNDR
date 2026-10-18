import { useCallback, useEffect, useRef, useState } from "react";
import { ArrowClockwise, ShieldCheck } from "@phosphor-icons/react";
import { Modal, PageHeader, Pill } from "../components/ui.jsx";

const FAMILY_NAMES = { firewall: "Firewall block", edr: "EDR isolation", agent: "Endpoint agent isolation" };
const ACTION_NAMES = {
  simulated: "Simulated · no enforcement", awaiting_approval: "Awaiting approval", queued: "Queued",
  executing: "Submitting", verifying: "Verifying restriction", succeeded: "Restriction verified",
  unknown: "Outcome unknown", release_queued: "Release requested", releasing: "Submitting release",
  release_verifying: "Verifying release", release_unknown: "Release outcome unknown",
  released: "Release verified", cancelled: "Cancelled", invalidated: "Authorization invalidated",
};
const EMPTY = { capabilities: { execution_enabled: false, permissions: [], families: [] }, policy: null,
  assets: [], actions: [], journal: [], loadedAt: null };

function displayTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unavailable" : `${date.toISOString().slice(0, 19).replace("T", " ")} UTC`;
}

function ActionState({ action }) {
  const tone = action.status.includes("unknown") ? "human" : action.status === "simulated" ? "local" : "neutral";
  return <Pill tone={tone}>{ACTION_NAMES[action.status] || action.status}</Pill>;
}

export function ResponsePage({ api, alerts = [], demoMode, notify }) {
  const [snapshot, setSnapshot] = useState(EMPTY);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [actionOffset, setActionOffset] = useState(0);
  const [journalOffset, setJournalOffset] = useState(0);
  const [selected, setSelected] = useState(null);
  const [confirmation, setConfirmation] = useState(null);
  const [batchResult, setBatchResult] = useState(null);
  const batchRequest = useRef(null);
  const generation = useRef(0);

  const load = useCallback(async () => {
    if (!api || demoMode) return;
    const current = ++generation.current;
    setLoading(true);
    try {
      const [capabilities, policy, firstAssets, nextAssets, actions, journal] = await Promise.all([
        api.getResponseCapabilities(), api.getResponsePolicy(), api.listResponseAssets(0),
        api.listResponseAssets(500), api.listResponseActions(actionOffset), api.listResponseJournal(journalOffset),
      ]);
      if (current !== generation.current) return;
      setSnapshot({ capabilities, policy, assets: [...firstAssets, ...nextAssets], actions, journal, loadedAt: new Date().toISOString() });
      setError(null);
    } catch (failure) {
      if (current === generation.current) setError(failure);
    } finally {
      if (current === generation.current) setLoading(false);
    }
  }, [api, demoMode, actionOffset, journalOffset]);

  useEffect(() => {
    load();
    return () => { generation.current += 1; };
  }, [load]);

  const { capabilities, policy, assets, actions, journal } = snapshot;
  const can = (permission) => !demoMode && !error && !loading && !busy &&
    (capabilities.permissions.includes(permission) || capabilities.permissions.includes("*"));
  const currentAction = actions.find((item) => item.action_id === selected?.action_id) || selected;

  async function perform(operation, title) {
    if (busy) return;
    setBusy(true);
    try {
      const result = await operation();
      if (result?.action_id) setSelected(result);
      setConfirmation(null);
      notify(title, result?.status === "simulated" ? "Simulation recorded. No device or firewall was changed." : "The request was saved locally. Enforcement status is shown separately.");
      await load();
      return result;
    } catch (failure) {
      notify("Response request was not confirmed", failure.message, "warning");
      // Refresh after conflicts/timeouts; do not automatically replay a mutation.
      await load();
      return null;
    } finally {
      setBusy(false);
    }
  }

  const liveReady = capabilities.execution_enabled === true;
  const policyAvailable = policy && !error;
  return (
    <div className="standard-page response-page">
      <PageHeader eyebrow="CUSTOMER-LOCAL RESPONSE" title="Response" description="Simulate containment, review exact proposals, and track verified outcomes."
        actions={<button className="outline-button" disabled={loading || busy || demoMode} onClick={load}><ArrowClockwise size={16} /> {loading ? "Refreshing…" : "Refresh"}</button>} />
      <section className="panel response-notice" aria-label="Response availability">
        <ShieldCheck size={24} />
        <div><strong>{demoMode ? "Preview only" : liveReady ? "Live integration enabled" : "Simulation only · live enforcement disabled"}</strong>
          <p>{demoMode ? "Connect to the customer Local API to register assets and record simulations. This preview does not perform response actions."
            : "A simulation is not a block or isolation. A submitted provider operation remains unverified until its effective state is confirmed."}</p>
          {snapshot.loadedAt ? <small>Last loaded {displayTime(snapshot.loadedAt)}. Refresh to retrieve current status.</small> : null}
        </div>
      </section>
      {error ? <div className="response-error" role="alert"><strong>{error.status === 403 ? "Response access required" : "Response data could not be refreshed"}</strong><p>{error.message}</p><p>Controls are disabled until response data can be loaded.</p></div> : null}
      <section className="panel workflow-card response-integrations">
        <div className="panel-heading"><h2>Integration readiness</h2><Pill>{liveReady ? "Execution enabled" : "Execution disabled"}</Pill></div>
        <div className="response-integration-grid">{Object.entries(FAMILY_NAMES).map(([family, name]) => {
          const integrations = capabilities.families.find((item) => item.family === family)?.integrations || [];
          return <article key={family}><strong>{name}</strong><p>{snapshot.loadedAt && !error ? integrations.length ? integrations.join(", ") : "No enforcement connection configured" : "Readiness unavailable"}</p><small>{family === "firewall" ? "Requires a gateway that can verify rule ownership and expiration." : "Requires stable device identity, management connectivity, and verified release."}</small></article>;
        })}</div>
      </section>
      <div className="response-layout">
        <section className="panel workflow-card">
          <div className="panel-heading"><h2>Response policy</h2><Pill tone="local">{policy?.mode || "Off / unavailable"}</Pill></div>
          <p>Allow specific device groups and response families before simulation. Critical assets are excluded.</p>
          {policyAvailable ? <PolicyForm key={policy.version} policy={policy} canManage={can("response:manage")} busy={busy}
            onSave={(changes) => perform(() => api.updateResponsePolicy(changes), "Response policy saved")} />
            : <p>{loading ? "Loading response policy…" : "No policy loaded."}</p>}
          <div className="response-stop">
            <strong>{policy?.emergency_stop ? "Emergency stop is active" : "Emergency stop"}</strong>
            <p>Prevent new enforcement. Existing restrictions and in-flight provider operations require separate recovery.</p>
            <button className="outline-button" disabled={!can("response:stop") || policy?.emergency_stop}
              onClick={() => setConfirmation({ operation: "stop" })}>Stop new enforcement</button>
          </div>
        </section>
        <section className="panel workflow-card">
          <div className="panel-heading"><h2>Propose a response</h2><Pill tone="human">Evidence required</Pill></div>
          <p>Choose a registered target and matching local alert. Simulation records a decision without contacting an integration.</p>
          <ProposalForm assets={assets} alerts={alerts} policy={policy}
            enabled={can("response:propose") && policyAvailable && policy.mode !== "off" && !policy.emergency_stop}
            onPropose={(proposal) => perform(() => api.proposeResponse(proposal), "Response proposal recorded")} />
        </section>
      </div>
      <section className="panel workflow-card response-section">
        <div className="panel-heading"><h2>Simulate recent detections</h2><Pill tone="local">No enforcement</Pill></div>
        <p>Evaluate up to 20 recent alerts against registered assets and permitted families. Missing identity, stale evidence, and excluded assets are reported without taking action.</p>
        <button className="outline-button" disabled={!can("response:propose") || !policyAvailable || policy.mode !== "simulate" || policy.emergency_stop}
          onClick={async () => {
            if (!batchRequest.current) batchRequest.current = crypto.randomUUID();
            const result = await perform(() => api.simulateResponseAlerts({ request_id: batchRequest.current, limit: 20 }), "Detection simulation completed");
            if (result) { setBatchResult(result); batchRequest.current = null; }
          }}>Simulate recent alerts</button>
        {batchResult ? <div className="response-detail" aria-live="polite"><strong>{batchResult.count} simulations recorded · {batchResult.excluded.length} exclusions · no enforcement</strong>
          {batchResult.excluded.length ? <ul>{batchResult.excluded.map((item, index) => <li key={`${item.alert_id}-${item.family || "identity"}-${index}`}>{item.alert_id}{item.family ? ` / ${FAMILY_NAMES[item.family]}` : ""}: {item.reason}</li>)}</ul> : null}</div> : null}
      </section>
      <section className="panel workflow-card response-section">
        <div className="panel-heading"><div><span className="eyebrow">SCOPED INVENTORY</span><h2>Asset assignments</h2></div><Pill>{assets.length} assets</Pill></div>
        <p>Addresses need a current, administrator-attested mapping to a stable device identity. Registration alone does not install an integration.</p>
        <div className="response-asset-list">{assets.map((asset) => <article key={asset.asset_id}><strong>{asset.asset_id}</strong><span>{asset.group} · {asset.platform}{asset.critical ? " · Critical / excluded" : ""}</span><span>{asset.addresses.join(", ")}</span><small>Valid until {displayTime(asset.valid_until)}</small></article>)}</div>
        {!assets.length ? <p className="table-empty">No asset assignments loaded.</p> : null}
        <details className="response-registration"><summary>Register an asset assignment</summary>
          <AssetForm enabled={can("response:manage")} assets={assets}
            onRegister={(asset) => perform(() => api.registerResponseAsset(asset), "Asset assignment registered")} />
        </details>
      </section>
      <section className="panel workflow-card response-section">
        <div className="panel-heading"><div><span className="eyebrow">SIMULATION AND ENFORCEMENT</span><h2>Response actions</h2></div><Pill>{actions.length} loaded</Pill></div>
        <div className="response-table-wrap"><table className="response-table"><thead><tr><th>Created / action</th><th>Target</th><th>Family</th><th>Outcome</th><th>Details</th></tr></thead><tbody>
          {actions.map((action) => <tr key={action.action_id}><td>{displayTime(action.created_at)}<small>{action.action_id}</small></td><td>{action.proposal.asset_id}<small>{action.proposal.address}</small></td><td>{FAMILY_NAMES[action.proposal.family]}</td><td><ActionState action={action} /></td><td><button className="outline-button" onClick={() => setSelected(action)}>Review</button></td></tr>)}
          {!actions.length ? <tr><td colSpan={5}>No response actions loaded.</td></tr> : null}
        </tbody></table></div>
        <Pagination offset={actionOffset} count={actions.length} disabled={loading || busy || demoMode} onChange={setActionOffset} label="Actions" />
        {currentAction ? <ActionDetails action={currentAction} capabilities={capabilities} can={can} liveReady={liveReady}
          onTransition={(operation) => setConfirmation({ operation, action: currentAction })} /> : null}
      </section>
      <section className="panel workflow-card response-section">
        <div className="panel-heading"><h2>Response journal</h2><Pill>Local records</Pill></div>
        <p>Response decisions and transitions are stored separately from the product audit trail. This view does not independently verify the journal hash chain.</p>
        <div className="response-table-wrap"><table className="response-table"><thead><tr><th>Sequence / time</th><th>Actor</th><th>Event</th><th>Resource</th></tr></thead><tbody>
          {journal.map((record) => <tr key={record.event_id}><td>#{record.sequence}<small>{displayTime(record.created_at)}</small></td><td>{record.actor_id}</td><td>{record.event}</td><td>{record.resource_id}{record.metadata.reason ? <small>{record.metadata.reason}</small> : null}</td></tr>)}
          {!journal.length ? <tr><td colSpan={4}>No response journal records loaded.</td></tr> : null}
        </tbody></table></div>
        <Pagination offset={journalOffset} count={journal.length} disabled={loading || busy || demoMode} onChange={setJournalOffset} label="Journal" />
      </section>
      {confirmation ? <Modal title={confirmation.operation === "stop" ? "Stop new enforcement?" : `${confirmation.operation === "approve" ? "Approve" : confirmation.operation === "release" ? "Request release of" : "Cancel"} this proposal?`}
        eyebrow="EXPLICIT RESPONSE DECISION" onClose={() => { if (!busy) setConfirmation(null); }}>
        {confirmation.action ? <><p>{confirmation.action.proposal.asset_id} · {confirmation.action.proposal.address} · {FAMILY_NAMES[confirmation.action.proposal.family]}</p>
          <p>Integration: {confirmation.action.proposal.binding.integration_id}; device: {confirmation.action.proposal.binding.target_id}.</p>
          <p>Scope: {confirmation.action.proposal.direction}; requested duration: {confirmation.action.proposal.duration_seconds}s.</p>
          <p className="response-hash">Proposal hash: {confirmation.action.proposal_hash}</p>
          <p>{confirmation.operation === "release" ? "This requests recovery. The restriction is only shown as released after verification." : "The server will recheck the proposal and your permission before accepting this request."}</p></>
          : <p>New authorizations will stop. Existing restrictions and operations already submitted to a provider are not automatically reversed.</p>}
        <div className="response-buttons"><button className="outline-button" disabled={busy} onClick={() => setConfirmation(null)}>Go back</button>
          <button className="primary-button" disabled={busy || loading || Boolean(error)} onClick={() => perform(
            () => confirmation.operation === "stop" ? api.stopResponse() : api.transitionResponse(confirmation.action.action_id, confirmation.operation, confirmation.action.proposal_hash),
            confirmation.operation === "stop" ? "Emergency stop activated" : "Response decision recorded")}>{busy ? "Saving…" : "Confirm decision"}</button></div>
      </Modal> : null}
    </div>
  );
}

function Pagination({ offset, count, disabled, onChange, label }) {
  return <nav className="response-pagination" aria-label={`${label} pagination`}><button className="outline-button" disabled={disabled || offset === 0} onClick={() => onChange(Math.max(0, offset - 50))}>Previous</button><span>{count ? `${offset + 1}–${offset + count}` : "No records on this page"}</span><button className="outline-button" disabled={disabled || count < 50} onClick={() => onChange(offset + 50)}>Next</button></nav>;
}

function PolicyForm({ policy, canManage, onSave, busy }) {
  const [mode, setMode] = useState(policy.mode);
  const [groups, setGroups] = useState(policy.allowed_groups.join(", "));
  const [families, setFamilies] = useState(policy.allowed_families);
  const [duration, setDuration] = useState(policy.max_duration_seconds);
  const [rules, setRules] = useState(policy.autonomous_rules);
  const [resume, setResume] = useState(false);
  return <form onSubmit={(event) => { event.preventDefault(); onSave({ version: policy.version, mode,
    allowed_groups: groups.split(",").map((value) => value.trim()).filter(Boolean), allowed_families: families,
    max_duration_seconds: Number(duration), autonomous_rules: rules, emergency_stop: policy.emergency_stop && !resume }); }}>
    <fieldset disabled={!canManage || busy}><legend className="response-sr-only">Response policy settings</legend>
      <label className="field-label">Mode<select value={mode} onChange={(event) => setMode(event.target.value)}><option value="off">Off</option><option value="simulate">Simulate only</option>{!["off", "simulate"].includes(policy.mode) ? <option value={policy.mode} disabled>{policy.mode} · configured externally</option> : null}</select></label>
      <label className="field-label">Allowed device groups<input value={groups} onChange={(event) => setGroups(event.target.value)} placeholder="Comma-separated group IDs" /></label>
      <div className="response-checkboxes">{Object.entries(FAMILY_NAMES).map(([family, name]) => <label key={family}><input type="checkbox" checked={families.includes(family)} onChange={(event) => setFamilies((current) => event.target.checked ? [...current, family] : current.filter((item) => item !== family))} />{name}</label>)}</div>
      <label className="field-label">Maximum requested duration (seconds)<input type="number" min={1} max={3600} required value={duration} onChange={(event) => setDuration(event.target.value)} /></label>
      <details className="response-registration"><summary>Automatic policy rules to evaluate in simulation</summary>
        <p>Match a specific detector, high/critical severity, allowed group, and allowed family. These rules do not enable live execution.</p>
        {rules.map((rule, index) => <div className="response-rule" key={index}>
          {[["detector_id", "Detector ID"], ["group", "Allowed device group"]].map(([key, label]) => <label className="field-label" key={key}>{label}<input required maxLength={128} value={rule[key]} onChange={(event) => setRules((current) => current.map((item, position) => position === index ? { ...item, [key]: event.target.value } : item))} /></label>)}
          <label className="field-label">Severity<select value={rule.severity} onChange={(event) => setRules((current) => current.map((item, position) => position === index ? { ...item, severity: event.target.value } : item))}><option value="high">High</option><option value="critical">Critical</option></select></label>
          <label className="field-label">Response family<select value={rule.family} onChange={(event) => setRules((current) => current.map((item, position) => position === index ? { ...item, family: event.target.value } : item))}>{Object.entries(FAMILY_NAMES).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select></label>
          <button className="outline-button" type="button" onClick={() => setRules((current) => current.filter((_, position) => position !== index))}>Remove rule {index + 1}</button>
        </div>)}
        <button className="outline-button" type="button" disabled={rules.length >= 50} onClick={() => setRules((current) => [...current, { detector_id: "", severity: "high", group: "", family: "firewall" }])}>Add simulation rule</button>
      </details>
      {policy.emergency_stop ? <label className="response-check"><input type="checkbox" checked={resume} onChange={(event) => setResume(event.target.checked)} />Clear emergency stop when saving this policy</label> : null}
      <p>Live modes require a separately configured and validated integration. This editor supports Off and Simulate.</p>
      <button className="primary-button" type="submit">Save response policy</button>
    </fieldset>
  </form>;
}

function ProposalForm({ assets, alerts, enabled, policy, onPropose }) {
  const [assetId, setAssetId] = useState("");
  const [alertId, setAlertId] = useState("");
  const [family, setFamily] = useState("firewall");
  const [address, setAddress] = useState("");
  const [duration, setDuration] = useState(300);
  const attempt = useRef(null);
  const asset = assets.find((item) => item.asset_id === assetId);
  return <form onSubmit={async (event) => {
    event.preventDefault();
    const body = { asset_id: assetId, alert_id: alertId, family, address, duration_seconds: Number(duration) };
    const hash = JSON.stringify(body);
    if (attempt.current?.hash !== hash) attempt.current = { hash, requestId: crypto.randomUUID() };
    const result = await onPropose({ ...body, request_id: attempt.current.requestId });
    if (result) attempt.current = null;
  }}><fieldset disabled={!enabled}><legend className="response-sr-only">Response proposal</legend>
    <label className="field-label">Registered asset<select required value={assetId} onChange={(event) => { setAssetId(event.target.value); setAddress(""); }}><option value="">Choose an asset</option>{assets.map((item) => <option key={item.asset_id} value={item.asset_id} disabled={item.critical}>{item.asset_id}{item.critical ? " · Critical / excluded" : ""}</option>)}</select></label>
    <label className="field-label">Local alert<select required value={alertId} onChange={(event) => setAlertId(event.target.value)}><option value="">Choose an alert</option>{alerts.map((item) => <option key={item.id} value={item.id}>{item.title} · {item.entityId || item.sourceIp}</option>)}</select></label>
    <label className="field-label">Response family<select value={family} onChange={(event) => setFamily(event.target.value)}>{Object.entries(FAMILY_NAMES).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select></label>
    <label className="field-label">Assigned address<select required value={address} onChange={(event) => setAddress(event.target.value)}><option value="">Choose an address</option>{asset?.addresses.map((item) => <option key={item} value={item}>{item}</option>)}</select></label>
    <label className="field-label">Requested duration (seconds)<input type="number" required min={1} max={policy?.max_duration_seconds || 3600} value={duration} onChange={(event) => setDuration(event.target.value)} /></label>
    <p>{family === "firewall" ? "A live firewall adapter must enforce expiration at the gateway." : "Endpoint isolation requires explicit, verified release; this duration does not schedule automatic recovery."}</p>
    <button className="primary-button" type="submit">{policy?.mode === "simulate" ? "Record simulation" : "Create response proposal"}</button>
  </fieldset></form>;
}

function AssetForm({ enabled, assets, onRegister }) {
  const [family, setFamily] = useState("firewall");
  const [localError, setLocalError] = useState("");
  return <form onSubmit={async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = Object.fromEntries(new FormData(form));
    if (assets.some((asset) => asset.asset_id === data.asset_id)) {
      setLocalError("This asset already exists. Use the scoped API to review and update its complete assignment.");
      return;
    }
    setLocalError("");
    const result = await onRegister({ asset_id: data.asset_id, group: data.group, platform: data.platform,
      critical: data.critical === "on", source: data.source,
      addresses: data.addresses.split(",").map((value) => value.trim()).filter(Boolean),
      observed_at: new Date(data.observed_at).toISOString(), valid_until: new Date(data.valid_until).toISOString(),
      bindings: { [family]: { integration_id: data.integration_id, target_id: data.target_id } } });
    if (result) form.reset();
  }}><fieldset disabled={!enabled}><legend className="response-sr-only">Authoritative asset assignment</legend>
    <div className="response-form-grid">{[["asset_id", "Stable asset ID"], ["group", "Device group"], ["platform", "Operating system / platform"], ["source", "Mapping source"], ["addresses", "Assigned addresses (comma-separated)"], ["integration_id", "Integration ID"], ["target_id", "Provider device ID"]].map(([name, label]) => <label className="field-label" key={name}>{label}<input name={name} required maxLength={name === "addresses" ? 800 : 128} /></label>)}
      <label className="field-label">Response family<select value={family} onChange={(event) => setFamily(event.target.value)}>{Object.entries(FAMILY_NAMES).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select></label>
      <label className="field-label">Assignment observed at (local time)<input type="datetime-local" name="observed_at" required step={1} /></label>
      <label className="field-label">Assignment valid until (local time)<input type="datetime-local" name="valid_until" required step={1} /></label>
    </div>
    <label className="response-check"><input type="checkbox" name="critical" defaultChecked />Critical asset · excluded from response</label>
    <label className="response-check"><input type="checkbox" required />I have verified this device identity and address assignment from the stated source.</label>
    {localError ? <p role="alert">{localError}</p> : null}
    <p>Use the actual observation time. Assignments must cover evidence time and expire within 24 hours.</p>
    <button className="primary-button" type="submit">Register assignment</button>
  </fieldset></form>;
}

function ActionDetails({ action, capabilities, can, liveReady, onTransition }) {
  const proposal = action.proposal;
  const sameActor = capabilities.actor_id === action.proposed_by;
  const canApprove = liveReady && !sameActor && can("response:approve") && action.status === "awaiting_approval" &&
    Date.now() < new Date(proposal.authorization_expires_at).getTime();
  const canCancel = can("response:propose") && (sameActor || can("response:approve")) && ["awaiting_approval", "queued"].includes(action.status);
  const canRelease = can("response:release") && ["succeeded", "unknown", "verifying", "release_unknown"].includes(action.status);
  return <article className="response-detail"><div className="panel-heading"><h3>Proposal review</h3><ActionState action={action} /></div>
    <dl className="detail-list"><div><dt>Asset / address</dt><dd>{proposal.asset_id} / {proposal.address}</dd></div><div><dt>Action / direction</dt><dd>{FAMILY_NAMES[proposal.family]} / {proposal.direction}</dd></div><div><dt>Policy / duration</dt><dd>Version {proposal.policy_version} / {proposal.duration_seconds}s</dd></div><div><dt>Proposed by</dt><dd>{action.proposed_by}</dd></div><div><dt>Authorization expires</dt><dd>{displayTime(proposal.authorization_expires_at)}</dd></div><div><dt>Observed state</dt><dd>{action.effective_state.replaceAll("_", " ")}</dd></div><div><dt>Provider operation</dt><dd>{action.provider_action_id || "Not recorded"}</dd></div><div><dt>Evidence</dt><dd>{proposal.evidence_ids.join(", ")}</dd></div></dl>
    <dl className="detail-list"><div><dt>Integration / device</dt><dd>{proposal.binding.integration_id} / {proposal.binding.target_id}</dd></div><div><dt>Platform / recovery</dt><dd>{proposal.platform} / {proposal.recovery.replaceAll("_", " ")}</dd></div><div><dt>Alert</dt><dd>{proposal.alert_id}</dd></div><div><dt>Authorization</dt><dd>{action.authorization ? `${action.authorization.type} / ${action.authorization.actor_id}` : "Not authorized"}</dd></div><div><dt>Release operation</dt><dd>{action.release_provider_action_id || "Not recorded"}</dd></div></dl>
    <p className="response-hash">Proposal hash: {action.proposal_hash}</p>
    <details><summary>Inspect complete proposal</summary><pre className="response-proposal-json">{JSON.stringify(proposal, null, 2)}</pre></details>
    {action.status === "simulated" ? <p>No enforcement performed. Automatic policy match: {action.simulation.would_authorize_automatically ? "yes" : "no"}; human approval would otherwise be required.</p> : null}
    {sameActor && action.status === "awaiting_approval" ? <p>A different authorized person must approve this proposal.</p> : null}
    <div className="response-buttons"><button className="primary-button" disabled={!canApprove} onClick={() => onTransition("approve")}>Approve exact proposal</button><button className="outline-button" disabled={!canCancel} onClick={() => onTransition("cancel")}>Cancel unstarted action</button><button className="outline-button" disabled={!canRelease} onClick={() => onTransition("release")}>Request verified release</button></div>
  </article>;
}
