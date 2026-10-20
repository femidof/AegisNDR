import { useEffect, useMemo, useState } from "react";
import { Sidebar, TrustStrip } from "./components/Chrome.jsx";
import { AiResponseModal, EvidenceModal, LedgerModal } from "./components/modals.jsx";
import { Toast } from "./components/ui.jsx";
import {
  DEMO_AUDIT_ALERT_STATUS,
  DEMO_AUDIT_CASE_CREATED,
  DEMO_AUDIT_INVESTIGATION_COMPLETED,
  DEMO_CASE_PREFIX,
  DEMO_CASE_UPDATED_TIME,
  DEMO_EXPORT_ASSESSMENT,
} from "./demo/demoState.js";
import {
  alerts as demoAlerts,
  auditEvents,
  evidence,
  initialCases,
  ledgerEntries,
  PRIMARY_ALERT_ID,
  sensors,
  trafficRows,
} from "./mockData.js";
import { AlertsPage } from "./pages/AlertsPage.jsx";
import { AuditPage } from "./pages/AuditPage.jsx";
import { CasesPage } from "./pages/CasesPage.jsx";
import { InvestigationPage, progressLabels } from "./pages/InvestigationPage.jsx";
import { OverviewPage } from "./pages/OverviewPage.jsx";
import { SensorsPage } from "./pages/SensorsPage.jsx";
import { SettingsPage } from "./pages/SettingsPage.jsx";
import { TrafficPage } from "./pages/TrafficPage.jsx";
import { TransmissionsPage } from "./pages/TransmissionsPage.jsx";
import { ResponsePage } from "./pages/ResponsePage.jsx";
import { DetectionRulesPage } from "./pages/DetectionRulesPage.jsx";
import { IntegrationsPage } from "./pages/IntegrationsPage.jsx";
import { LogSearchPage } from "./pages/LogSearchPage.jsx";
import { loadDashboard } from "./dashboardState.js";

function App({ mode = "demo", api = null, user = null, onSignOut = null }) {
  const demoMode = mode === "demo";
  const [activePage, setActivePage] = useState("Investigation");
  const [alerts, setAlerts] = useState(demoMode ? demoAlerts : []);
  const [selectedAlertId, setSelectedAlertId] = useState(demoMode ? PRIMARY_ALERT_ID : null);
  const [cases, setCases] = useState(demoMode ? initialCases : []);
  const [overview, setOverview] = useState(null);
  const [sensorItems, setSensorItems] = useState(demoMode ? sensors : []);
  const [traffic, setTraffic] = useState(demoMode ? trafficRows : []);
  const [transmissions, setTransmissions] = useState(demoMode ? ledgerEntries : []);
  const [audit, setAudit] = useState({ events: demoMode ? auditEvents : [], chainValid: undefined });
  const [policy, setPolicy] = useState(null);
  const [investigations, setInvestigations] = useState([]);
  const [investigation, setInvestigation] = useState(null);
  const [transmission, setTransmission] = useState(null);
  const [evidenceItems, setEvidenceItems] = useState([]);
  const [runState, setRunState] = useState("idle");
  const [runStep, setRunStep] = useState(0);
  const [selectedEvidence, setSelectedEvidence] = useState(null);
  const [ledgerOpen, setLedgerOpen] = useState(false);
  const [aiResponseOpen, setAiResponseOpen] = useState(false);
  const [actionMenuOpen, setActionMenuOpen] = useState(false);
  const [toast, setToast] = useState(null);
  const [dynamicAudit, setDynamicAudit] = useState([]);
  const [dataSource, setDataSource] = useState(demoMode ? "demo" : "loading");
  const [access, setAccess] = useState(null);
  const [readErrors, setReadErrors] = useState({});
  const [rules, setRules] = useState(null);
  const [suppressions, setSuppressions] = useState([]);
  const [integrations, setIntegrations] = useState(null);
  const [systemSettings, setSystemSettings] = useState(null);
  const [exports, setExports] = useState([]);
  const [supportBundles, setSupportBundles] = useState(null);
  const [searchResults, setSearchResults] = useState([]);
  const [health, setHealth] = useState(null);
  const [healthObservedAt, setHealthObservedAt] = useState(0);
  const can = (permission) => !demoMode && (Array.isArray(access?.permissions) && access.permissions.includes(permission));
  const selectedAlert = useMemo(() => alerts.find((item) => item.id === selectedAlertId) || alerts[0], [alerts, selectedAlertId]);

  useEffect(() => {
    if (demoMode || !api) return undefined;
    let cancelled = false;
    let pending = false;
    async function refresh() {
      if (pending) return;
      pending = true;
      try {
        const next = await loadDashboard(api);
        if (cancelled) return;
        setOverview(next.overview);
        setAlerts(next.alerts);
        setSelectedAlertId((current) => next.alerts.some((item) => item.id === current) ? current : next.alerts[0]?.id ?? null);
        setCases(next.cases);
        setSensorItems(next.sensors);
        setTraffic(next.traffic);
        setTransmissions(next.transmissions);
        setAudit(next.audit);
        setPolicy(next.policy);
        setInvestigations(next.investigations);
        setAccess(next.session);
        setReadErrors(next.errors);
        setRules(next.rules);
        setSuppressions(next.suppressions);
        setIntegrations(next.integrations);
        setSystemSettings(next.systemSettings);
        setExports(next.exports);
        setSupportBundles(next.supportBundles);
        setDataSource(next.dataSource);
      } catch (error) {
        if (cancelled) return;
        setDataSource("error");
        setToast({ title: "Local API unavailable", message: error.message, tone: "warning" });
      } finally {
        pending = false;
      }
    }
    refresh();
    const timer = window.setInterval(refresh, 60_000);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [api, demoMode]);

  useEffect(() => {
    if (demoMode || !api) return undefined;
    let cancelled = false;
    let pending = false;
    async function checkHealth() {
      if (pending) return;
      pending = true;
      try {
        const next = await api.getSystemHealth();
        if (!cancelled) { setHealth(next); setHealthObservedAt(Date.now()); }
      } catch {
        if (!cancelled) { setHealth(null); setHealthObservedAt(0); }
      } finally { pending = false; }
    }
    checkHealth();
    const timer = window.setInterval(checkHealth, 15_000);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [api, demoMode]);

  useEffect(() => {
    if (demoMode || !api || !selectedAlert) return undefined;
    let cancelled = false;
    api.searchEvents({ entity_id: selectedAlert.entityId }).then((items) => {
      if (!cancelled) setEvidenceItems(items);
    }).catch((error) => {
      if (!cancelled) notify("Evidence could not be loaded", error.message, "warning");
    });
    return () => { cancelled = true; };
  }, [api, demoMode, selectedAlert?.id]);

  useEffect(() => {
    if (!demoMode) {
      setInvestigation(investigations.find((item) => item.alertId === selectedAlert?.id) || null);
      setTransmission(transmissions.find((item) => item.alertId === selectedAlert?.id) || null);
    }
  }, [demoMode, investigations, selectedAlert?.id, transmissions]);

  useEffect(() => {
    if (!demoMode || runState !== "running") return undefined;
    const timer = window.setInterval(() => {
      setRunStep((current) => {
        if (current >= progressLabels.length - 1) {
          window.clearInterval(timer);
          setRunState("complete");
          setDynamicAudit((events) => [{ ...DEMO_AUDIT_INVESTIGATION_COMPLETED, object: selectedAlertId }, ...events]);
          setToast({ title: "Investigation complete", message: "10 evidence items validated and stored locally." });
          return current;
        }
        return current + 1;
      });
    }, 600);
    return () => window.clearInterval(timer);
  }, [runState, selectedAlertId]);

  useEffect(() => {
    if (!toast) return undefined;
    const timer = window.setTimeout(() => setToast(null), 4200);
    return () => window.clearTimeout(timer);
  }, [toast]);

  function notify(title, message, tone = "success") {
    setToast({ title, message, tone });
  }

  function openAlert(id) {
    setSelectedAlertId(id);
    setActivePage("Investigation");
  }

  async function updateAlertStatus(id, status) {
    try {
      const updated = demoMode ? { ...alerts.find((item) => item.id === id), status } : await api.updateAlert(id, { status });
      setAlerts((records) => records.map((item) => item.id === id ? updated : item));
    } catch (error) {
      notify("Alert was not updated", error.message, "warning");
      return;
    }
    setDynamicAudit((events) => [{ ...DEMO_AUDIT_ALERT_STATUS, action: `${DEMO_AUDIT_ALERT_STATUS.action}${status}`, object: id }, ...events]);
    setActionMenuOpen(false);
    notify("Alert status updated", `${id} is now ${status}.`);
  }

  async function startInvestigation() {
    if (!selectedAlert) return;
    setRunStep(0);
    setRunState("running");
    if (demoMode) {
      await updateAlertStatus(selectedAlert.id, "Under Investigation");
      return;
    }
    try {
      const result = await api.startInvestigation(selectedAlert.id);
      setInvestigations((items) => [result, ...items.filter((item) => item.id !== result.id)]);
      setInvestigation(result);
      setRunState(result.status === "completed" ? "complete" : "failed");
      const updated = await api.updateAlert(selectedAlert.id, { status: "Under Investigation" });
      setAlerts((records) => records.map((item) => item.id === updated.id ? updated : item));
      const [nextTransmissions, nextAudit] = await Promise.all([api.listTransmissions(), api.listAudit()]);
      setTransmissions(nextTransmissions);
      setAudit(nextAudit);
      try {
        const nextTransmission = await api.getInvestigationTransmission(result.id);
        setTransmission(nextTransmission);
      } catch {
        setTransmission(null);
      }
      notify(result.status === "completed" ? "Investigation complete" : "Investigation requires review", result.status === "completed" ? "The validated assessment was persisted locally." : `The local runtime returned ${result.status}.`, result.status === "completed" ? "success" : "warning");
    } catch (error) {
      setRunState("failed");
      notify("Investigation failed closed", error.message, "warning");
    }
  }

  async function createCase() {
    if (!selectedAlert) return;
    if (cases.some((item) => item.alertId === selectedAlert.id)) {
      setActionMenuOpen(false);
      setActivePage("Cases");
      notify("Case already linked", "Opening the existing incident case.", "warning");
      return;
    }
    let created;
    try {
      created = demoMode
        ? { id: `${DEMO_CASE_PREFIX}${String(83 + cases.length).padStart(4, "0")}`, alertId: selectedAlert.id, title: selectedAlert.title, priority: "P1", owner: "Maya Chen", status: "Open", updated: DEMO_CASE_UPDATED_TIME }
        : await api.createCase({ title: selectedAlert.title, priority: "critical", assignee: user?.name || user?.email || "", alert_ids: [selectedAlert.id] });
    } catch (error) {
      notify("Case was not created", error.message, "warning");
      return;
    }
    setCases((records) => [created, ...records]);
    setDynamicAudit((events) => [{ ...DEMO_AUDIT_CASE_CREATED, object: created.id }, ...events]);
    setActionMenuOpen(false);
    setActivePage("Cases");
    notify("Incident case created", `${created.id} is assigned to ${created.owner}.`);
  }

  async function updateCaseStatus(id, status) {
    try {
      const updated = demoMode ? { ...cases.find((item) => item.id === id), status } : await api.updateCase(id, { status });
      setCases((records) => records.map((item) => item.id === id ? updated : item));
      notify("Case updated", `${id} is now ${status}.`);
    } catch (error) {
      notify("Case was not updated", error.message, "warning");
    }
  }

  async function savePolicy(changes) {
    return changeResource(() => api.updateModelPolicy(changes), setPolicy, "Model policy saved");
  }

  async function changeResource(operation, update, title) {
    if (demoMode || !api) return false;
    try {
      const item = await operation();
      update(item);
      notify(title, "The local API confirmed the change.");
      return true;
    } catch (error) {
      notify("Change could not be confirmed", error.message, "warning");
      return false;
    }
  }

  function downloadDocument(file) {
    if (!file?.filename || !file.document || typeof file.document !== "object") throw new Error("The API returned an invalid download.");
    const url = URL.createObjectURL(new Blob([JSON.stringify(file.document, null, 2)], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = file.filename;
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  async function downloadArtifact(operation) {
    try { downloadDocument(await operation()); }
    catch (error) { notify("Download unavailable", error.message, "warning"); }
  }

  async function requestExport(body) {
    return changeResource(() => api.requestEvidenceExport(body), (item) => setExports((items) => [item, ...items]), "Export requested; approval required");
  }

  async function exportInvestigation() {
    if (!selectedAlert) return;
    if (!demoMode) {
      const requested = await requestExport({ alert_id: selectedAlert.id, evidence_ids: selectedAlert.evidenceIds,
        reason: "Investigation evidence requested for incident response review", format: "json" });
      if (requested) setActivePage("System Settings");
      return;
    }
    const report = { exported_at: new Date().toISOString(), alert: selectedAlert, evidence: demoMode ? evidence : evidenceItems, assessment: demoMode ? DEMO_EXPORT_ASSESSMENT : investigation?.assessment, transmission: demoMode ? ledgerEntries[0] : transmission };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${selectedAlert.id}-investigation.json`;
    link.click();
    URL.revokeObjectURL(url);
    notify("Demo investigation exported", "A JSON report containing demo data was generated.");
  }

  const investigationProps = {
    alert: selectedAlert,
    runState,
    runStep,
    onStart: startInvestigation,
    onLedger: () => setLedgerOpen(true),
    onEvidence: setSelectedEvidence,
    onAiResponse: () => setAiResponseOpen(true),
    onBack: () => setActivePage("Alerts"),
    onExport: exportInvestigation,
    actionMenuOpen,
    setActionMenuOpen,
    onStatus: (status) => updateAlertStatus(selectedAlert.id, status),
    onCreateCase: createCase,
    demoMode,
    investigation,
    transmission,
    evidenceItems,
    policy,
  };

  let page;
  if (activePage === "Overview") page = <OverviewPage alerts={alerts} cases={cases} overview={overview} sensors={sensorItems} onNavigate={setActivePage} onOpenAlert={openAlert} dataSource={dataSource} demoMode={demoMode} />;
  else if (activePage === "Alerts") page = <AlertsPage alerts={alerts} selectedAlertId={selectedAlertId} onSelect={setSelectedAlertId} onInvestigate={openAlert} onStatusChange={updateAlertStatus} />;
  else if (activePage === "Investigation") page = <InvestigationPage {...investigationProps} />;
  else if (activePage === "Cases") page = <CasesPage cases={cases} onCreateCase={createCase} onStatusChange={updateCaseStatus} canCreate={Boolean(selectedAlert)} />;
  else if (activePage === "Response") page = <ResponsePage api={api} alerts={alerts} demoMode={demoMode} notify={notify} />;
  else if (activePage === "Traffic") page = <TrafficPage rows={traffic} />;
  else if (activePage === "Sensors") page = <SensorsPage items={sensorItems} />;
  else if (activePage === "Log Search") page = <LogSearchPage results={searchResults} onSearch={async (criteria) => { setSearchResults(demoMode ? traffic : await api.searchEvents(criteria)); }} />;
  else if (activePage === "Detection Rules") page = <DetectionRulesPage rules={rules} suppressions={suppressions} canManage={can("rules:manage")}
    onCreateRule={(body) => changeResource(() => api.createDetectionRule(body), (item) => setRules((items) => [...(items || []), item]), "Rule created")}
    onUpdateRule={(id, body) => changeResource(() => api.updateDetectionRule(id, body), (item) => setRules((items) => (items || []).map((value) => value.rule_id === id ? item : value)), "Rule updated")}
    onDeleteRule={(id) => changeResource(() => api.deleteDetectionRule(id), () => setRules((items) => (items || []).filter((value) => value.rule_id !== id)), "Rule deleted")}
    onCreateSuppression={(body) => changeResource(() => api.createSuppression(body), (item) => setSuppressions((items) => [...items, item]), "Suppression created")}
    onUpdateSuppression={(id, body) => changeResource(() => api.updateSuppression(id, body), (item) => setSuppressions((items) => items.map((value) => value.suppression_id === id ? item : value)), "Suppression updated")}
    onDeleteSuppression={(id) => changeResource(() => api.deleteSuppression(id), () => setSuppressions((items) => items.filter((value) => value.suppression_id !== id)), "Suppression deleted")} />;
  else if (activePage === "Integrations") page = <IntegrationsPage integrations={integrations} canManage={can("integrations:manage")}
    onCreate={(body) => changeResource(() => api.createIntegration(body), (item) => setIntegrations((items) => [...(items || []), item]), "Integration created")}
    onUpdate={(id, body) => changeResource(() => api.updateIntegration(id, body), (item) => setIntegrations((items) => (items || []).map((value) => value.integration_id === id ? item : value)), "Integration updated")}
    onDelete={(id) => changeResource(() => api.deleteIntegration(id), () => setIntegrations((items) => (items || []).filter((value) => value.integration_id !== id)), "Integration deleted")} />;
  else if (activePage === "AI Transmissions") page = <TransmissionsPage entries={transmissions} onLedger={(entry) => { setTransmission(entry || transmission); setLedgerOpen(true); }} />;
  else if (activePage === "Audit") page = <AuditPage dynamicEvents={demoMode ? dynamicAudit : []} events={audit.events} chainValid={audit.chainValid} />;
  else page = <SettingsPage notify={notify} policy={policy} onSave={savePolicy} demoMode={demoMode} systemSettings={systemSettings}
    canManagePolicy={can("model-policy:manage")} canManageSystem={can("deployments:manage")} canReadEvidence={can("evidence:read")} canExport={can("evidence:export")}
    onSaveSystemSettings={(body) => changeResource(() => api.updateSystemSettings(body), setSystemSettings, "Retention settings saved")}
    exports={exports} selectedAlert={selectedAlert} onRequestExport={requestExport}
    onApproveExport={(id, reason) => changeResource(() => api.approveEvidenceExport(id, reason), (item) => setExports((items) => items.map((value) => value.export_id === id ? item : value)), "Export approved")}
    onDownloadExport={(id) => downloadArtifact(() => api.downloadEvidenceExport(id))}
    supportBundles={supportBundles} onCreateSupportBundle={(body) => changeResource(() => api.createSupportBundle(body), (item) => setSupportBundles((items) => [item, ...(items || [])]), "Support bundle created")}
    onDownloadSupportBundle={(id) => downloadArtifact(() => api.downloadSupportBundle(id))} />;

  const viewResource = { Overview: "overview", Alerts: "alerts", Investigation: "investigations", Cases: "cases", Sensors: "sensors", Traffic: "traffic", "Log Search": "traffic", "Detection Rules": "rules", Integrations: "integrations", Audit: "audit", "AI Transmissions": "transmissions", "System Settings": "systemSettings" }[activePage];
  if (!demoMode && readErrors[viewResource]) page = <div className="standard-page"><section className="panel workflow-card" role="alert"><h1>{activePage} unavailable</h1><p>{readErrors[viewResource].status === 403 ? "Your current role does not have permission to read this view." : "The local API could not load this view. Retry after checking the service connection."}</p></section></div>;

  return (
    <div className="app-shell">
      <TrustStrip dataSource={dataSource} demoMode={demoMode} health={health} observedAt={healthObservedAt} policy={policy} user={user} onSignOut={onSignOut} />
      <div className="app-body">
        <Sidebar activePage={activePage} onNavigate={setActivePage} alertCount={!readErrors.alerts ? alerts.filter((item) => item.status !== "Closed").length : null} />
        <div className="page-surface">{page}</div>
      </div>
      {selectedEvidence ? <EvidenceModal selectedEvidence={selectedEvidence} evidenceItems={evidenceItems} demoMode={demoMode} onClose={() => setSelectedEvidence(null)} /> : null}
      {ledgerOpen ? <LedgerModal transmission={transmission} demoMode={demoMode} onClose={() => setLedgerOpen(false)} /> : null}
      {aiResponseOpen ? <AiResponseModal assessment={investigation?.assessment} demoMode={demoMode} onClose={() => setAiResponseOpen(false)} /> : null}
      <Toast toast={toast} onDismiss={() => setToast(null)} />
    </div>
  );
}

export { App };
