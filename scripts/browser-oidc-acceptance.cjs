const { chromium } = require("playwright");

const DASHBOARD = process.env.DASHBOARD_ORIGIN || "http://localhost:4173";
const PORTAL = process.env.PORTAL_ORIGIN || "http://localhost:4180";
const USERNAME = process.env.OIDC_TEST_USERNAME || "analyst_demo";
const PASSWORD = process.env.OIDC_TEST_PASSWORD || "ChangeMe-2026!";
const EXPECTED_ALERT = "HYBRID NDR deterministic HTTP sensor acceptance";

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail ? " :: " + detail : ""}`);
}

async function logtoSignIn(page) {
  // The user may already hold a Logto session, in which case the sign-in page
  // is skipped and the authorization response redirects straight back.
  try {
    await page.waitForURL(/localhost:3011/, { timeout: 8000 });
  } catch {
    return;
  }
  await page.waitForLoadState("networkidle");
  await page.locator('input[name="identifier"], input[type="text"], input[name="username"]').first().fill(USERNAME);
  await page.locator('input[type="password"]').first().fill(PASSWORD);
  await page.locator('button[type="submit"], button:has-text("Sign in")').first().click();
}

(async () => {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const consoleErrors = [];
  const apiCalls = [];
  const page = await context.newPage();
  page.on("console", (m) => m.type() === "error" && consoleErrors.push(m.text()));
  page.on("pageerror", (e) => consoleErrors.push(String(e)));
  page.on("request", (req) => {
    if (req.url().includes("/api/v1/")) apiCalls.push(req.method() + " " + req.url());
  });

  // ---- Customer dashboard journey ----
  await page.goto(DASHBOARD, { waitUntil: "networkidle" });
  check("dashboard loads", (await page.title()).includes("AegisNDR"));
  await page.locator("button:has-text('Sign in')").first().click();
  await logtoSignIn(page);
  await page.waitForURL(/localhost:4173/, { timeout: 30000 });
  await page.waitForLoadState("networkidle");
  await page.waitForFunction(() => document.querySelector(".trust-strip") != null, { timeout: 15000 });
  // Wait for the alert queue to render from the API before reading the body.
  await page.locator(".nav-item", { hasText: "Alerts" }).first().click();
  await page.waitForSelector(".table-row", { timeout: 15000 });
  await page.waitForTimeout(800);
  const body = await page.locator("body").innerText();
  check("dashboard signed-in user", /Demo Analyst/.test(body), "Demo Analyst visible");
  check("dashboard shows real persisted alert", body.includes(EXPECTED_ALERT), EXPECTED_ALERT);
  const realApiCalls = apiCalls.filter((call) => call.startsWith("GET ") || call.startsWith("POST "));
  check("dashboard uses real /api/v1 endpoints", realApiCalls.length >= 3, JSON.stringify(realApiCalls.slice(0, 3)));

  // Authenticated mutation: toggle the real alert's status via the UI.
  const select = page.locator(".alert-preview select").first();
  if (await select.count() > 0) {
    const options = await select.locator("option").allTextContents();
    const current = await select.inputValue();
    const target = options.find((o) => o !== current) || options[0];
    await select.selectOption(target);
    await page.waitForTimeout(1500);
  }
  const patched = apiCalls.some((call) => call.startsWith("PATCH ") && call.includes("/api/v1/alerts/"));
  check("authenticated alert update reaches local API", patched, "PATCH /api/v1/alerts/<id> observed");
  await page.screenshot({ path: "/tmp/screens/dashboard-signed-in.png", fullPage: true });

  // ---- Cloud portal journey ----
  await page.goto(PORTAL, { waitUntil: "networkidle" });
  await page.locator("button:has-text('Continue with Logto')").first().click();
  await logtoSignIn(page);
  await page.waitForURL(/localhost:4180/, { timeout: 30000 });
  await page.waitForLoadState("networkidle");
  await page.waitForSelector("text=Metadata-only boundary", { timeout: 15000 });
  await page.waitForTimeout(800);
  const portalBody = await page.locator("body").innerText();
  check("portal signed-in user + org", /Demo Analyst/.test(portalBody) && /Organization Owner/.test(portalBody));
  check("portal shows metadata-only boundary", /Metadata-only boundary/.test(portalBody));
  const noCustomerContent =
    !/demo-scan-|EV-\d{4}|10\.0\.4\.|203\.0\.113\.|network\.connection|network\.dns/.test(portalBody);
  check("portal contains no customer event content", noCustomerContent);
  await page.screenshot({ path: "/tmp/screens/portal-signed-in.png", fullPage: true });

  check("no browser console errors", consoleErrors.length === 0, JSON.stringify(consoleErrors));

  const failed = results.filter((r) => !r.ok);
  console.log(`\nRESULT: ${results.length - failed.length}/${results.length} checks passed`);
  await browser.close();
  process.exit(failed.length ? 1 : 0);
})().catch((e) => { console.error("FATAL", e); process.exit(1); });
