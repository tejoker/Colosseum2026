// WCAG 2.1 A/AA audit of the dashboard using axe-core in headless Chrome.
//
//   node scripts/a11y-audit.mjs
//
// Env:
//   BASE            dashboard URL (default http://localhost:3000)
//   SESSION_COOKIE  value of the sauron_session cookie for authed pages
//   CHROME          path to a Chrome/Chromium binary (default /usr/bin/google-chrome)
//   THEME           "dark" (default) or "light"
//
// Exits non-zero if any page has WCAG 2.1 A/AA violations. axe-core is a
// dashboard dependency; puppeteer-core is a devDependency. A running dashboard
// (and a core for authed pages) must be reachable first.
import puppeteer from "puppeteer-core";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const AXE = readFileSync(require.resolve("axe-core/axe.min.js"), "utf8");
const BASE = process.env.BASE || "http://localhost:3000";
const COOKIE = process.env.SESSION_COOKIE || "";
const CHROME = process.env.CHROME || "/usr/bin/google-chrome";
const THEME = process.env.THEME === "light" ? "light" : "dark";

const PAGES = [
  ["/login", false],
  ["/welcome", true],
  ["/explorer", true],
  ["/", true],
  ["/policies", true],
  ["/onboard", true],
];

const browser = await puppeteer.launch({
  executablePath: CHROME,
  headless: "shell",
  args: ["--no-sandbox", "--disable-gpu"],
});

let total = 0;
for (const [path, needsAuth] of PAGES) {
  const page = await browser.newPage();
  await page.emulateMediaFeatures([{ name: "prefers-color-scheme", value: THEME }]);
  if (needsAuth && COOKIE) {
    await page.setCookie({ name: "sauron_session", value: COOKIE, domain: "localhost", path: "/" });
  }
  try {
    const resp = await page.goto(BASE + path, { waitUntil: "networkidle2", timeout: 20000 });
    await page.evaluate(AXE);
    const r = await page.evaluate(async () =>
      window.axe.run(document, {
        runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"] },
      })
    );
    const nodes = r.violations.reduce((a, v) => a + v.nodes.length, 0);
    total += nodes;
    console.log(`[${path}] status=${resp?.status()} violations=${r.violations.length} (${nodes} nodes)`);
    for (const v of r.violations) {
      console.log(`  ${v.impact} ${v.id} x${v.nodes.length}  ${v.help}`);
    }
  } catch (e) {
    console.log(`[${path}] ERROR ${String(e).slice(0, 120)}`);
    total += 1;
  }
  await page.close();
}
await browser.close();
console.log(`\nTHEME=${THEME} total violation-nodes: ${total}`);
process.exit(total === 0 ? 0 : 1);
