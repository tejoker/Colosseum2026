// Capture dashboard screenshots for the README.
//
//   CHROME=/path/to/chrome node scripts/screenshots.mjs
//
// Env:
//   BASE            dashboard URL (default http://localhost:3000)
//   CORE            core URL, used to log in (default http://localhost:3001)
//   OPERATOR/PASSWORD  dev-stack operator (default dev/dev)
//   CHROME          path to a Chrome/Chromium binary
//   OUT             output directory (default ../docs/img)
//   THEME           "dark" (default) or "light"
//
// Same shape as a11y-audit.mjs: puppeteer-core plus an explicit browser path,
// so nothing is downloaded at install time.
import puppeteer from "puppeteer-core";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const BASE = process.env.BASE || "http://localhost:3000";
const CHROME = process.env.CHROME || "/usr/bin/google-chrome";
const OUT = resolve(process.env.OUT || `${HERE}/../../docs/img`);
const THEME = process.env.THEME === "light" ? "light" : "dark";
const OPERATOR = process.env.OPERATOR || "dev";
const PASSWORD = process.env.PASSWORD || "dev";

const SHOTS = [
  ["/", "dashboard-overview.png"],
  ["/explorer", "dashboard-explorer.png"],
  ["/welcome", "dashboard-welcome.png"],
  ["/proofs", "dashboard-proofs.png"],
  [process.env.AGENT_PATH || "/protected", "dashboard-agent.png"],
];

mkdirSync(OUT, { recursive: true });

const browser = await puppeteer.launch({
  executablePath: CHROME,
  headless: "shell",
  args: ["--no-sandbox", "--disable-gpu"],
});

// Log in through the form rather than injecting the cookie: an injected cookie
// authenticates the page shell but the client-side fetches still came back
// empty, so the first screenshots showed "No agents registered yet" against a
// deployment with 369 of them.
const page = await browser.newPage();
await page.setViewport({ width: 1440, height: 900 });
await page.emulateMediaFeatures([{ name: "prefers-color-scheme", value: THEME }]);
await page.goto(`${BASE}/login`, { waitUntil: "networkidle2", timeout: 30000 });
await page.type("#login-operator", OPERATOR);
await page.type("#login-password", PASSWORD);
await Promise.all([
  page.waitForNavigation({ waitUntil: "networkidle2", timeout: 30000 }).catch(() => {}),
  page.click('button[type="submit"]'),
]);

for (const [path, file] of SHOTS) {
  const resp = await page.goto(BASE + path, { waitUntil: "networkidle2", timeout: 30000 });
  await new Promise((r) => setTimeout(r, 1500)); // let client-side fetches paint
  await page.screenshot({ path: `${OUT}/${file}` });
  console.log(`[${path}] status=${resp?.status()} -> ${file}`);
}
await page.close();

await browser.close();
