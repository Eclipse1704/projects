// Renders icons/icon{16,48,128}.png from an inline SVG (run: npm run icons).
import { chromium } from "playwright";
import { existsSync } from "node:fs";

const SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128">
  <rect width="128" height="128" rx="26" fill="#0b5cad"/>
  <rect x="26" y="30" width="52" height="64" rx="6" fill="#fff"/>
  <rect x="34" y="42" width="36" height="6" rx="3" fill="#0b5cad"/>
  <rect x="34" y="56" width="28" height="6" rx="3" fill="#0b5cad"/>
  <rect x="34" y="70" width="32" height="6" rx="3" fill="#0b5cad"/>
  <circle cx="84" cy="80" r="20" fill="none" stroke="#ffd166" stroke-width="10"/>
  <line x1="98" y1="95" x2="112" y2="110" stroke="#ffd166" stroke-width="12" stroke-linecap="round"/>
</svg>`;

const exe = "/opt/pw-browsers/chromium";
const browser = await chromium.launch(existsSync(exe) ? { executablePath: exe } : {});
for (const size of [16, 48, 128]) {
  const page = await browser.newPage({ viewport: { width: size, height: size } });
  await page.setContent(`<style>body{margin:0}</style>${SVG.replace("<svg ", `<svg width="${size}" height="${size}" `)}`);
  await page.screenshot({ path: `icons/icon${size}.png`, omitBackground: true });
  await page.close();
}
await browser.close();
