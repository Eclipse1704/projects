import { DEFAULT_SETTINGS } from "./presets.js";

export async function loadSettings() {
  const { settings } = await chrome.storage.local.get("settings");
  return { ...DEFAULT_SETTINGS, ...(settings || {}) };
}

export async function saveSettings(patch) {
  const current = await loadSettings();
  await chrome.storage.local.set({ settings: { ...current, ...patch } });
}
