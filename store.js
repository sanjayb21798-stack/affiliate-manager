// store.js — tiny JSON "database" for the Affiliate Manager

const fs = require('fs');
const path = require('path');

// You can override with: set DB_FILE=./data/affiliate-db.json
const DB_PATH = process.env.DB_FILE || path.join(__dirname, 'db.json');

// Default shape for a fresh DB (keep in sync with server.js expectations)
const DEFAULT_DB = {
  affiliates: [],
  clicks: [],
  conversions: [],
  commissions: [],
  payouts: [],
  merchants: [],   // Feature 4
  coupons: []      // Feature 4
};

// Ensure any loaded object has all required arrays
function ensureShape(obj) {
  const db = Object.assign({}, DEFAULT_DB, obj || {});
  // Make sure each key is an array (avoid null/undefined)
  for (const k of Object.keys(DEFAULT_DB)) {
    if (!Array.isArray(db[k])) db[k] = [];
  }
  return db;
}

// Atomic save (write to temp file then rename)
function atomicWrite(filePath, data) {
  const dir = path.dirname(filePath);
  const tmp = path.join(dir, `.tmp-${path.basename(filePath)}-${Date.now()}`);
  fs.writeFileSync(tmp, data);
  fs.renameSync(tmp, filePath);
}

function load() {
  try {
    if (!fs.existsSync(DB_PATH)) {
      // First run: create empty DB file
      atomicWrite(DB_PATH, JSON.stringify(DEFAULT_DB, null, 2));
      return JSON.parse(JSON.stringify(DEFAULT_DB));
    }
    const raw = fs.readFileSync(DB_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    return ensureShape(parsed);
  } catch (err) {
    // If the file is corrupted, back it up and start fresh
    try {
      const backup = `${DB_PATH}.corrupt-${Date.now()}.bak`;
      fs.copyFileSync(DB_PATH, backup);
      console.error(`[store] DB parse error. Backed up corrupt file to ${backup}`);
    } catch (_) {}
    return JSON.parse(JSON.stringify(DEFAULT_DB));
  }
}

function save(currentDb) {
  // Pretty-print for easier manual inspection
  const json = JSON.stringify(currentDb, null, 2);
  atomicWrite(DB_PATH, json);
}

// Load once and export the singleton
const db = load();

module.exports = {
  db,
  save,
  DB_PATH
};
