// services/leaderboard.service.js
const fs = require("fs/promises");
const path = require("path");

const DATA_DIR = path.join(__dirname, "..", "data");
const DATA_PATH = path.join(DATA_DIR, "leaderboard.json");
const TMP_PATH = path.join(DATA_DIR, "leaderboard.tmp.json");

// In-process mutex for sequential writes
let writeLock = Promise.resolve();

async function ensureStorage() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  try {
    await fs.access(DATA_PATH);
  } catch {
    await fs.writeFile(DATA_PATH, "[]", "utf-8");
  }
}

async function readAll() {
  await ensureStorage();
  const raw = await fs.readFile(DATA_PATH, "utf-8");
  const json = JSON.parse(raw);
  return Array.isArray(json) ? json : [];
}

async function writeAll(list) {
  const data = JSON.stringify(list, null, 2);
  await fs.writeFile(TMP_PATH, data, "utf-8");
  await fs.rename(TMP_PATH, DATA_PATH);
}

function withWriteLock(fn) {
  writeLock = writeLock.then(fn, fn);
  return writeLock;
}

function normalizeItem(guid, payload) {
  return {
    guid: String(guid),
    name: String(payload.name ?? "Unknown").slice(0, 64),
    tag: String(payload.tag ?? "").replace(/^#/, "").slice(0, 16),
    score: Number(payload.score ?? 0),
    updatedAt: payload.updatedAt ?? null,
  };
}

/**
 * Paged list:
 * returns { page, limit, total, totalPages, data:[...ranked...] }
 */
exports.listPaged = async (page = 1, limit = 10) => {
  const p = Math.max(Number(page || 1), 1);
  const l = Math.min(Math.max(Number(limit || 10), 1), 100);

  const list = await readAll();
  list.sort((a, b) => Number(b.score || 0) - Number(a.score || 0));

  const total = list.length;
  const totalPages = Math.max(1, Math.ceil(total / l));
  const safePage = Math.min(p, totalPages);

  const start = (safePage - 1) * l;
  const slice = list.slice(start, start + l).map((x, i) => ({
    ...x,
    rank: start + i + 1,
  }));

  return {
    page: safePage,
    limit: l,
    total,
    totalPages,
    data: slice,
  };
};

// Backward-compatible: list first N items as array (ranked)
exports.list = async (limit = 100) => {
  const res = await exports.listPaged(1, Math.min(Number(limit || 100), 1000));
  return res.data;
};

exports.get = async (guid) => {
  const list = await readAll();
  const item = list.find((x) => String(x.guid) === String(guid));
  return item || null;
};

exports.create = async (guid, payload) => {
  return withWriteLock(async () => {
    const list = await readAll();
    const exists = list.some((x) => String(x.guid) === String(guid));
    if (exists) {
      const err = new Error("already exists");
      err.code = "ALREADY_EXISTS";
      throw err;
    }

    const item = normalizeItem(guid, payload);
    list.push(item);

    await writeAll(list);
    return item;
  });
};

exports.update = async (guid, patch) => {
  return withWriteLock(async () => {
    const list = await readAll();
    const idx = list.findIndex((x) => String(x.guid) === String(guid));
    if (idx < 0) return null;

    const current = list[idx] || {};
    const next = {
      ...current,
      ...patch,
      guid: String(guid),
    };

    list[idx] = normalizeItem(guid, next);
    await writeAll(list);
    return list[idx];
  });
};

exports.remove = async (guid) => {
  return withWriteLock(async () => {
    const list = await readAll();
    const before = list.length;
    const filtered = list.filter((x) => String(x.guid) !== String(guid));
    if (filtered.length === before) return false;

    await writeAll(filtered);
    return true;
  });
};