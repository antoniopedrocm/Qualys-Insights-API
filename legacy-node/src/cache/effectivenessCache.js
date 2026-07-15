const fs = require('fs/promises');
const path = require('path');

const CACHE_PATH = path.join(__dirname, '..', '..', 'data', 'effectiveness-cache.json');

let writeQueue = Promise.resolve();

function buildEmptyCache() {
  return {
    meta: {
      generatedAt: new Date(0).toISOString(),
      source: 'qualys-active-vulns-cache',
      version: 1
    },
    itemsByDetectionId: {}
  };
}

async function ensureCacheDir() {
  await fs.mkdir(path.dirname(CACHE_PATH), { recursive: true });
}

async function loadCache() {
  try {
    const raw = await fs.readFile(CACHE_PATH, 'utf-8');
    const parsed = JSON.parse(raw);
    return {
      ...buildEmptyCache(),
      ...parsed,
      meta: {
        ...buildEmptyCache().meta,
        ...(parsed.meta || {})
      },
      itemsByDetectionId: parsed.itemsByDetectionId || {}
    };
  } catch (error) {
    if (error.code === 'ENOENT') return buildEmptyCache();
    throw error;
  }
}

async function saveCache(cache) {
  await ensureCacheDir();
  const tempPath = `${CACHE_PATH}.tmp`;
  const payload = JSON.stringify(cache, null, 2);
  await fs.writeFile(tempPath, payload, 'utf-8');
  await fs.rename(tempPath, CACHE_PATH);
}

function mergeCacheItem(existingItem = {}, nextItem = {}) {
  const mergedTags = Array.isArray(nextItem.hostTags)
    ? nextItem.hostTags
    : (Array.isArray(existingItem.hostTags) ? existingItem.hostTags : []);

  return {
    ...existingItem,
    ...nextItem,
    dns: nextItem.dns ?? existingItem.dns ?? '',
    ip: nextItem.ip ?? existingItem.ip ?? '',
    title: nextItem.title ?? existingItem.title ?? '',
    severity: nextItem.severity ?? existingItem.severity ?? 'Info',
    solution: nextItem.solution ?? existingItem.solution ?? '',
    hostTags: mergedTags
  };
}

async function upsertMany(items = [], meta = {}) {
  writeQueue = writeQueue.then(async () => {
    const cache = await loadCache();

    items.forEach((item) => {
      const detectionId = String(item.detectionId || '').trim();
      if (!detectionId) return;
      const existing = cache.itemsByDetectionId[detectionId] || {};
      cache.itemsByDetectionId[detectionId] = mergeCacheItem(existing, {
        ...item,
        detectionId
      });
    });

    cache.meta = {
      ...cache.meta,
      ...meta,
      generatedAt: meta.generatedAt || new Date().toISOString(),
      source: 'qualys-active-vulns-cache',
      version: 1
    };

    await saveCache(cache);
    return cache;
  });

  return writeQueue;
}

module.exports = {
  CACHE_PATH,
  loadCache,
  saveCache,
  upsertMany,
  mergeCacheItem,
  buildEmptyCache
};
