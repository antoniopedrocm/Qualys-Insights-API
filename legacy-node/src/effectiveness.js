function parseDetectionIds(input = '') {
  if (typeof input !== 'string') return [];

  const tokens = input
    .split(/[\n,;\s]+/)
    .map((token) => token.trim())
    .filter(Boolean);

  return Array.from(new Set(tokens));
}

function classifyDetectionIds(ids = [], activeSet = new Set()) {
  const uniqueIds = Array.from(new Set(ids.map((id) => String(id).trim()).filter(Boolean)));

  const items = uniqueIds.map((detectionId) => {
    const isNumeric = /^\d+$/.test(detectionId);
    if (!isNumeric) {
      return { detectionId, status: 'invalid' };
    }

    return {
      detectionId,
      status: activeSet.has(detectionId) ? 'open' : 'fixed'
    };
  });

  const summary = items.reduce(
    (acc, item) => {
      acc.total += 1;
      if (item.status === 'open') acc.open += 1;
      if (item.status === 'fixed') acc.fixed += 1;
      if (item.status === 'invalid') acc.invalid += 1;
      return acc;
    },
    { total: 0, fixed: 0, open: 0, invalid: 0 }
  );

  return { ...summary, items };
}

module.exports = {
  parseDetectionIds,
  classifyDetectionIds
};
