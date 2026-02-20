const test = require('node:test');
const assert = require('node:assert/strict');

const { mergeCacheItem } = require('../src/cache/effectivenessCache');

test('mergeCacheItem preserva dados antigos quando novo item vem incompleto', () => {
  const existing = {
    detectionId: '123',
    status: 'open',
    dns: 'srv.local',
    ip: '10.0.0.1',
    title: 'Titulo',
    severity: 'Alta',
    solution: 'Patch',
    hostTags: ['PRD'],
    lastSeen: '2026-02-18T10:00:00.000Z'
  };

  const incoming = {
    detectionId: '123',
    status: 'fixed',
    hostTags: [],
    lastSeen: '2026-02-18T10:00:00.000Z'
  };

  const merged = mergeCacheItem(existing, incoming);

  assert.equal(merged.status, 'fixed');
  assert.equal(merged.dns, 'srv.local');
  assert.equal(merged.ip, '10.0.0.1');
  assert.equal(merged.severity, 'Alta');
  assert.deepEqual(merged.hostTags, []);
  assert.equal(merged.lastSeen, '2026-02-18T10:00:00.000Z');
});
