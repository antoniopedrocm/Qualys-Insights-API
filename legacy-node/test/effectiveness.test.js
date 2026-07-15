const test = require('node:test');
const assert = require('node:assert/strict');

const { parseDetectionIds, classifyDetectionIds } = require('../src/effectiveness');

test('parseDetectionIds aceita múltiplos separadores e remove duplicados', () => {
  const input = '123\n456,789;123  999\t789';
  const parsed = parseDetectionIds(input);
  assert.deepEqual(parsed, ['123', '456', '789', '999']);
});

test('classifyDetectionIds marca open/fixed/invalid corretamente', () => {
  const ids = ['100', '200', 'abc', '300', '100'];
  const activeSet = new Set(['200', '300']);

  const result = classifyDetectionIds(ids, activeSet);

  assert.equal(result.total, 4);
  assert.equal(result.open, 2);
  assert.equal(result.fixed, 1);
  assert.equal(result.invalid, 1);
  assert.deepEqual(result.items, [
    { detectionId: '100', status: 'fixed' },
    { detectionId: '200', status: 'open' },
    { detectionId: 'abc', status: 'invalid' },
    { detectionId: '300', status: 'open' }
  ]);
});
