const test = require('node:test');
const assert = require('node:assert/strict');

const { normalizeSeverity } = require('../src/severity');

test('normalizeSeverity converte formatos comuns do Qualys para pt-BR', () => {
  assert.equal(normalizeSeverity('5'), 'Crítica');
  assert.equal(normalizeSeverity('4 - High'), 'Alta');
  assert.equal(normalizeSeverity('Medium'), 'Média');
  assert.equal(normalizeSeverity('baixa'), 'Baixa');
  assert.equal(normalizeSeverity('informational'), 'Info');
});
