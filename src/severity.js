const severityMap = {
  '5': 'Crítica',
  '4': 'Alta',
  '3': 'Média',
  '2': 'Baixa',
  '1': 'Info',
  critical: 'Crítica',
  high: 'Alta',
  medium: 'Média',
  low: 'Baixa',
  info: 'Info',
  informational: 'Info'
};

function normalizeSeverity(input) {
  if (input === null || input === undefined) return 'Info';
  const raw = String(input).trim();
  if (!raw) return 'Info';

  const normalized = raw.toLowerCase();
  if (severityMap[normalized]) return severityMap[normalized];

  const digitMatch = normalized.match(/[1-5]/);
  if (digitMatch && severityMap[digitMatch[0]]) {
    return severityMap[digitMatch[0]];
  }

  const accentless = normalized
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '');

  if (accentless.includes('crit')) return 'Crítica';
  if (accentless.includes('high') || accentless.includes('alta')) return 'Alta';
  if (accentless.includes('med')) return 'Média';
  if (accentless.includes('low') || accentless.includes('baixa')) return 'Baixa';

  return 'Info';
}

module.exports = {
  normalizeSeverity
};
