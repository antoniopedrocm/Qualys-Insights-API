import React from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Tooltip,
  Legend,
} from 'chart.js';
import { Bar } from 'react-chartjs-2';

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip, Legend);

const SEVERITY_META = {
  crit: { label: 'Crítica', color: '#EF4444' },
  alta: { label: 'Alta', color: '#F97316' },
  media: { label: 'Média', color: '#FBBF24' },
};

const ICON_BY_AMBIENTE = {
  'Desenvolvimento e Qualidade': '🛠️',
  'Produção Baixa': '⚠️',
  'Produção Alta': '🔴',
};

const chartLabels = ['Crítica', 'Alta', 'Média'];

export const calcTotalPanel = (panel) =>
  ['crit', 'alta', 'media'].reduce(
    (acc, key) => acc + (panel[key]?.abertas || 0) + (panel[key]?.corrigidas || 0),
    0,
  );

const buildChartData = (panel) => {
  const abertas = ['crit', 'alta', 'media'].map((key) => panel[key]?.abertas || 0);
  const corrigidas = ['crit', 'alta', 'media'].map((key) => panel[key]?.corrigidas || 0);

  return {
    labels: chartLabels,
    datasets: [
      {
        label: 'Abertas',
        data: abertas,
        backgroundColor: ['crit', 'alta', 'media'].map((key) => SEVERITY_META[key].color),
        borderRadius: 7,
        borderSkipped: false,
        stack: 'vulnerabilidades',
      },
      {
        label: 'Corrigidas',
        data: corrigidas,
        backgroundColor: '#22C55E',
        borderRadius: 7,
        borderSkipped: false,
        stack: 'vulnerabilidades',
      },
    ],
  };
};

const buildChartOptions = (panel) => ({
  responsive: true,
  maintainAspectRatio: false,
  interaction: {
    mode: 'index',
    intersect: false,
  },
  plugins: {
    legend: {
      position: 'bottom',
      align: 'start',
      labels: {
        color: '#94A3B8',
        boxWidth: 14,
        boxHeight: 14,
        borderRadius: 4,
      },
    },
    tooltip: {
      backgroundColor: '#0B1220',
      titleColor: '#E2E8F0',
      bodyColor: '#CBD5E1',
      borderColor: '#1E293B',
      borderWidth: 1,
      callbacks: {
        title: (ctx) => ctx?.[0]?.label || '',
        label: (ctx) => {
          const severityKeyByIndex = ['crit', 'alta', 'media'];
          const severityKey = severityKeyByIndex[ctx.dataIndex];
          const severityLabel = SEVERITY_META[severityKey].label;
          const abertas = panel[severityKey]?.abertas || 0;
          const corrigidas = panel[severityKey]?.corrigidas || 0;
          const total = abertas + corrigidas;
          return `${severityLabel} — Abertas: ${abertas}, Corrigidas: ${corrigidas}, Total: ${total}`;
        },
      },
    },
  },
  scales: {
    x: {
      stacked: true,
      grid: { display: false },
      ticks: {
        color: '#94A3B8',
      },
    },
    y: {
      stacked: true,
      beginAtZero: true,
      ticks: {
        color: '#94A3B8',
      },
      grid: {
        color: 'rgba(148, 163, 184, 0.16)',
        drawBorder: false,
      },
    },
  },
});

const styles = {
  dashboard: {
    background: 'linear-gradient(160deg, #0B1220 0%, #0A0F1A 100%)',
    padding: '24px',
    minHeight: '100vh',
    color: '#E2E8F0',
    fontFamily: 'Inter, Segoe UI, Roboto, sans-serif',
  },
  grid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
    gap: '16px',
  },
  panel: {
    background: 'linear-gradient(180deg, #0E1A38 0%, #0A1630 100%)',
    border: '1px solid rgba(30, 41, 59, 0.9)',
    borderRadius: '14px',
    padding: '18px 18px 12px',
    boxShadow: '0 10px 30px rgba(0, 0, 0, 0.25)',
    minHeight: '420px',
    display: 'flex',
    flexDirection: 'column',
  },
  header: {
    display: 'grid',
    gridTemplateColumns: '1fr auto 1fr',
    alignItems: 'center',
    marginBottom: '14px',
    gap: '8px',
  },
  title: {
    margin: 0,
    fontSize: '1.55rem',
    fontWeight: 700,
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
  },
  total: {
    margin: 0,
    color: '#CBD5E1',
    fontWeight: 600,
    justifySelf: 'center',
    fontSize: '0.95rem',
  },
  chartWrap: {
    position: 'relative',
    flex: 1,
    minHeight: '280px',
  },
};

export const mockExecutiveData = [
  {
    ambiente: 'Desenvolvimento e Qualidade',
    crit: { abertas: 240, corrigidas: 420 },
    alta: { abertas: 460, corrigidas: 440 },
    media: { abertas: 700, corrigidas: 520 },
  },
  {
    ambiente: 'Produção Baixa',
    crit: { abertas: 120, corrigidas: 200 },
    alta: { abertas: 190, corrigidas: 280 },
    media: { abertas: 350, corrigidas: 230 },
  },
  {
    ambiente: 'Produção Alta',
    crit: { abertas: 210, corrigidas: 650 },
    alta: { abertas: 560, corrigidas: 670 },
    media: { abertas: 920, corrigidas: 660 },
  },
];

const ExecutiveDashboard = ({ data = mockExecutiveData }) => (
  <section style={styles.dashboard}>
    <div style={styles.grid}>
      {data.map((panel) => {
        const total = calcTotalPanel(panel);
        return (
          <article key={panel.ambiente} style={styles.panel}>
            <header style={styles.header}>
              <h2 style={styles.title}>
                <span>{ICON_BY_AMBIENTE[panel.ambiente] || '📊'}</span>
                {panel.ambiente}
              </h2>
              <p style={styles.total}>Total: {total} vulnerabilidades</p>
            </header>
            <div style={styles.chartWrap}>
              <Bar data={buildChartData(panel)} options={buildChartOptions(panel)} />
            </div>
          </article>
        );
      })}
    </div>
  </section>
);

export default ExecutiveDashboard;
