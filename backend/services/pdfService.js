const puppeteer = require('puppeteer');
const Indicator = require('../models/Indicator');
const buildHtml = (indicators, stats, opts = {}) => {
  const title = opts.title || `ThreatView Security Intelligence Report`;
  const generated = new Date().toLocaleString();
  const highRiskCount = indicators.filter(i => (i.risk_score || 0) >= 80).length;
  const rows = indicators.slice(0, 100).map(i => `
    <tr>
      <td><div class="indicator-cell">${i.indicator || ''}</div></td>
      <td><span class="badge ${i.type}">${(i.type||'').toUpperCase()}</span></td>
      <td><span class="score ${i.risk_score >= 80 ? 'high' : i.risk_score >= 50 ? 'medium' : 'low'}">${i.risk_score||0}</span></td>
      <td>${i.source||''}</td>
      <td>${i.country||''}</td>
    </tr>`).join('');
  return `
  <!DOCTYPE html>
  <html>
  <head>
    <meta charset="utf-8" />
    <style>
      :root { --primary: #6366f1; --secondary: #a855f7; --text-main: #1e293b; --text-muted: #64748b; --border: #e2e8f0; }
      body { font-family: 'Inter', -apple-system, sans-serif; color: var(--text-main); margin: 0; padding: 40px; line-height: 1.5; }
      .header { border-bottom: 2px solid var(--primary); padding-bottom: 20px; margin-bottom: 40px; display: flex; justify-content: space-between; align-items: flex-end; }
      .header h1 { margin: 0; color: var(--primary); font-size: 24px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.05em; }
      .meta { font-size: 12px; color: var(--text-muted); text-align: right; }
      .summary-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 40px; }
      .summary-card { padding: 20px; border: 1px solid var(--border); border-radius: 12px; background: #f8fafc; }
      .summary-card h3 { margin: 0 0 8px 0; font-size: 12px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.05em; }
      .summary-card .value { font-size: 28px; font-weight: 700; color: var(--text-main); }
      h2 { font-size: 18px; margin-bottom: 20px; color: var(--text-main); display: flex; align-items: center; gap: 10px; }
      table { width: 100%; border-collapse: collapse; }
      th { text-align: left; padding: 12px; border-bottom: 2px solid var(--border); color: var(--text-muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; }
      td { padding: 12px; border-bottom: 1px solid var(--border); font-size: 13px; }
      .indicator-cell { font-family: 'JetBrains Mono', monospace; font-weight: 500; color: #0f172a; }
      .badge { font-size: 10px; font-weight: 700; padding: 4px 8px; border-radius: 6px; background: #f1f5f9; color: var(--text-muted); }
      .badge.ip { background: #e0f2fe; color: #0369a1; }
      .score { font-weight: 700; }
      .score.high { color: #dc2626; }
      .score.medium { color: #d97706; }
      .score.low { color: #059669; }
      .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid var(--border); font-size: 10px; color: var(--text-muted); text-align: center; }
    </style>
  </head>
  <body>
    <div class="header">
      <div>
        <h1>ThreatView</h1>
        <div style="font-size: 14px; font-weight: 600; color: var(--text-muted);">${title}</div>
      </div>
      <div class="meta">
        <div>Generated: ${generated}</div>
        <div>Period: ${opts.startDate || 'Last 7 Days'} → ${opts.endDate || 'Now'}</div>
      </div>
    </div>
    <div class="summary-grid">
      <div class="summary-card">
        <h3>Total Indicators</h3>
        <div class="value">${indicators.length}</div>
      </div>
      <div class="summary-card">
        <h3>High Risk Threats</h3>
        <div class="value" style="color: #dc2626">${highRiskCount}</div>
      </div>
      <div class="summary-card">
        <h3>Data Sources</h3>
        <div class="value">${Object.keys(stats.bySource||{}).length}</div>
      </div>
    </div>
    <section>
      <h2>Recent Security Intelligence</h2>
      <table>
        <thead><tr><th>Indicator</th><th>Type</th><th>Risk</th><th>Source</th><th>Country</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </section>
    <div class="footer">
      This report is confidential and intended for authorized security personnel only. 
      © ${new Date().getFullYear()} ThreatView Intelligence Platform.
    </div>
  </body>
  </html>`;
};
const normalizeDate = (value) => {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
};
const generatePDF = async (opts = {}) => {
  const startDate = normalizeDate(opts.startDate);
  const endDate = normalizeDate(opts.endDate);
  const indicatorsAll = await Indicator.findAll();
  const filtered = indicatorsAll.filter(i => {
    if (!startDate && !endDate) return true;
    const last = new Date(i.last_seen || i.createdAt);
    if (startDate && last < startDate) return false;
    if (endDate && last > endDate) return false;
    return true;
  });
  const stats = await Indicator.getStats();
  const html = buildHtml(filtered, stats, { startDate: opts.startDate, endDate: opts.endDate, title: opts.title });
  const browser = await puppeteer.launch({ headless: 'new', args: ['--no-sandbox', '--disable-setuid-sandbox'] });
  const page = await browser.newPage();
  await page.setContent(html, { waitUntil: 'networkidle0' });
  const pdfBuffer = await page.pdf({ format: 'A4', printBackground: true, margin: { top: '20mm', bottom: '20mm', left: '10mm', right: '10mm' } });
  await browser.close();
  return pdfBuffer;
};
module.exports = {
  generatePDF
};