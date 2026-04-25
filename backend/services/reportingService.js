const { jsPDF } = require('jspdf');
const pdfService = require('./pdfService');
const Indicator = require('../models/Indicator');
const db = require('../database');
const _filterByDateRange = (items, startDate, endDate) => {
  if (!startDate && !endDate) return items;
  const start = startDate ? new Date(startDate) : null;
  const end = endDate ? new Date(endDate) : null;
  return items.filter(i => {
    const last = new Date(i.last_seen || i.createdAt);
    if (start && last < start) return false;
    if (end && last > end) return false;
    return true;
  });
};
const generateThreatReport = async (opts = {}) => {
  try {
    return await pdfService.generatePDF(opts);
  } catch (err) {
    const indicators = await Indicator.findAll();
    const filtered = _filterByDateRange(indicators, opts.startDate, opts.endDate);
    const stats = await Indicator.getStats();
    const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
    doc.text('ThreatView - Fallback Report', 20, 20);
    doc.text(`Indicators: ${filtered.length}`, 20, 30);
    return doc.output('arraybuffer');
  }
};
const generateCSVExport = async (opts = {}) => {
  const indicators = await Indicator.findAll();
  const filtered = _filterByDateRange(indicators, opts.startDate, opts.endDate);
  let csv = 'ID,Indicator,Type,Threat Type,Risk Score,Source,Country,Industry Targets,Last Seen,Created At\n';
  const escaped = (str) => `"${(str || '').toString().replace(/"/g, '""')}"`;
  filtered.forEach(i => {
    csv += [
      escaped(i.id),
      escaped(i.indicator),
      escaped(i.type),
      escaped(i.threat_type),
      i.risk_score || 0,
      escaped(i.source),
      escaped(i.country),
      escaped(i.industry_targets),
      escaped(i.last_seen),
      escaped(i.createdAt)
    ].join(',') + '\n';
  });
  return csv;
};
const generateJSONExport = async (opts = {}) => {
  const indicators = await Indicator.findAll();
  const filtered = _filterByDateRange(indicators, opts.startDate, opts.endDate);
  return JSON.stringify(filtered, null, 2);
};
const generateAndEmailWeeklyReports = async () => {
  const EmailService = require('./emailService');
  const subscriptions = db.read().subscriptions || [];
  const pros = subscriptions.filter(s => s.tier === 'pro');
  if (!pros.length) return { sent: 0 };
  const endDate = new Date();
  const startDate = new Date(endDate.getTime() - 7 * 24 * 60 * 60 * 1000);
  const pdfBuffer = await generateThreatReport({ startDate: startDate.toISOString(), endDate: endDate.toISOString(), title: 'Weekly Threat Landscape' });
  let sent = 0;
  for (const p of pros) {
    const user = { id: p.id, email: p.email, name: p.email };
    const name = `ThreatView_Weekly_${new Date().toISOString().split('T')[0]}`;
    const result = await EmailService.sendReport(user, pdfBuffer, name);
    if (result.success) sent++;
  }
  return { sent };
};
module.exports = {
  generateThreatReport,
  generateCSVExport,
  generateJSONExport,
  generateAndEmailWeeklyReports
};