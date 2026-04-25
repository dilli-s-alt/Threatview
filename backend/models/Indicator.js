const db = require('../database');
const Indicator = {
  async findAll(options = {}) {
    return await db.find(options);
  },
  async findAndCountAll(options = {}) {
    const { page = 1, limit = 10, search = '', type = '' } = options;
    return await db.findPaginated({
      page: parseInt(page),
      limit: parseInt(limit),
      search,
      type
    });
  },
  async findOrCreate({ where, defaults }) {
    return await db.findOrCreate({ where, defaults });
  },
  async count() {
    return await db.count();
  },
  async findById(id) {
    const indicators = await db.find();
    return indicators.find(i => i.id === id);
  },
  async findByIndicator(indicator) {
    const indicators = await db.find();
    return indicators.find(i => i.indicator === indicator);
  },
  async findByType(type) {
    return await db.find({ type });
  },
  async findBySource(source) {
    return await db.find({ source });
  },
  async findHighRisk(limit = 100) {
    const indicators = await db.find({ limit });
    return indicators.filter(i => (i.risk_score || 0) >= 80);
  },
  async findRecent(hoursAgo = 24) {
    const cutoff = new Date(Date.now() - hoursAgo * 60 * 60 * 1000);
    const indicators = await db.find();
    return indicators.filter(i => new Date(i.last_seen || i.createdAt) >= cutoff);
  },
  async update(id, updates) {
    return await db.update(id, updates);
  },
  async deleteOlderThan(days) {
    return await db.deleteOlderThan(days);
  },
  async getStats() {
    const indicators = await db.find();
    const stats = {
      total: indicators.length,
      highRisk: indicators.filter(i => (i.risk_score || 0) >= 80).length,
      mediumRisk: indicators.filter(i => (i.risk_score || 0) >= 50 && (i.risk_score || 0) < 80).length,
      lowRisk: indicators.filter(i => (i.risk_score || 0) < 50).length,
      byType: this._groupBy(indicators, 'type'),
      bySource: this._groupBy(indicators, 'source'),
      byCountry: this._groupBy(indicators, 'country'),
      byThreatType: this._groupBy(indicators, 'threat_type'),
      lastSevenDays: indicators.filter(i => {
        const date = new Date(i.last_seen || i.createdAt);
        return date >= new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
      }).length
    };
    return stats;
  },
  async logAlert(indicator, user, reason) {
    return await db.logAlert(indicator, user, reason);
  },
  _groupBy(array, key) {
    return array.reduce((acc, obj) => {
      acc[obj[key]] = (acc[obj[key]] || 0) + 1;
      return acc;
    }, {});
  }
};
module.exports = Indicator;