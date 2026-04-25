const fs = require('fs');
const path = require('path');
const DB_FILE = path.join(__dirname, process.env.DB_FILE_PATH || 'db.json');

class LocalDB {
  constructor() {
    this.data = null;
    this.writePromise = Promise.resolve();
    this.init();
  }

  init() {
    if (!fs.existsSync(DB_FILE)) {
      this.data = {
        indicators: [],
        alerts: [],
        users: [],
        subscriptions: [],
        metadata: {
          version: '1.0',
          createdAt: new Date().toISOString(),
          lastSync: null
        }
      };
      this._writeSync(this.data);
      if (process.env.VERBOSE_LOGS === 'true') {
        console.log(`✓ Database initialized at ${DB_FILE}`);
      }
    } else {
      try {
        const raw = fs.readFileSync(DB_FILE, 'utf8');
        this.data = JSON.parse(raw);
        if (process.env.VERBOSE_LOGS === 'true') {
          console.log(`✓ Database loaded from ${DB_FILE} (${raw.length} bytes)`);
        }
      } catch (e) {
        console.error('⚠ Corrupted database detected. Reinitializing...');
        this.data = {
          indicators: [],
          alerts: [],
          users: [],
          subscriptions: [],
          metadata: {
            version: '1.0',
            createdAt: new Date().toISOString(),
            lastSync: null
          }
        };
        this._writeSync(this.data);
      }
    }
  }

  read() {
    if (!this.data) this.init();
    return this.data;
  }

  async _writeAsync(data) {
    this.data = data; // Update in-memory cache immediately
    
    // Simple write queue to prevent concurrent writes to the same file
    this.writePromise = this.writePromise.then(async () => {
      const tempFile = DB_FILE + '.tmp';
      try {
        await fs.promises.writeFile(tempFile, JSON.stringify(data, null, 2));
        await fs.promises.rename(tempFile, DB_FILE);
      } catch (e) {
        console.error('Database write error:', e.message);
        if (fs.existsSync(tempFile)) fs.unlinkSync(tempFile);
      }
    });
    
    return this.writePromise;
  }

  _writeSync(data) {
    this.data = data;
    const tempFile = DB_FILE + '.tmp';
    try {
      fs.writeFileSync(tempFile, JSON.stringify(data, null, 2));
      fs.renameSync(tempFile, DB_FILE);
    } catch (e) {
      console.error('Database write error:', e.message);
      if (fs.existsSync(tempFile)) fs.unlinkSync(tempFile);
      throw e;
    }
  }

  _generateId() {
    return Date.now().toString(36) + Math.random().toString(36).substr(2);
  }

  async find(options = {}) {
    let indicators = this.read().indicators;
    if (options.type) {
      indicators = indicators.filter(i => i.type === options.type);
    }
    if (options.source) {
      indicators = indicators.filter(i => i.source === options.source);
    }
    if (options.limit) {
      indicators = indicators.slice(0, options.limit);
    }
    return indicators;
  }

  async findPaginated(options = {}) {
    const { page = 1, limit = 10, search = '', type = '' } = options;
    let indicators = this.read().indicators;
    if (search) {
      const q = search.toLowerCase();
      indicators = indicators.filter(i =>
        (i.indicator || '').toLowerCase().includes(q) ||
        (i.threat_type || '').toLowerCase().includes(q) ||
        (i.source || '').toLowerCase().includes(q) ||
        (i.country || '').toLowerCase().includes(q)
      );
    }
    if (type) {
      indicators = indicators.filter(i => i.type === type);
    }
    const total = indicators.length;
    const offset = (page - 1) * limit;
    const data = indicators.slice(offset, offset + limit);
    return { total, page, limit, pages: Math.ceil(total / limit), data };
  }

  async create(item) {
    const data = this.read();
    const newItem = {
      id: this._generateId(),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      ...item
    };
    data.indicators.push(newItem);
    data.metadata.lastSync = new Date().toISOString();
    await this._writeAsync(data);
    return newItem;
  }

  async findOrCreate({ where, defaults }) {
    const data = this.read();
    const key = Object.keys(where)[0];
    const existing = data.indicators.find(item => item[key] === where[key]);
    if (existing) {
      return [existing, false];
    }
    const newItem = {
      id: this._generateId(),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      ...defaults
    };
    data.indicators.push(newItem);
    data.metadata.lastSync = new Date().toISOString();
    await this._writeAsync(data);
    return [newItem, true];
  }

  async count() {
    return this.read().indicators.length;
  }

  async update(id, updates) {
    const data = this.read();
    const index = data.indicators.findIndex(i => i.id === id);
    if (index === -1) return null;
    data.indicators[index] = {
      ...data.indicators[index],
      ...updates,
      updatedAt: new Date().toISOString()
    };
    data.metadata.lastSync = new Date().toISOString();
    await this._writeAsync(data);
    return data.indicators[index];
  }

  async deleteOlderThan(days) {
    const data = this.read();
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - days);
    const before = data.indicators.length;
    data.indicators = data.indicators.filter(i =>
      new Date(i.last_seen || i.createdAt) >= cutoff
    );
    const deleted = before - data.indicators.length;
    if (deleted > 0) {
      data.metadata.lastSync = new Date().toISOString();
      await this._writeAsync(data);
    }
    return { deleted, remaining: data.indicators.length };
  }

  async addSubscription(email, tier = 'free') {
    const data = this.read();
    const sub = {
      id: this._generateId(),
      email,
      tier,
      createdAt: new Date().toISOString(),
      alertsEnabled: true,
      alertThreshold: 80
    };
    data.subscriptions.push(sub);
    await this._writeAsync(data);
    return sub;
  }

  async getSubscriptions() {
    return this.read().subscriptions || [];
  }

  async logAlert(indicator, user, reason, metadata = {}) {
    const data = this.read();
    const alert = {
      id: this._generateId(),
      indicatorId: indicator.id,
      indicator: indicator.indicator,
      userId: user.id,
      reason,
      status: 'pending',
      delivery: metadata,
      createdAt: new Date().toISOString()
    };
    data.alerts.push(alert);
    await this._writeAsync(data);
    return alert;
  }
}

const db = new LocalDB();
module.exports = db;