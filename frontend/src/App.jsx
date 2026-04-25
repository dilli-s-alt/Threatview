import { useEffect, useState } from 'react';
import { geoMercator, geoPath } from 'd3-geo';
import { feature } from 'topojson-client';
import landData from 'world-atlas/land-110m.json';
import { XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, CartesianGrid } from 'recharts';
import { Globe2, ShieldCheck, Search, AlertTriangle, LayoutDashboard, Bell, Settings, Download, RefreshCw } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import Sidebar from './components/Sidebar';
import './App.css';

const riskColors = { high: '#ef4444', medium: '#f59e0b', low: '#10b981' };
const API_BASE = import.meta.env.VITE_API_BASE || (window.location.hostname === 'localhost' ? 'http://localhost:3001' : 'https://threatview-ayee.onrender.com');
const COUNTRY_COORDINATES = {
  US: { longitude: -98, latitude: 39 }, CN: { longitude: 103, latitude: 35 }, RU: { longitude: 37, latitude: 55 },
  IN: { longitude: 78, latitude: 22 }, BR: { longitude: -51, latitude: -10 }, DE: { longitude: 10, latitude: 51 },
  FR: { longitude: 2, latitude: 46 }, GB: { longitude: -1, latitude: 54 }, JP: { longitude: 138, latitude: 36 },
  KR: { longitude: 127, latitude: 37 }, CA: { longitude: -106, latitude: 56 }
};

const projectPoint = (longitude, latitude) => {
  const coords = projection([Number(longitude), Number(latitude)]);
  return coords ? { x: coords[0], y: coords[1] } : { x: 0, y: 0 };
};

const projectCountry = (countryCode) => {
  const country = COUNTRY_COORDINATES[countryCode.toUpperCase()];
  return country ? projectPoint(country.longitude, country.latitude) : null;
};

const LAND_FEATURES = feature(landData, landData.objects.land).features;
const projection = geoMercator().fitSize([960, 340], { type: 'FeatureCollection', features: LAND_FEATURES });
const pathGenerator = geoPath().projection(projection);

function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [stats, setStats] = useState(null);
  const [indicators, setIndicators] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [search, setSearch] = useState('');
  const [brandQuery, setBrandQuery] = useState('healthcare.com');
  const [brandResult, setBrandResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [brandLoading, setBrandLoading] = useState(false);
  const [reportLoading, setReportLoading] = useState(false);
  const [apiOnline, setApiOnline] = useState(false);

  useEffect(() => {
    const checkHealth = async () => {
      try {
        const res = await fetch(`${API_BASE}/health`);
        setApiOnline(res.ok);
      } catch {
        setApiOnline(false);
      }
    };
    checkHealth();
    const interval = setInterval(checkHealth, 10000);
    return () => clearInterval(interval);
  }, []);
  const [error, setError] = useState(null);
  const [tier, setTier] = useState(localStorage.getItem('userTier') || 'free');
  const [toast, setToast] = useState(null);

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 3000);
  };
  const [sortField, setSortField] = useState('last_seen');
  const [sortDirection, setSortDirection] = useState('desc');

  const fetchStats = async (retryCount = 0) => {
    try {
      const response = await fetch(`${API_BASE}/api/stats`, { 
        headers: { 'x-tier': tier },
        signal: AbortSignal.timeout(30000)
      });
      if (response.status === 502 && retryCount < 3) {
        setTimeout(() => fetchStats(retryCount + 1), 5000);
        return;
      }
      if (!response.ok) throw new Error('Stats request failed');
      setStats(await response.json());
      setError(null);
    } catch (err) { 
      if (retryCount < 2) setTimeout(() => fetchStats(retryCount + 1), 5000);
      else setError('Unable to load dashboard stats.'); 
    }
  };

  const fetchIndicators = async (query = '', retryCount = 0) => {
    setLoading(true);
    try {
      const url = query ? `${API_BASE}/api/search?query=${encodeURIComponent(query)}` : `${API_BASE}/api/indicators?page=1&limit=50`;
      const response = await fetch(url, { 
        headers: { 'x-tier': tier },
        signal: AbortSignal.timeout(30000)
      });
      if (response.status === 502 && retryCount < 3) {
        setTimeout(() => fetchIndicators(query, retryCount + 1), 5000);
        return;
      }
      const result = await response.json();
      setIndicators(result.results || result.data || []);
      setError(null);
    } catch (err) { 
      if (retryCount < 2) setTimeout(() => fetchIndicators(query, retryCount + 1), 5000);
      else setError('Unable to load threat indicators.'); 
    } finally { setLoading(false); }
  };

  const fetchAlerts = async () => {
    try {
      const response = await fetch(`${API_BASE}/api/alerts`, { headers: { 'x-tier': tier } });
      const result = await response.json();
      setAlerts(result.userAlerts || []);
    } catch (err) { console.error('Alerts fetch failed'); }
  };

  const fetchBrandSearch = async (domain) => {
    if (!domain) return;
    setBrandLoading(true);
    try {
      const response = await fetch(`${API_BASE}/api/brand/search?domain=${encodeURIComponent(domain)}`, { headers: { 'x-tier': tier } });
      setBrandResult(await response.json());
    } catch (err) { setBrandResult({ status: 'error', message: err.message }); } finally { setBrandLoading(false); }
  };

  useEffect(() => {
    fetchStats();
    fetchBrandSearch(brandQuery);
    fetchAlerts();
  }, [tier]);

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchIndicators(search);
    }, 400);
    return () => clearTimeout(timer);
  }, [search, tier]);

  const handleManualSync = async () => {
    setLoading(true);
    try {
      await fetch(`${API_BASE}/api/ingestion/manual-sync`, { method: 'POST', headers: { 'x-tier': tier } });
      await Promise.all([fetchStats(), fetchIndicators(search), fetchAlerts()]);
      showToast('Intelligence sync complete. Dashboard updated.');
    } catch (err) { setError('Manual sync failed.'); } finally { setLoading(false); }
  };

  const downloadExport = async (type) => {
    if (tier !== 'pro' && type !== 'json') {
      showToast('Advanced exports require Pro Tier.', 'error');
      return;
    }
    setReportLoading(true);
    try {
      const response = await fetch(`${API_BASE}/api/export/${type}`, { headers: { 'x-tier': tier } });
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `threatview_export_${new Date().getTime()}.${type}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      showToast(`${type.toUpperCase()} export generated successfully.`);
    } catch (err) { setError('Export failed.'); } finally { setReportLoading(false); }
  };

  const sortedIndicators = [...indicators].sort((a, b) => {
    const aVal = sortField === 'risk_score' ? Number(a.risk_score || 0) : (a[sortField] || '');
    const bVal = sortField === 'risk_score' ? Number(b.risk_score || 0) : (b[sortField] || '');
    return sortDirection === 'desc' ? (aVal < bVal ? 1 : -1) : (aVal > bVal ? 1 : -1);
  });

  const renderDashboard = () => (
    <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} className="dashboard-shell">
      <header className="view-header">
        <h1>Intelligence Overview</h1>
        <div className="header-actions">
          <div className="connection-status">
            <span className={`dot ${!apiOnline ? 'offline' : (loading ? 'syncing' : 'online')}`}></span>
            <span className="status-text">
              {!apiOnline ? 'System Offline' : (loading ? 'Syncing...' : 'System Online')}
            </span>
          </div>
          <button className="btn btn-secondary" onClick={handleManualSync} disabled={loading}>
            <RefreshCw size={18} className={loading ? 'animate-spin' : ''} />
            <span>Manual Sync</span>
          </button>
        </div>
      </header>

      <div className="summary-grid">
        <div className="stat-card glass-card">
          <div className="stat-icon icon-primary"><ShieldCheck size={24} /></div>
          <div><span>Indicators</span><strong>{stats?.totalIndicators ?? 0}</strong></div>
        </div>
        <div className="stat-card glass-card">
          <div className="stat-icon icon-warning"><AlertTriangle size={24} /></div>
          <div><span>High Risk</span><strong>{stats?.highRiskCount ?? 0}</strong></div>
        </div>
        <div className="stat-card glass-card">
          <div className="stat-icon icon-globe"><Globe2 size={24} /></div>
          <div><span>Top Countries</span><strong>{stats?.countryDistribution?.length ?? 0}</strong></div>
        </div>
      </div>

      <div className="chart-grid">
        <div className="glass-card chart-card">
          <h2>Risk Level</h2>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={stats?.typeDistribution || []}>
              <CartesianGrid stroke="rgba(255,255,255,0.05)" vertical={false} />
              <XAxis dataKey="name" tick={{fill: '#94a3b8', fontSize: 10}} axisLine={false} tickLine={false} />
              <YAxis tick={{fill: '#94a3b8', fontSize: 10}} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{background: '#0f172a', border: '1px solid rgba(255,255,255,0.1)'}} />
              <Bar dataKey="value" fill="#6366f1" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="map-section glass-card">
        <div className="section-header"><h2>Global Threat Map</h2></div>
        <div className="map-visual">
          <svg viewBox="0 0 960 340" className="world-map">
            {LAND_FEATURES.map((f, i) => <path key={i} d={pathGenerator(f)} className="world-land" />)}
            {indicators.filter(it => it.latitude && it.longitude).map((it, i) => {
              const pt = projectPoint(it.longitude, it.latitude);
              const color = it.risk_score > 70 ? riskColors.high : it.risk_score > 40 ? riskColors.medium : riskColors.low;
              return <circle key={i} cx={pt.x} cy={pt.y} r="4" fill={color} opacity="0.8" />;
            })}
          </svg>
        </div>
      </div>
    </motion.div>
  );

  const renderIoCSearch = () => (
    <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -20 }} className="dashboard-shell">
      <header className="view-header">
        <h1>IoC Search</h1>
        <div className="search-box">
          <Search size={18} />
          <input type="text" value={search} placeholder="Search indicators..." onChange={(e) => setSearch(e.target.value)} />
        </div>
      </header>
      <div className="glass-card table-section">
        <div className="indicator-table">
          <table>
            <thead>
              <tr>
                <th onClick={() => setSortField('indicator')}>Indicator</th>
                <th onClick={() => setSortField('type')}>Type</th>
                <th onClick={() => setSortField('risk_score')}>Risk</th>
                <th onClick={() => setSortField('source')}>Source</th>
                <th onClick={() => setSortField('last_seen')}>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {sortedIndicators.map(it => (
                <tr key={it.id}>
                  <td>{it.indicator}</td>
                  <td><span className={`type-tag ${it.type}`}>{it.type}</span></td>
                  <td><span className="risk-score" style={{color: it.risk_score > 70 ? '#ef4444' : it.risk_score > 40 ? '#f59e0b' : '#10b981'}}>{it.risk_score}</span></td>
                  <td>{it.source}</td>
                  <td>{new Date(it.last_seen || it.createdAt).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </motion.div>
  );

  const renderBrandMonitor = () => (
    <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.95 }} className="dashboard-shell">
      <header className="view-header">
        <h1>Brand Monitor</h1>
      </header>
      <div className="glass-card brand-section">
        <p className="section-desc">Search your domain in active threat feeds to identify potential phishing or impersonation attempts.</p>
        <form className="brand-form" onSubmit={(e) => { e.preventDefault(); fetchBrandSearch(brandQuery); }}>
          <input type="text" value={brandQuery} onChange={(e) => setBrandQuery(e.target.value)} placeholder="Enter domain..." />
          <button className="btn btn-primary" type="submit" disabled={brandLoading}>{brandLoading ? 'Checking...' : 'Run Analysis'}</button>
        </form>
        {brandResult && (
          <div className={`brand-result ${brandResult.status.toLowerCase()}`}>
            <h3>{brandResult.status}: {brandResult.message}</h3>
            {brandResult.matches?.length > 0 && (
              <div className="brand-matches">
                <table>
                  <thead><tr><th>Indicator</th><th>Risk</th><th>Source</th><th>Last Seen</th></tr></thead>
                  <tbody>{brandResult.matches.map((m, i) => (
                    <tr key={i}><td>{m.indicator}</td><td>{m.risk_score}</td><td>{m.source}</td><td>{new Date(m.last_seen).toLocaleDateString()}</td></tr>
                  ))}</tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>
    </motion.div>
  );

  const renderAlerts = () => (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="dashboard-shell">
      <header className="view-header">
        <div>
          <h1>Alerts Center</h1>
          <p className="subtitle">Real-time threat notifications matching your profile.</p>
        </div>
      </header>
      <div className="alerts-list">
        {alerts.length === 0 ? (
          <div className="glass-card table-empty">
            <Bell size={48} style={{ opacity: 0.2, marginBottom: 16 }} />
            <p>No active alerts detected. Your environment is currently secure.</p>
          </div>
        ) : (
          alerts.map(a => (
            <div key={a.id} className={`glass-card alert-item-premium ${a.severity?.toLowerCase()}`}>
              <div className="alert-badge-container">
                <span className={`severity-badge ${a.severity?.toLowerCase()}`}>
                  {a.severity || 'HIGH'}
                </span>
              </div>
              <div className="alert-main">
                <div className="alert-top">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <strong className="alert-indicator">{a.indicator}</strong>
                    {a.delivery && (
                      <span className={`delivery-pill ${a.delivery.status}`}>
                        {a.delivery.status === 'sent' ? '✉️ Sent' : a.delivery.status === 'mocked' ? '🧪 Mock' : '❌ Fail'}
                      </span>
                    )}
                  </div>
                  <span className="alert-time">{new Date(a.createdAt).toLocaleString()}</span>
                </div>
                <p className="alert-reason">{a.reason}</p>
                <div className="alert-footer">
                  <span className="alert-type-tag">{a.type?.replace('_', ' ')}</span>
                  <div className="alert-actions-inline">
                    <button className="btn-text" onClick={() => acknowledgeAlert(a.id)}>Acknowledge</button>
                    <button className="btn-text secondary">Investigate</button>
                  </div>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </motion.div>
  );

  const [configStatus, setConfigStatus] = useState({ emailService: 'loading' });

  useEffect(() => {
    fetch(`${API_BASE}/api/config/status`).then(res => res.json()).then(data => setConfigStatus(data)).catch(() => {});
  }, []);

  const renderSettings = () => (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="dashboard-shell">
      <header className="view-header"><h1>Account & Settings</h1></header>
      <div className="glass-card settings-section">
        <div className="setting-group">
          <h3>Subscription Tier</h3>
          <div className="tier-selector">
            <div className={`tier-card ${tier === 'free' ? 'active' : ''}`} onClick={() => { setTier('free'); localStorage.setItem('userTier', 'free'); }}>
              <h4>Free Tier</h4>
              <p>24h history access</p>
            </div>
            <div className={`tier-card ${tier === 'pro' ? 'active' : ''}`} onClick={() => { setTier('pro'); localStorage.setItem('userTier', 'pro'); }}>
              <h4>Pro Tier</h4>
              <p>Unlimited history & Exports</p>
            </div>
          </div>
        </div>
        <div className="setting-group">
          <div className="group-header-flex">
            <h3>Notifications</h3>
            <span className={`status-pill ${configStatus.emailService}`}>
              {configStatus.emailService.toUpperCase()} MODE
            </span>
          </div>
          <div className="setting-row">
            <p>Test your email alert integration (SendGrid).</p>
            <button className="btn btn-secondary" onClick={async () => {
              const res = await fetch(`${API_BASE}/api/test/email`, { method: 'POST', headers: { 'x-tier': tier } });
              const data = await res.json();
              if (data.success) {
                const mode = data.mockMode ? 'MOCK' : 'LIVE';
                alert(`Success (${mode} Mode)! Test email processed. Check your console/inbox.`);
              } else alert('Failed to send test email: ' + (data.error || 'Unknown error'));
            }}>Send Test Email</button>
          </div>
        </div>
        <div className="setting-group">
          <h3>Data Exports</h3>
          <div className="export-actions">
            <button className="btn btn-secondary" onClick={() => downloadExport('pdf')} disabled={reportLoading}><Download size={18} /><span>PDF Report</span></button>
            <button className="btn btn-secondary" onClick={() => downloadExport('csv')} disabled={reportLoading}><Download size={18} /><span>CSV Export</span></button>
            <button className="btn btn-secondary" onClick={() => downloadExport('json')} disabled={reportLoading}><Download size={18} /><span>JSON Export</span></button>
          </div>
        </div>
      </div>
    </motion.div>
  );

  return (
    <div className="app-container">
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} tier={tier} />
      <main className="main-content">
        <AnimatePresence mode="wait">
          {activeTab === 'dashboard' && renderDashboard()}
          {activeTab === 'indicators' && renderIoCSearch()}
          {activeTab === 'brand' && renderBrandMonitor()}
          {activeTab === 'alerts' && renderAlerts()}
          {activeTab === 'settings' && renderSettings()}
        </AnimatePresence>
      </main>

      <AnimatePresence>
        {toast && (
          <motion.div
            initial={{ opacity: 0, y: 50, scale: 0.9 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 20, scale: 0.9 }}
            className={`toast-notification ${toast.type}`}
          >
            {toast.type === 'success' ? <div className="toast-icon">✓</div> : <div className="toast-icon">!</div>}
            <div className="toast-message">{toast.message}</div>
          </motion.div>
        )}
      </AnimatePresence>

      {error && <div className="error-banner">{error}</div>}
    </div>
  );
}
export default App;