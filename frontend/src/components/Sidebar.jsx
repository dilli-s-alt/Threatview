import React from 'react';
import { 
  Globe2, 
  ShieldCheck, 
  Search, 
  AlertTriangle,
  LayoutDashboard,
  Bell,
  Settings,
  History,
} from 'lucide-react';

const Sidebar = ({ activeTab, setActiveTab, tier }) => {
  const menuItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'indicators', label: 'IoC Search', icon: Search },
    { id: 'brand', label: 'Brand Monitor', icon: ShieldCheck },
    { id: 'alerts', label: 'Alerts', icon: Bell },
    { id: 'settings', label: 'Settings', icon: Settings },
  ];

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="brand-icon">
          <ShieldCheck size={28} />
        </div>
        <div className="brand-text">
          <h2>ThreatView</h2>
          <span className={`tier-badge ${tier}`}>{tier.toUpperCase()}</span>
        </div>
      </div>

      <nav className="sidebar-nav">
        {menuItems.map((item) => (
          <button
            key={item.id}
            className={`nav-item ${activeTab === item.id ? 'active' : ''}`}
            onClick={() => setActiveTab(item.id)}
          >
            <item.icon size={20} />
            <span>{item.label}</span>
            {item.id === 'alerts' && <span className="notification-dot"></span>}
          </button>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div className="user-profile">
          <div className="avatar">JD</div>
          <div className="user-info">
            <strong>John Doe</strong>
            <span>SecOps Lead</span>
          </div>
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;
