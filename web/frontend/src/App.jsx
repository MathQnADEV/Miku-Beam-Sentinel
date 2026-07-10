import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import { LayoutDashboard, Shield, Activity, FileText, Plus, Sparkles, Menu, X } from 'lucide-react';
import ScanConfig from './pages/ScanConfig';
import Reports from './pages/Reports';
import ReportDetail from './pages/ReportDetail';
import Login from './pages/Login';
import Projects from './pages/Projects';
import ProjectDetail from './pages/ProjectDetail';

const NavItem = ({ to, icon: Icon, label, onClick }) => (
  <Link
    to={to}
    onClick={onClick}
    className="flex items-center gap-3 px-4 py-2.5 rounded-xl text-white/90 hover:bg-white/25 hover:text-white transition font-medium"
  >
    <Icon className="w-5 h-5" /> {label}
  </Link>
);

const Sidebar = ({ open, onClose }) => {
  return (
    <div
      className={`w-64 h-screen fixed left-0 top-0 p-4 flex flex-col text-white bg-gradient-to-b from-[#39c5bb] via-[#22d3ee] to-[#ec4899] shadow-2xl z-50 transition-transform duration-300 md:translate-x-0 ${open ? 'translate-x-0' : '-translate-x-full'}`}
    >
      <div className="flex items-center gap-3 mb-8 px-2 pt-2">
        <img
          src="/miku.svg"
          alt="Miku"
          className="w-12 h-12 rounded-full ring-2 ring-white/70 object-cover bg-white/30 miku-float"
        />
        <div className="flex-1">
          <h1 className="text-lg font-bold leading-tight font-miku">Miku Beam</h1>
          <p className="text-xs text-white/85 -mt-0.5 flex items-center gap-1">
            Sentinel <Sparkles className="w-3 h-3 miku-sparkle" />
          </p>
        </div>
        {/* Close button (mobile only) */}
        <button onClick={onClose} className="md:hidden text-white/90 hover:text-white" aria-label="Close menu">
          <X className="w-6 h-6" />
        </button>
      </div>
      <nav className="space-y-1.5 flex-1">
        <NavItem to="/" icon={LayoutDashboard} label="Dashboard" onClick={onClose} />
        <NavItem to="/scans/new" icon={Plus} label="New Scan" onClick={onClose} />
        <NavItem to="/projects" icon={Activity} label="Projects" onClick={onClose} />
        <NavItem to="/reports" icon={FileText} label="Reports" onClick={onClose} />
      </nav>
      <div className="text-center text-xs text-white/85 pb-2">made with 💖 &amp; Miku</div>
    </div>
  );
};

const Dashboard = () => (
  <div className="p-4 md:p-8 max-w-6xl mx-auto">
    {/* Hero */}
    <div className="relative overflow-hidden rounded-3xl shadow-xl mb-6 miku-animated-bg text-white p-6 md:p-8">
      <div className="relative z-10 md:max-w-[68%]">
        <div className="flex items-center gap-3 mb-2">
          <Shield className="w-9 h-9 md:w-10 md:h-10 drop-shadow" />
          <h1 className="text-3xl md:text-4xl font-bold font-miku drop-shadow">Miku Beam Sentinel</h1>
        </div>
        <p className="text-base md:text-lg text-white/95 mb-1">Professional API Security Scanner &amp; Vulnerability Assessment Platform ✨</p>
        <p className="text-xs text-white/80">Version 1.0 | Maintainer: MathQnADEV · based on Cerberus API Sentinel by Sudeepa Wanigarathna (MIT)</p>
      </div>
      <img
        src="/miku.gif"
        alt="Miku"
        className="hidden md:block absolute right-5 -bottom-1 h-44 rounded-2xl object-cover shadow-lg ring-2 ring-white/40 miku-float"
      />
    </div>

    {/* About */}
    <div className="miku-card p-5 md:p-6 mb-6">
      <h2 className="text-2xl font-bold mb-4 miku-gradient-text inline-block">About This Tool</h2>
      <p className="text-gray-700 leading-relaxed">
        Miku Beam Sentinel is a comprehensive offensive security tool designed for professional API penetration testing
        and vulnerability assessment. It provides automated scanning capabilities to identify security weaknesses in RESTful APIs,
        helping security professionals and developers ensure their applications are protected against common and advanced attack vectors.
      </p>
    </div>

    {/* Capabilities */}
    <div className="miku-card p-5 md:p-6 mb-6">
      <h2 className="text-2xl font-bold mb-4 text-gray-800 flex items-center gap-2">
        <Shield className="w-6 h-6 text-pink-500" />
        Vulnerability Detection Capabilities
      </h2>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {[
          'SQL Injection (SQLi)',
          'Cross-Site Scripting (XSS)',
          'Command Injection',
          'BOLA/IDOR',
          'Server-Side Request Forgery (SSRF)',
          'XML External Entity (XXE)',
          'Broken Authentication',
          'Broken Access Control',
          'Security Misconfiguration',
          'Sensitive Data Exposure',
          'XML Injection',
          'LDAP Injection',
          'XPath Injection',
          'HTTP Parameter Pollution',
          'Server-Side Template Injection (SSTI)',
          'JWT Vulnerabilities',
          'OAuth Misconfigurations',
          'API Rate Limiting Issues',
          'Insecure Direct Object References',
          'Mass Assignment',
          'GraphQL Injection',
          'NoSQL Injection',
          'Business Logic Flaws',
          'Insufficient Logging & Monitoring'
        ].map((vuln, idx) => (
          <div key={idx} className="flex items-start gap-2 p-3 bg-white/70 rounded-xl border border-pink-100">
            <span className="text-teal-500 font-bold">✓</span>
            <span className="text-sm text-gray-700">{vuln}</span>
          </div>
        ))}
      </div>
    </div>

    {/* Features + Use Cases */}
    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
      <div className="miku-card p-5 md:p-6">
        <h3 className="text-xl font-bold mb-4 text-gray-800">Key Features</h3>
        <ul className="space-y-2 text-gray-700">
          {['Automated vulnerability scanning', 'Project-based organization', 'Detailed vulnerability reports', 'RESTful API integration', 'Multiple authentication methods'].map((f, i) => (
            <li key={i} className="flex items-start gap-2">
              <span className="text-pink-500">♪</span>
              <span>{f}</span>
            </li>
          ))}
        </ul>
      </div>

      <div className="miku-card p-5 md:p-6">
        <h3 className="text-xl font-bold mb-4 text-gray-800">Use Cases</h3>
        <ul className="space-y-2 text-gray-700">
          {['Security assessments & audits', 'Penetration testing engagements', 'Continuous security monitoring', 'DevSecOps integration', 'Compliance verification'].map((u, i) => (
            <li key={i} className="flex items-start gap-2">
              <span className="text-teal-500">♪</span>
              <span>{u}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  </div>
);

function App() {
  const [open, setOpen] = useState(false);
  return (
    <Router>
      <div className="min-h-screen">
        {/* Mobile top bar */}
        <div className="md:hidden fixed top-0 inset-x-0 z-40 flex items-center gap-3 px-4 py-3 bg-gradient-to-r from-[#39c5bb] to-[#ec4899] text-white shadow-lg">
          <button onClick={() => setOpen(true)} aria-label="Open menu">
            <Menu className="w-6 h-6" />
          </button>
          <img src="/miku.svg" alt="Miku" className="w-8 h-8 rounded-full ring-2 ring-white/70 bg-white/30 object-cover" />
          <span className="font-bold font-miku">Miku Beam Sentinel</span>
        </div>

        {/* Backdrop (mobile drawer) */}
        {open && (
          <div className="md:hidden fixed inset-0 bg-black/40 z-40" onClick={() => setOpen(false)} />
        )}

        <Sidebar open={open} onClose={() => setOpen(false)} />

        <main className="md:ml-64 pt-16 md:pt-0">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/new-scan" element={<ScanConfig />} />
            <Route path="/scans/new" element={<ScanConfig />} />
            <Route path="/projects" element={<Projects />} />
            <Route path="/projects/:id" element={<ProjectDetail />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/reports/:id" element={<ReportDetail />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;
