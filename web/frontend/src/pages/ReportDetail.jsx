import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ArrowLeft, AlertTriangle, Shield, CheckCircle, Download } from 'lucide-react';
import { scansAPI } from '../services/api';

// --- CVSS v3.1 qualitative severity rating scale ------------------------------
// The scan engine only stores a qualitative severity (CRITICAL/HIGH/MEDIUM/LOW),
// so scores/vectors below are representative values mapped from that rating.
const SEVERITY_META = {
    CRITICAL: { label: 'Critical', badge: 'bg-red-100 text-red-800', bar: 'bg-red-600', band: '9.0 – 10.0', score: '9.8', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
    HIGH: { label: 'High', badge: 'bg-orange-100 text-orange-800', bar: 'bg-orange-500', band: '7.0 – 8.9', score: '7.5', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' },
    MEDIUM: { label: 'Medium', badge: 'bg-yellow-100 text-yellow-800', bar: 'bg-yellow-500', band: '4.0 – 6.9', score: '5.3', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N' },
    LOW: { label: 'Low', badge: 'bg-green-100 text-green-800', bar: 'bg-green-600', band: '0.1 – 3.9', score: '3.1', vector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N' },
    INFO: { label: 'Info', badge: 'bg-blue-100 text-blue-800', bar: 'bg-blue-500', band: '0.0', score: '0.0', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N' },
};
const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const metaFor = (sev) => SEVERITY_META[String(sev || '').toUpperCase()] || SEVERITY_META.INFO;

const REMEDIATION = [
    [/command injection/i, 'Never pass user-controlled data to OS/shell commands. Use safe, parameterised APIs, avoid shell execution, enforce strict allow-lists, and run with least privilege.'],
    [/sql injection/i, 'Use parameterised queries / prepared statements (or an ORM). Never concatenate user input into SQL, and use least-privilege database accounts.'],
    [/(xss|cross-site scripting)/i, 'Apply context-aware output encoding, a strict Content-Security-Policy, and input validation. Prefer frameworks that auto-escape output.'],
    [/(template injection|ssti)/i, 'Do not render user input as template source. Use logic-less or sandboxed templates and pass user data only as bound variables.'],
    [/security header/i, 'Add the missing hardening headers: Content-Security-Policy, X-Frame-Options (or CSP frame-ancestors), X-Content-Type-Options: nosniff, Strict-Transport-Security, and Referrer-Policy.'],
    [/(ssrf|request forgery)/i, 'Validate and allow-list outbound destinations, block internal/link-local and cloud-metadata ranges, and disable unused URL schemes.'],
    [/(idor|bola|access control)/i, 'Enforce server-side object-level authorization on every request; never trust client-supplied identifiers.'],
    [/jwt/i, 'Verify token signature and algorithm (reject "none"), validate exp/aud/iss claims, and rotate signing keys.'],
];
const getRemediation = (name) => {
    const hit = REMEDIATION.find(([re]) => re.test(name || ''));
    return hit ? hit[1] : 'Validate the finding and remediate following OWASP guidance for this vulnerability class, applying defence-in-depth controls.';
};

const PRINT_CSS = `
@media print {
  @page { margin: 14mm; }
  body { background: #ffffff !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  body * { visibility: hidden; }
  .report-print-root, .report-print-root * { visibility: visible; }
  .report-print-root { position: absolute; left: 0; top: 0; width: 100%; margin: 0 !important; padding: 0 !important; max-width: none !important; }
  .no-print { display: none !important; }
  .finding-card, .report-section { break-inside: avoid; page-break-inside: avoid; }
}`;

const ReportDetail = () => {
    const { id } = useParams();
    const [scan, setScan] = useState(null);
    const [vulnerabilities, setVulnerabilities] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const scanResponse = await scansAPI.get(id);
                setScan(scanResponse.data);
                const vulnResponse = await scansAPI.getVulnerabilities(id);
                const vData = vulnResponse.data;
                setVulnerabilities(Array.isArray(vData) ? vData : (vData?.results || []));
            } catch (error) {
                console.error('Failed to fetch scan/vulnerabilities:', error);
            } finally {
                setLoading(false);
            }
        };
        fetchData();
    }, [id]);

    const handleExportPDF = () => window.print();

    if (loading) return <div className="p-8">Loading report...</div>;
    if (!scan) return <div className="p-8">Report not found.</div>;

    const recon = scan.results?.reconnaissance || {};
    const targetUrl = scan.results?.target_url || '—';

    // Severity roll-up
    const counts = SEV_ORDER.reduce((acc, s) => ({ ...acc, [s]: 0 }), {});
    vulnerabilities.forEach((v) => {
        const k = String(v.severity || '').toUpperCase();
        if (k in counts) counts[k] += 1; else counts.INFO += 1;
    });
    const total = vulnerabilities.length;
    const overall = SEV_ORDER.find((s) => counts[s] > 0) || 'INFO';
    const sorted = [...vulnerabilities].sort(
        (a, b) => SEV_ORDER.indexOf(String(a.severity || 'INFO').toUpperCase()) - SEV_ORDER.indexOf(String(b.severity || 'INFO').toUpperCase())
    );

    return (
        <div className="report-print-root p-4 md:p-8 max-w-5xl mx-auto">
            <style>{PRINT_CSS}</style>

            <Link to="/reports" className="no-print flex items-center text-gray-500 hover:text-gray-700 mb-6">
                <ArrowLeft className="w-4 h-4 mr-2" /> Back to Reports
            </Link>

            {/* Report header */}
            <div className="report-section bg-white p-8 rounded-lg shadow-md border border-gray-200 mb-6">
                <div className="flex flex-wrap justify-between items-start gap-4">
                    <div className="flex items-start gap-3">
                        <Shield className="w-10 h-10 text-pink-500 shrink-0" />
                        <div>
                            <h1 className="text-2xl font-bold text-gray-900 leading-tight">API Security Assessment Report</h1>
                            <p className="text-gray-500 mt-1">Miku Beam Sentinel · CVSS v3.1</p>
                        </div>
                    </div>
                    <div className="flex items-center gap-3">
                        <button onClick={handleExportPDF} className="no-print flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-pink-500 to-cyan-500 text-white rounded-xl font-semibold shadow-md hover:from-pink-600 hover:to-cyan-600 transition-all">
                            <Download className="w-4 h-4" /> Export PDF
                        </button>
                        <span className={`px-4 py-2 rounded-full font-bold text-sm ${scan.status === 'COMPLETED' ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'}`}>
                            {scan.status}
                        </span>
                    </div>
                </div>
                <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-2 mt-6 text-sm">
                    <div className="flex justify-between border-b border-gray-100 py-1"><dt className="text-gray-500">Target</dt><dd className="font-medium text-gray-900 break-all text-right">{targetUrl}</dd></div>
                    <div className="flex justify-between border-b border-gray-100 py-1"><dt className="text-gray-500">Scan ID</dt><dd className="font-mono text-gray-700 text-xs text-right">{scan.id}</dd></div>
                    <div className="flex justify-between border-b border-gray-100 py-1"><dt className="text-gray-500">Started</dt><dd className="font-medium text-gray-900 text-right">{new Date(scan.started_at || Date.now()).toLocaleString()}</dd></div>
                    <div className="flex justify-between border-b border-gray-100 py-1"><dt className="text-gray-500">Completed</dt><dd className="font-medium text-gray-900 text-right">{scan.completed_at ? new Date(scan.completed_at).toLocaleString() : 'N/A'}</dd></div>
                </dl>
            </div>

            {/* Executive summary */}
            <div className="report-section bg-white p-6 rounded-lg shadow-md border border-gray-200 mb-6">
                <div className="flex items-center justify-between mb-4">
                    <h2 className="text-xl font-bold text-gray-800">Executive Summary</h2>
                    <div className="flex items-center gap-2 text-sm">
                        <span className="text-gray-500">Overall risk</span>
                        <span className={`px-2 py-1 rounded font-bold uppercase text-xs ${metaFor(overall).badge}`}>{metaFor(overall).label}</span>
                    </div>
                </div>
                <p className="text-gray-600 text-sm mb-5">
                    The assessment of <span className="font-medium">{targetUrl}</span> identified <span className="font-bold">{total}</span> finding{total === 1 ? '' : 's'}.
                    Severity is rated using the CVSS v3.1 qualitative scale; each finding below lists its representative CVSS base score and vector.
                </p>

                {/* Severity distribution tiles */}
                <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-4">
                    {SEV_ORDER.map((s) => (
                        <div key={s} className="border border-gray-200 rounded-lg p-3 text-center">
                            <div className="text-2xl font-bold text-gray-900">{counts[s]}</div>
                            <div className={`mt-1 inline-block px-2 py-0.5 rounded text-xs font-semibold uppercase ${metaFor(s).badge}`}>{metaFor(s).label}</div>
                        </div>
                    ))}
                </div>

                {/* Distribution bar */}
                {total > 0 && (
                    <div className="flex h-3 w-full rounded-full overflow-hidden">
                        {SEV_ORDER.filter((s) => counts[s] > 0).map((s) => (
                            <div key={s} className={metaFor(s).bar} style={{ width: `${(counts[s] / total) * 100}%` }} title={`${metaFor(s).label}: ${counts[s]}`} />
                        ))}
                    </div>
                )}
            </div>

            {/* CVSS legend */}
            <div className="report-section bg-gray-50 p-4 rounded-lg border border-gray-200 mb-8 text-xs text-gray-600">
                <span className="font-semibold text-gray-700">CVSS v3.1 severity bands: </span>
                {SEV_ORDER.map((s, i) => (
                    <span key={s}>
                        <span className={`px-1.5 py-0.5 rounded font-semibold ${metaFor(s).badge}`}>{metaFor(s).label}</span> {metaFor(s).band}{i < SEV_ORDER.length - 1 ? '  ·  ' : ''}
                    </span>
                ))}
                <p className="mt-2 italic">Scores are derived from the qualitative severity; vectors are representative for the vulnerability class.</p>
            </div>

            {/* Findings */}
            <h2 className="text-xl font-bold text-gray-800 flex items-center gap-2 mb-4">
                <AlertTriangle className="w-5 h-5 text-red-500" /> Findings ({total})
            </h2>

            {total === 0 ? (
                <div className="bg-green-50 p-6 rounded-lg border border-green-200 text-green-700 flex items-center gap-3">
                    <CheckCircle className="w-6 h-6" /> No vulnerabilities detected. Good job!
                </div>
            ) : (
                <div className="space-y-5">
                    {sorted.map((vuln, index) => {
                        const m = metaFor(vuln.severity);
                        return (
                            <div key={vuln.id || index} className="finding-card bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
                                <div className="flex justify-between items-start gap-3 p-5 border-b border-gray-100">
                                    <h3 className="text-lg font-bold text-gray-900">
                                        <span className="text-gray-400 mr-2">#{index + 1}</span>{vuln.name}
                                    </h3>
                                    <div className="text-right shrink-0">
                                        <span className={`inline-block px-2 py-1 rounded text-xs font-bold uppercase ${m.badge}`}>{m.label}</span>
                                        <div className="text-sm font-bold text-gray-900 mt-1">CVSS {m.score}</div>
                                    </div>
                                </div>
                                <div className="p-5 space-y-4">
                                    <p className="text-gray-700">{vuln.description}</p>

                                    <div className="text-xs font-mono text-gray-500 bg-gray-50 border border-gray-200 rounded px-3 py-2 overflow-x-auto">
                                        {m.vector}
                                    </div>

                                    <div>
                                        <div className="text-xs text-gray-500 uppercase font-semibold mb-1">Evidence</div>
                                        <div className="bg-gray-900 text-gray-100 p-4 rounded text-xs font-mono whitespace-pre-wrap break-words overflow-x-auto">
                                            {vuln.evidence}
                                        </div>
                                    </div>

                                    <div className="bg-blue-50 border border-blue-200 rounded p-4">
                                        <div className="text-xs text-blue-800 uppercase font-semibold mb-1">Remediation</div>
                                        <p className="text-sm text-blue-900">{getRemediation(vuln.name)}</p>
                                    </div>
                                </div>
                            </div>
                        );
                    })}
                </div>
            )}

            {/* Reconnaissance data */}
            {scan.status === 'COMPLETED' && scan.results?.reconnaissance && (
                <div className="report-section mt-10">
                    <h2 className="text-xl font-bold text-gray-800 mb-4">Reconnaissance Data</h2>
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                        {/* Directories */}
                        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                            <h4 className="font-semibold text-blue-900 mb-2 text-sm">📁 Directories ({(recon.directories || []).length})</h4>
                            <div className="max-h-40 overflow-y-auto space-y-1">
                                {(recon.directories || []).map((dir, idx) => (
                                    <div key={idx} className="text-xs font-mono bg-white px-2 py-1 rounded text-gray-700 flex justify-between gap-2">
                                        <span className="truncate">{typeof dir === 'string' ? dir : (dir.path || dir.url)}</span>
                                        {typeof dir === 'object' && dir?.status != null && <span className="shrink-0 text-gray-500">{dir.status}</span>}
                                    </div>
                                ))}
                            </div>
                        </div>
                        {/* Subdomains */}
                        <div className="bg-purple-50 border border-purple-200 rounded-lg p-4">
                            <h4 className="font-semibold text-purple-900 mb-2 text-sm">🌐 Subdomains ({(recon.subdomains || []).length})</h4>
                            <div className="max-h-40 overflow-y-auto space-y-1">
                                {(recon.subdomains || []).map((sub, idx) => (
                                    <div key={idx} className="text-xs font-mono bg-white px-2 py-1 rounded text-gray-700">{sub}</div>
                                ))}
                            </div>
                        </div>
                        {/* Open Ports */}
                        <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                            <h4 className="font-semibold text-green-900 mb-2 text-sm">🔓 Open Ports ({(recon.open_ports || []).length})</h4>
                            <div className="max-h-40 overflow-y-auto space-y-1">
                                {(recon.open_ports || []).map((port, idx) => (
                                    <div key={idx} className="text-xs bg-white px-2 py-1 rounded flex justify-between">
                                        <span className="font-mono text-gray-700">Port {port.port}</span>
                                        <span className="text-gray-600">{port.service}</span>
                                        <span className={`font-semibold ${port.state === 'open' ? 'text-green-600' : port.state === 'filtered' ? 'text-yellow-600' : 'text-gray-500'}`}>{port.state}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                        {/* Tech Stack */}
                        {(() => {
                            const tech = recon.technologies || recon.tech_stack || {};
                            const langs = Array.isArray(tech.languages) ? tech.languages.join(', ') : (tech.languages || '');
                            return (
                                <div className="bg-orange-50 border border-orange-200 rounded-lg p-4">
                                    <h4 className="font-semibold text-orange-900 mb-2 text-sm">⚙️ Tech Stack</h4>
                                    <div className="max-h-40 overflow-y-auto space-y-1 text-xs">
                                        <div className="bg-white px-2 py-1 rounded"><span className="font-semibold text-gray-700">Server:</span> {tech.server || 'N/A'}</div>
                                        <div className="bg-white px-2 py-1 rounded"><span className="font-semibold text-gray-700">Backend:</span> {tech.backend || 'N/A'}</div>
                                        <div className="bg-white px-2 py-1 rounded"><span className="font-semibold text-gray-700">Frontend:</span> {tech.frontend || 'N/A'}</div>
                                        <div className="bg-white px-2 py-1 rounded"><span className="font-semibold text-gray-700">Database:</span> {tech.database || 'N/A'}</div>
                                        <div className="bg-white px-2 py-1 rounded"><span className="font-semibold text-gray-700">Languages:</span> {langs || 'N/A'}</div>
                                    </div>
                                </div>
                            );
                        })()}
                    </div>
                </div>
            )}

            {/* Print footer note */}
            <p className="text-center text-xs text-gray-400 mt-10">
                Generated by Miku Beam Sentinel · For authorised security testing only.
            </p>
        </div>
    );
};

export default ReportDetail;
