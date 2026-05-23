import React from 'react';
import { Link } from 'react-router-dom';
import { FiShield, FiZap, FiTarget, FiLock, FiCheck, FiCode, FiActivity, FiTrendingUp, FiCpu, FiUsers, FiHeart, FiTerminal } from 'react-icons/fi';

const LandingPage = () => {
  const donateUrl = process.env.REACT_APP_DONATE_URL;

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-900 via-gray-800 to-gray-900">
      {/* Header/Nav */}
      <nav className="container mx-auto px-6 py-4">
        <div className="flex justify-between items-center">
          <div className="text-2xl font-bold text-white flex items-center gap-2">
            <FiShield className="text-primary" />
            BugBounty Arsenal
          </div>
          <div className="flex gap-4">
            <Link to="/login" className="px-6 py-2 text-white hover:text-primary transition">
              Login
            </Link>
            <Link
              to="/register"
              className="px-6 py-2 bg-primary text-white rounded-lg hover:bg-primary-600 transition"
            >
              Get Started
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="container mx-auto px-6 py-20 text-center">
        <h1 className="text-5xl md:text-6xl font-bold text-white mb-6">
          Professional <span className="text-primary">Security Testing</span> Platform
        </h1>
        <p className="text-xl text-gray-300 mb-8 max-w-3xl mx-auto">
          Comprehensive security scanning with 50+ detectors across 10 specialized categories.
          Real-time vulnerability detection. Async scanning with live progress. 100% transparent results.
        </p>
        <div className="flex gap-4 justify-center flex-wrap">
          <Link
            to="/register"
            className="px-8 py-4 bg-primary text-white rounded-lg text-lg font-semibold hover:bg-primary-600 transition flex items-center gap-2"
          >
            <FiZap /> Create Free Account
          </Link>
          {donateUrl && (
            <a
              href={donateUrl}
              target="_blank"
              rel="noreferrer"
              className="px-8 py-4 border-2 border-pink-500 text-pink-300 rounded-lg text-lg font-semibold hover:bg-pink-500 hover:text-white transition flex items-center gap-2"
            >
              <FiHeart /> Donate
            </a>
          )}
          <a
            href="#features"
            className="px-8 py-4 border-2 border-primary text-primary rounded-lg text-lg font-semibold hover:bg-primary hover:text-white transition"
          >
            Learn More
          </a>
        </div>
        
        {/* Stats */}
        <div className="grid grid-cols-4 gap-8 mt-16 max-w-4xl mx-auto">
          <div className="text-center">
            <div className="text-4xl font-bold text-primary">50+</div>
            <div className="text-gray-400 mt-2">Security Detectors</div>
          </div>
          <div className="text-center">
            <div className="text-4xl font-bold text-primary">10</div>
            <div className="text-gray-400 mt-2">Scan Categories</div>
          </div>
          <div className="text-center">
            <div className="text-4xl font-bold text-primary">24/7</div>
            <div className="text-gray-400 mt-2">Availability</div>
          </div>
          <div className="text-center">
            <div className="text-4xl font-bold text-primary">100%</div>
            <div className="text-gray-400 mt-2">Real Scanning</div>
          </div>
        </div>
      </section>

      {/* Live Demo */}
      <DemoSection />

      {/* Features Section */}
      <section id="features" className="bg-gray-800 py-20">
        <div className="container mx-auto px-6">
          <h2 className="text-4xl font-bold text-white text-center mb-4">
            Complete Security Testing Platform
          </h2>
          <p className="text-center text-gray-400 mb-12 max-w-3xl mx-auto">
            BugBounty Arsenal provides comprehensive security testing across 10 specialized categories
            with 50+ advanced detectors. From reconnaissance to advanced injection and SSRF techniques.
          </p>
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
            <FeatureCard
              icon={<FiTarget />}
              title="Reconnaissance Scan"
              items={[
                'Subdomain Takeover Detection',
                'Directory Listing Discovery',
                'Security Headers Analysis',
                'Secret & API Key Detection',
                'CORS Misconfiguration',
                'GraphQL Endpoint Discovery',
              ]}
            />
            <FeatureCard
              icon={<FiCode />}
              title="Web Application Scan"
              items={[
                'XSS Detection (All Types)',
                'SQL Injection (Advanced)',
                'LFI/RFI Path Traversal',
                'CSRF Token Bypass',
                'XXE Vulnerability',
                'SSTI Detection',
                'Command Injection',
              ]}
            />
            <FeatureCard
              icon={<FiLock />}
              title="API Security Scan"
              items={[
                'JWT Security Testing',
                'OAuth 2.0 Flow Analysis',
                'Rate Limit Bypass',
                'IDOR Detection',
                'NoSQL Injection',
                'GraphQL Injection',
              ]}
            />
            <FeatureCard
              icon={<FiActivity />}
              title="Vulnerability Assessment"
              items={[
                'SSRF (+ Out-of-Band)',
                'Race Condition Testing',
                'Cache Poisoning',
                'Prototype Pollution',
                'CVE Database Matching',
                'File Upload Vulnerabilities',
              ]}
            />
            <FeatureCard
              icon={<FiShield />}
              title="Mobile Security"
              items={[
                'Android APK Static Analysis',
                'iOS IPA Static Analysis',
                'Dangerous Permissions Detection',
                'Certificate Pinning Absence',
                'Hardcoded Secrets & API Keys',
                'Weak Cryptography (DES, MD5, RC4)',
              ]}
            />
            <FeatureCard
              icon={<FiZap />}
              title="Advanced Scanners (Verified Email)"
              items={[
                'All 50+ Detectors',
                'Nuclei Integration',
                'Custom Payloads',
                'Brute Force Testing',
                'Parameter Fuzzing',
                'Advanced Techniques',
              ]}
            />
          </div>
        </div>
      </section>

      {/* Platform Capabilities */}
      <section className="py-20">
        <div className="container mx-auto px-6">
          <h2 className="text-4xl font-bold text-white text-center mb-12">
            Why Choose BugBounty Arsenal
          </h2>
          <div className="grid md:grid-cols-3 gap-8 max-w-5xl mx-auto">
            <div className="bg-gray-800/50 backdrop-blur-lg border border-gray-700/50 p-6 rounded-xl">
              <div className="text-3xl mb-4 text-primary"><FiTrendingUp /></div>
              <h3 className="text-xl font-bold text-white mb-3">Async Scanning</h3>
              <p className="text-gray-400">
                Scans run asynchronously via Celery workers with real-time
                progress updates. Start a scan and track it live in the dashboard.
              </p>
            </div>
            <div className="bg-gray-800/50 backdrop-blur-lg border border-gray-700/50 p-6 rounded-xl">
              <div className="text-3xl mb-4 text-primary"><FiActivity /></div>
              <h3 className="text-xl font-bold text-white mb-3">Detailed Reports</h3>
              <p className="text-gray-400">
                Export comprehensive reports in HTML, PDF, JSON, or CSV formats.
                Full evidence including HTTP requests, responses, and detector output.
              </p>
            </div>
            <div className="bg-gray-800/50 backdrop-blur-lg border border-gray-700/50 p-6 rounded-xl">
              <div className="text-3xl mb-4 text-primary"><FiCpu /></div>
              <h3 className="text-xl font-bold text-white mb-3">REST API Access</h3>
              <p className="text-gray-400">
                Integrate scanning into your CI/CD pipeline.
                Full REST API with token authentication and structured JSON results.
              </p>
            </div>
            <div className="bg-gray-800/50 backdrop-blur-lg border border-gray-700/50 p-6 rounded-xl">
              <div className="text-3xl mb-4 text-primary"><FiUsers /></div>
              <h3 className="text-xl font-bold text-white mb-3">Team Collaboration</h3>
              <p className="text-gray-400">
                Share scans with your team members.
                Role-based access control with team admin and member roles.
              </p>
            </div>
            <div className="bg-gray-800/50 backdrop-blur-lg border border-gray-700/50 p-6 rounded-xl">
              <div className="text-3xl mb-4 text-primary"><FiZap /></div>
              <h3 className="text-xl font-bold text-white mb-3">High Performance</h3>
              <p className="text-gray-400">
                Concurrent scanning with intelligent rate limiting.
                Up to 10 parallel scans for Enterprise users.
              </p>
            </div>
            <div className="bg-gray-800/50 backdrop-blur-lg border border-gray-700/50 p-6 rounded-xl">
              <div className="text-3xl mb-4 text-primary"><FiShield /></div>
              <h3 className="text-xl font-bold text-white mb-3">Open Source</h3>
              <p className="text-gray-400">
                Fully open-source on GitHub. Inspect every detector, contribute
                improvements, or self-host on your own infrastructure.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Open Source + Donate */}
      <section id="donate" className="bg-gray-800 py-20">
        <div className="container mx-auto px-6 max-w-5xl">
          <h2 className="text-4xl font-bold text-white text-center mb-4">
            Open-source, community supported
          </h2>
          <p className="text-center text-gray-300 mb-10">
            BugBounty Arsenal is being transitioned to a fully free platform. To reduce abuse,
            dangerous scanners require an account with a verified email. To save scan reports,
            users must register.
          </p>
          {donateUrl ? (
            <div className="flex justify-center">
              <a
                href={donateUrl}
                target="_blank"
                rel="noreferrer"
                className="px-10 py-4 bg-pink-500 text-white rounded-lg text-lg font-semibold hover:bg-pink-600 transition inline-flex items-center gap-2"
              >
                <FiHeart /> Donate with PayPal
              </a>
            </div>
          ) : null}
        </div>
      </section>

      {/* Security & Privacy */}
      <section className="bg-gray-800 py-20">
        <div className="container mx-auto px-6">
          <h2 className="text-4xl font-bold text-white text-center mb-12">
            Security & Privacy First
          </h2>
          <div className="grid md:grid-cols-2 gap-8 max-w-4xl mx-auto">
            <div className="bg-gray-900 p-6 rounded-lg">
              <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                <FiShield className="text-primary" /> Data Protection
              </h3>
              <ul className="text-gray-300 space-y-2">
                <li>• HTTPS everywhere</li>
                <li>• Scan results stored per-user only</li>
                <li>• No third-party data sharing</li>
                <li>• Open-source — auditable code</li>
                <li>• Responsible disclosure policy</li>
              </ul>
            </div>
            <div className="bg-gray-900 p-6 rounded-lg">
              <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                <FiLock className="text-primary" /> Responsible Scanning
              </h3>
              <ul className="text-gray-300 space-y-2">
                <li>• Rate limiting to prevent service disruption</li>
                <li>• Non-destructive testing only</li>
                <li>• Rate limiting per target</li>
                <li>• Scope validation</li>
                <li>• Legal compliance checks</li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* Legacy billing widgets removed from the open-source release */}
    </div>
  );
};

const FeatureCard = ({ icon, title, items }) => (
  <div className="bg-gray-900/50 backdrop-blur-lg border border-gray-700/50 p-6 rounded-xl hover:bg-gray-800/50 hover:border-gray-600/50 hover:shadow-xl transition-all duration-300 cursor-pointer">
    <div className="text-3xl text-primary mb-4">{icon}</div>
    <h3 className="text-xl font-bold text-white mb-4">{title}</h3>
    <ul className="text-gray-400 space-y-2 text-sm">
      {items.map((item, i) => (
        <li key={i} className="flex items-start gap-2">
          <FiCheck className="text-primary mt-1 flex-shrink-0" />
          {item}
        </li>
      ))}
    </ul>
  </div>
);

/* ─── Demo Section ─────────────────────────────────────────────────────────── */

const SEV = {
  critical: { badge: 'bg-red-500/20 text-red-400 border border-red-500/40', dot: 'bg-red-500', card: 'border-red-500/20' },
  high: { badge: 'bg-orange-500/20 text-orange-400 border border-orange-500/40', dot: 'bg-orange-500', card: 'border-orange-500/20' },
  medium: { badge: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/40', dot: 'bg-yellow-400', card: 'border-yellow-500/20' },
  low: { badge: 'bg-blue-500/20 text-blue-400 border border-blue-500/40', dot: 'bg-blue-400', card: 'border-blue-500/20' },
  info: { badge: 'bg-gray-500/20 text-gray-400 border border-gray-500/40', dot: 'bg-gray-400', card: 'border-gray-500/20' },
};

const SevBadge = ({ sev }) => {
  const s = SEV[sev] || SEV.info;
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-bold ${s.badge}`}>
      {sev.toUpperCase()}
    </span>
  );
};

const DemoSection = () => {
  const [data, setData] = React.useState(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState(null);
  const [visibleCount, setVisibleCount] = React.useState(0);

  const handleScan = () => {
    if (loading || data) return;
    setLoading(true);
    setError(null);
    fetch('/api/demo/scan/')
      .then((r) => r.json())
      .then((json) => { setData(json); setLoading(false); })
      .catch(() => { setError('Could not load scan results. Please try again.'); setLoading(false); });
  };

  // Stagger findings reveal after data arrives
  React.useEffect(() => {
    if (!data) return;
    const vulns = data.vulnerabilities || [];
    if (visibleCount >= vulns.length) return;
    const t = setTimeout(() => setVisibleCount((n) => n + 1), 180);
    return () => clearTimeout(t);
  }, [data, visibleCount]);

  const vulns = data?.vulnerabilities || [];
  const visibleVulns = vulns.slice(0, visibleCount);
  const allVisible = visibleCount >= vulns.length && vulns.length > 0;

  return (
    <section className="py-20 bg-gray-900">
      <div className="container mx-auto px-6">
        <div className="text-center mb-12">
          <h2 className="text-4xl font-bold text-white mb-4 flex items-center justify-center gap-3">
            <FiTerminal className="text-primary" /> Try It Live
          </h2>
          <p className="text-gray-400 max-w-2xl mx-auto">
            Run a real scan against{' '}
            <a href="http://testphp.vulnweb.com" target="_blank" rel="noreferrer" className="text-primary hover:underline">
              testphp.vulnweb.com
            </a>{' '}
            — Acunetix's deliberately vulnerable demo app. Click Scan to see actual results from our engine.
          </p>
        </div>

        <div className="max-w-3xl mx-auto">
          {/* Scan input row */}
          <div className="flex gap-3 mb-8">
            <input
              type="text"
              readOnly
              value="http://testphp.vulnweb.com"
              className="flex-1 bg-gray-950 border border-gray-700 text-gray-300 font-mono text-sm rounded-lg px-4 py-3 cursor-default select-none focus:outline-none"
            />
            <button
              onClick={handleScan}
              disabled={loading || !!data}
              className="px-6 py-3 bg-primary text-white rounded-lg font-semibold hover:bg-primary-600 transition disabled:opacity-60 disabled:cursor-not-allowed flex items-center gap-2 whitespace-nowrap"
            >
              {loading ? (
                <>
                  <span className="inline-block w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  Scanning…
                </>
              ) : data ? (
                <>
                  <FiCheck /> Done
                </>
              ) : (
                <>
                  <FiZap /> Scan
                </>
              )}
            </button>
          </div>

          {/* Error state */}
          {error && !loading && (
            <div className="bg-gray-950 rounded-xl border border-red-500/30 p-6 text-center text-red-400 font-mono text-sm mb-6">
              {error}
            </div>
          )}

          {/* Results */}
          {data && (
            <>
              {/* Scan meta banner */}
              <div className="bg-gray-950 rounded-xl border border-gray-700/50 overflow-hidden mb-5 shadow-2xl">
                <div className="flex items-center gap-2 px-4 py-3 bg-gray-800/70 border-b border-gray-700/40">
                  <div className="w-3 h-3 rounded-full bg-red-500/70" />
                  <div className="w-3 h-3 rounded-full bg-yellow-500/70" />
                  <div className="w-3 h-3 rounded-full bg-green-500/70" />
                  <span className="text-gray-500 text-xs ml-3 font-mono">bugbounty-arsenal — scan report</span>
                  <span className="ml-auto text-xs text-green-400 font-mono font-semibold">● completed</span>
                </div>
                <div className="p-5 font-mono text-sm space-y-1">
                  <div className="text-green-400">$ bugbounty-arsenal scan {data.meta?.target}</div>
                  {data.meta?.scan_date && (
                    <div className="text-gray-500">scan_date: {data.meta.scan_date}</div>
                  )}
                  {data.meta?.duration && (
                    <div className="text-gray-500">duration:  {data.meta.duration}</div>
                  )}
                  <div className="text-gray-300 mt-2">
                    Findings:{' '}
                    {data.summary && Object.entries(data.summary).map(([sev, cnt]) =>
                      cnt > 0 ? (
                        <span key={sev} className={`mr-3 ${SEV[sev]?.badge?.split(' ')[1] || 'text-gray-300'}`}>
                          {sev} ×{cnt}
                        </span>
                      ) : null
                    )}
                  </div>
                  {data.meta?.note && (
                    <div className="text-gray-600 text-xs mt-2 break-words">{data.meta.note}</div>
                  )}
                </div>
              </div>

              {/* Findings */}
              <div className="text-xs text-gray-500 font-mono mb-3 px-1">
                Vulnerabilities — {visibleVulns.length} / {vulns.length}
              </div>
              <div className="space-y-3">
                {visibleVulns.map((f, i) => {
                  const s = SEV[f.severity] || SEV.info;
                  return (
                    <div
                      key={i}
                      style={{ animation: 'demoFadeIn 0.3s ease both' }}
                      className={`bg-gray-800/50 border ${s.card} rounded-lg p-4 flex gap-3 items-start`}
                    >
                      <div className={`w-2.5 h-2.5 rounded-full mt-1.5 flex-shrink-0 ${s.dot}`} />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-3 flex-wrap mb-1">
                          <span className="text-white font-semibold">{f.title}</span>
                          <SevBadge sev={f.severity} />
                          {f.confidence && (
                            <span className="text-xs text-gray-500 font-mono">confidence: {f.confidence}%</span>
                          )}
                        </div>
                        <div className="text-xs text-gray-400 font-mono break-all mb-1">
                          <span className="text-gray-500">{f.detector}</span>
                          {f.url && <span className="text-primary"> · {f.url}</span>}
                        </div>
                        {f.description && (
                          <div className="text-xs text-gray-400 mb-1">{f.description}</div>
                        )}
                        {(f.evidence || f.payload) && (
                          <div className="text-xs text-gray-500 font-mono mt-1 break-words bg-gray-900/50 rounded px-2 py-1">
                            {f.evidence || `payload: ${f.payload}`}
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* CTA */}
              {allVisible && (
                <div className="mt-10 text-center" style={{ animation: 'demoFadeIn 0.5s ease both' }}>
                  <p className="text-gray-400 mb-5 text-lg">Ready to scan your own targets?</p>
                  <Link
                    to="/register"
                    className="inline-flex items-center gap-2 px-8 py-3 bg-primary text-white rounded-lg font-semibold hover:bg-primary-600 transition text-lg"
                  >
                    <FiZap /> Start Free Scan
                  </Link>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </section>
  );
};

export default LandingPage;

