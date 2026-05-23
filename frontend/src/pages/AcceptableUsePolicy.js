import React from 'react';
import { Link } from 'react-router-dom';
import { FiArrowLeft, FiShield } from 'react-icons/fi';

const AcceptableUsePolicy = () => {
  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-900 via-gray-800 to-gray-900">
      {/* Header */}
      <div className="bg-gray-900 border-b border-gray-800">
        <div className="max-w-4xl mx-auto px-4 py-6">
          <Link
            to="/"
            className="inline-flex items-center gap-2 text-primary hover:text-primary-600 transition mb-4"
          >
            <FiArrowLeft />
            Back to Home
          </Link>
          <div className="flex items-center gap-3">
            <FiShield className="text-primary text-3xl" />
            <h1 className="text-3xl font-bold text-white">Acceptable Use Policy (AUP)</h1>
          </div>
          <p className="text-gray-400 mt-2">Last Updated: January 23, 2026</p>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-4xl mx-auto px-4 py-12">
        <div className="ui-card ui-card-lg p-8 ui-prose prose-lg">
          <p>
            This Acceptable Use Policy ("AUP") explains what is allowed and what is prohibited when using
            BugBounty Arsenal (the "Service"). This AUP is part of our{' '}
            <Link to="/terms" className="text-primary hover:underline">Terms of Service</Link>.
          </p>

          <h2>1. You Must Have Authorization</h2>
          <p>
            You may use the Service only on targets that you own or for which you have explicit written
            authorization, including valid bug bounty scope and rules.
          </p>

          <h2>2. Allowed Uses</h2>
          <ul>
            <li>Testing systems you own</li>
            <li>Testing systems where you have explicit written permission (contract / scope / ticket)</li>
            <li>Participating in authorized bug bounty programs within scope</li>
            <li>Training and education in controlled lab environments</li>
          </ul>

          <h2>3. Prohibited Uses</h2>
          <p>
            You must not use the Service to:
          </p>
          <ul>
            <li>Scan, probe, or attack any target without authorization</li>
            <li>Perform denial-of-service (DoS) activity or intentionally disrupt availability</li>
            <li>Conduct credential stuffing, password spraying, or brute force attacks against third parties</li>
            <li>Exfiltrate data or attempt to access non-public information without explicit permission</li>
            <li>Scan critical infrastructure, government, healthcare, financial systems, or other high-risk targets without explicit written scope</li>
            <li>Bypass or attempt to bypass safety controls, throttles, or plan restrictions</li>
            <li>Use the Service as a proxy for SSRF, port scanning, or internal network discovery</li>
            <li>Upload or run malware, exploit code intended to cause harm, or destructive payloads outside permitted scope</li>
          </ul>

          <h2>4. Plan Restrictions and Scan Profiles</h2>
          <p>
            Some scan profiles and detectors are considered high-impact ("Aggressive"). These may include
            high concurrency scanning, brute force, fuzzing, destructive checks, or other intrusive techniques.
          </p>
          <ul>
            <li>Non-Enterprise plans are limited to low-impact scanning.</li>
            <li>Aggressive scanning is available only for verified Enterprise customers and approved scope.</li>
          </ul>

          <h2>5. Enforcement</h2>
          <p>
            We may throttle, block, cancel scans, suspend accounts, or restrict features at any time to prevent
            abuse, protect infrastructure, or respond to complaints.
          </p>

          <h2>6. Logging and Investigations</h2>
          <p>
            We maintain security logs and audit metadata (e.g., account identifiers, timestamps, scan settings)
            to operate the Service, prevent abuse, and investigate incidents. We may preserve relevant logs to
            comply with legal obligations.
          </p>

          <h2>7. Reporting Abuse</h2>
          <p>
            If you believe the Service was used to scan your systems without authorization, contact us with as
            much detail as possible (target, timestamps, request logs):{' '}
            <a href="mailto:abuse@bugbounty-arsenal.com" className="text-primary hover:underline">abuse@bugbounty-arsenal.com</a>.
          </p>

          <h2>8. Relationship to Other Policies</h2>
          <p>
            This AUP works together with our{' '}
            <Link to="/terms" className="text-primary hover:underline">Terms</Link>,{' '}
            <Link to="/privacy" className="text-primary hover:underline">Privacy Policy</Link>, and{' '}
            <Link to="/disclaimer" className="text-primary hover:underline">Disclaimer</Link>.
          </p>

          <div className="bg-gray-100 border-l-4 border-gray-400 p-4 my-6">
            <p className="text-sm text-gray-700">
              <strong>Version:</strong> 1.0<br />
              <strong>Effective Date:</strong> January 23, 2026<br />
              <strong>Last Revision:</strong> January 23, 2026
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AcceptableUsePolicy;
