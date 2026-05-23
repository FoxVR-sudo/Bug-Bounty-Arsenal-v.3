import React from 'react';
import { Link } from 'react-router-dom';
import { FiArrowLeft, FiAlertTriangle } from 'react-icons/fi';

const Disclaimer = () => {
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
            <FiAlertTriangle className="text-yellow-500 text-3xl" />
            <h1 className="text-3xl font-bold text-white">Legal Disclaimer</h1>
          </div>
          <p className="text-gray-400 mt-2">Last Updated: January 18, 2026</p>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-4xl mx-auto px-4 py-12">
        <div className="ui-card ui-card-lg p-8 ui-prose prose-lg">
          
          <div className="bg-red-50 border-l-4 border-red-500 p-6 my-6">
            <h2 className="text-red-800 mt-0">⚠️ READ THIS CAREFULLY</h2>
            <p className="text-red-700 font-semibold">
              Unauthorized vulnerability scanning is ILLEGAL and can result in criminal prosecution, 
              imprisonment, and substantial fines. By using this tool, you accept FULL responsibility 
              for your actions.
            </p>
          </div>

          <h2>1. Educational Purpose Only</h2>
          <p>
            BugBounty Arsenal is intended EXCLUSIVELY for:
          </p>
          <ul>
            <li>Security researchers conducting authorized testing</li>
            <li>Ethical hackers with proper permissions</li>
            <li>Penetration testers under contract</li>
            <li>Students learning in controlled lab environments</li>
            <li>Bug bounty program participants</li>
          </ul>

          <h2>2. Legal Prohibition</h2>
          <div className="bg-red-50 border border-red-200 rounded p-4 my-4">
            <h3 className="text-red-800 mt-0">🚨 CRIMINAL OFFENSE</h3>
            <p className="text-red-700">
              Scanning systems without explicit authorization is ILLEGAL under:
            </p>
            <ul className="text-red-700">
              <li><strong>Bulgarian Criminal Code:</strong> Articles 319a-319d (Computer Crimes)</li>
              <li><strong>GDPR:</strong> Unauthorized data processing violations</li>
              <li><strong>US Computer Fraud and Abuse Act (CFAA)</strong></li>
              <li><strong>UK Computer Misuse Act 1990</strong></li>
              <li>Similar laws in virtually all countries worldwide</li>
            </ul>
            <p className="text-red-700 font-semibold mt-4">
              <strong>Penalties may include:</strong>
            </p>
            <ul className="text-red-700">
              <li>Prison sentences up to 6 years or more</li>
              <li>Fines up to 10,000 BGN or more</li>
              <li>Civil lawsuits for damages</li>
              <li>Permanent criminal record</li>
            </ul>
          </div>

          <h2>3. User Responsibility</h2>
          <p>
            <strong>YOU ARE SOLELY RESPONSIBLE FOR:</strong>
          </p>
          <ul>
            <li>Obtaining written authorization before scanning ANY system</li>
            <li>Complying with all applicable laws and regulations</li>
            <li>Understanding and following bug bounty program rules</li>
            <li>Any and all consequences of your scanning activities</li>
            <li>Damages to systems or data</li>
            <li>Legal fees and penalties</li>
          </ul>

          <h2>4. No Warranties</h2>
          <p>
            BugBounty Arsenal is provided "AS IS" without warranties of any kind:
          </p>
          <ul>
            <li><strong>No accuracy guarantee:</strong> Results may include false positives or false negatives</li>
            <li><strong>No completeness guarantee:</strong> Not all vulnerabilities may be detected</li>
            <li><strong>No uptime guarantee:</strong> Service may be unavailable</li>
            <li><strong>No fitness guarantee:</strong> Tool may not meet your specific needs</li>
          </ul>

          <h2>5. Limitation of Liability</h2>
          <div className="bg-yellow-50 border-l-4 border-yellow-400 p-4 my-4">
            <p className="font-semibold text-yellow-800">
              BugBounty Arsenal and its operators SHALL NOT BE LIABLE for:
            </p>
            <ul className="text-yellow-700">
              <li>Illegal use of the Service by users</li>
              <li>Damages to scanned systems or data</li>
              <li>Financial losses resulting from scans</li>
              <li>Reputational damage</li>
              <li>Legal consequences or prosecution</li>
              <li>False positives causing unnecessary work</li>
              <li>Missed vulnerabilities leading to breaches</li>
              <li>Third-party claims or lawsuits</li>
            </ul>
          </div>

          <h2>6. Indemnification</h2>
          <p>
            You agree to INDEMNIFY, DEFEND, and HOLD HARMLESS BugBounty Arsenal, its owners, operators, 
            and affiliates from any claims, damages, losses, liabilities, and expenses (including legal fees) 
            arising from your use of the Service.
          </p>

          <h2>7. Professional Advice Disclaimer</h2>
          <p>
            The Service does not provide legal, professional, or expert advice. Results should be verified 
            by qualified security professionals. Do not rely solely on automated scan results.
          </p>

          <h2>8. Responsible Disclosure</h2>
          <p>
            If you discover vulnerabilities using this tool:
          </p>
          <ul>
            <li><strong>DO NOT</strong> publicly disclose without permission</li>
            <li><strong>DO</strong> contact the system owner privately</li>
            <li><strong>DO</strong> follow responsible disclosure guidelines</li>
            <li><strong>DO</strong> allow reasonable time for fixes (typically 90 days)</li>
            <li><strong>DO</strong> respect bug bounty program policies</li>
          </ul>

          <h2>9. Prohibited Targets</h2>
          <div className="bg-red-50 border border-red-200 rounded p-4 my-4">
            <h3 className="text-red-800 mt-0">🚫 NEVER SCAN:</h3>
            <ul className="text-red-700">
              <li>Government or military systems (without explicit authorization)</li>
              <li>Critical infrastructure (power, water, healthcare, etc.)</li>
              <li>Financial institutions without permission</li>
              <li>Healthcare systems containing patient data</li>
              <li>Educational institutions without authorization</li>
              <li>Any system with explicit "no scanning" policies</li>
              <li>Third-party systems during security audits (without scope approval)</li>
            </ul>
          </div>

          <h2>10. Service Modifications</h2>
          <p>
            We reserve the right to modify, suspend, or discontinue the Service at any time without notice. 
            We are not liable for any modifications or interruptions.
          </p>

          <h2>11. Jurisdiction</h2>
          <p>
            This Disclaimer is governed by Bulgarian law. Any legal disputes shall be resolved exclusively 
            in the courts of Sofia, Bulgaria.
          </p>

          <h2>12. Severability</h2>
          <p>
            If any provision of this Disclaimer is found invalid or unenforceable, the remaining provisions 
            shall continue in full force and effect.
          </p>

          <div className="bg-gray-900 text-white rounded-lg p-6 my-8">
            <h3 className="text-yellow-400 flex items-center gap-2">
              <FiAlertTriangle />
              FINAL WARNING
            </h3>
            <p className="mt-4">
              By using BugBounty Arsenal, you acknowledge that you have read, understood, and agreed to this 
              Disclaimer. You confirm that you will ONLY scan systems you own or have explicit written 
              authorization to test.
            </p>
            <p className="mt-4 font-semibold text-red-400">
              IF YOU DO NOT AGREE OR DO NOT HAVE PROPER AUTHORIZATION, DO NOT USE THIS SERVICE.
            </p>
          </div>

          <div className="bg-gray-100 border-l-4 border-gray-400 p-4 my-6">
            <p className="text-sm text-gray-700">
              <strong>Version:</strong> 1.0<br />
              <strong>Effective Date:</strong> January 18, 2026<br />
              <strong>Last Revision:</strong> January 18, 2026
            </p>
          </div>

        </div>
      </div>
    </div>
  );
};

export default Disclaimer;

