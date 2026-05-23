import React from 'react';
import { Link } from 'react-router-dom';
import { FiArrowLeft, FiShield } from 'react-icons/fi';

const Terms = () => {
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
            <h1 className="text-3xl font-bold text-white">Terms of Service</h1>
          </div>
          <p className="text-gray-400 mt-2">Last Updated: January 18, 2026</p>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-4xl mx-auto px-4 py-12">
        <div className="ui-card ui-card-lg p-8 ui-prose prose-lg">
          
          <h2>1. Acceptance of Terms</h2>
          <p>
            By using BugBounty Arsenal ("the Service"), you agree to comply with these Terms of Service. 
            If you do not agree with these terms, please do not use the Service.
          </p>

          <h2>2. Service Description</h2>
          <p>
            BugBounty Arsenal is an automated vulnerability scanning tool for web applications, designed 
            for ethical hackers, penetration testers, and security researchers.
          </p>

          <h2>3. Legal Use</h2>
          <div className="bg-yellow-50 border-l-4 border-yellow-400 p-4 my-4">
            <p className="font-semibold text-yellow-800">⚠️ IMPORTANT:</p>
            <p className="text-yellow-700">
              You agree to use the Service ONLY for:
            </p>
            <ul className="text-yellow-700">
              <li>Testing systems you own</li>
              <li>Testing systems for which you have explicit written authorization</li>
              <li>Participating in authorized bug bounty programs</li>
              <li>Educational purposes in controlled environments</li>
            </ul>
          </div>

          <h2>4. Prohibited Activities</h2>
          <div className="bg-red-50 border-l-4 border-red-500 p-4 my-4">
            <p className="font-semibold text-red-800">🚫 STRICTLY FORBIDDEN:</p>
            <ul className="text-red-700">
              <li>Scanning systems without explicit authorization</li>
              <li>Using the Service for illegal purposes</li>
              <li>Denial of service attacks or system damage</li>
              <li>Unauthorized data exfiltration</li>
              <li>Public disclosure of vulnerabilities without owner consent</li>
            </ul>
          </div>

          <h2>5. User Responsibility</h2>
          <p>
            You are solely responsible for your use of the Service. You acknowledge that:
          </p>
          <ul>
            <li>You must obtain proper authorization before scanning any system</li>
            <li>You must comply with all applicable laws and regulations</li>
            <li>You are responsible for any damages resulting from your actions</li>
            <li>You will practice responsible disclosure of any vulnerabilities found</li>
          </ul>

          <h2>6. Limitation of Liability</h2>
          <p className="font-semibold">
            BugBounty Arsenal and its operators are NOT LIABLE for:
          </p>
          <ul>
            <li>Any illegal use of the Service by users</li>
            <li>Damages to systems scanned by users</li>
            <li>Legal consequences of unauthorized scanning</li>
            <li>Financial losses or reputational damage</li>
            <li>False positives or missed vulnerabilities</li>
          </ul>

          <h2>7. Open-Source Release</h2>
          <p>
            BugBounty Arsenal is released here as open-source software.
            Optional donations may be offered to support hosting and maintenance, but payment is not required
            to use the features included in this repository.
          </p>
          <p>
            Some high-risk actions may still require email or domain verification as a safety control.
            These verification requirements are intended to reduce abuse.
          </p>

          <h2>8. Account Termination</h2>
          <p>
            We reserve the right to terminate accounts that:
          </p>
          <ul>
            <li>Violate these Terms of Service</li>
            <li>Engage in illegal scanning activities</li>
            <li>Abuse the Service or infrastructure</li>
            <li>Repeatedly evade safety controls or verification requirements</li>
          </ul>

          <h2>9. Intellectual Property</h2>
          <p>
            All content, features, and functionality of BugBounty Arsenal are owned by us and protected 
            by international copyright, trademark, and other intellectual property laws.
          </p>

          <h2>10. Changes to Terms</h2>
          <p>
            We may modify these Terms at any time. Continued use of the Service after changes constitutes 
            acceptance of the new Terms.
          </p>

          <h2>11. Governing Law</h2>
          <p>
            These Terms are governed by the laws of Bulgaria. Any disputes shall be resolved in the courts 
            of Sofia, Bulgaria.
          </p>

          <h2>12. Contact Information</h2>
          <p>
            For questions about these Terms, contact us at:{' '}
            <a href="mailto:legal@bugbounty-arsenal.com" className="text-primary hover:underline">
              legal@bugbounty-arsenal.com
            </a>
          </p>

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

export default Terms;
