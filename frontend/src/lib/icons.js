import React from 'react';
import {
  FiGlobe,
  FiSearch,
  FiCpu,
  FiShield,
  FiLink,
  FiLock,
  FiBriefcase,
  FiTarget,
  FiAlertTriangle,
  FiAlertCircle,
  FiSmartphone,
  FiTerminal,
  FiEye,
  FiTag,
  FiCheck,
} from 'react-icons/fi';

export const getDetectorCategoryIcon = (key, { size = 18, className = '' } = {}) => {
  const props = { size, className };

  switch (key) {
    case 'web':
      return <FiGlobe {...props} />;
    case 'recon':
      return <FiSearch {...props} />;
    case 'api':
      return <FiCpu {...props} />;
    case 'injection':
      return <FiTerminal {...props} />;
    case 'fuzzing':
      return <FiTarget {...props} />;
    case 'auth':
      return <FiLock {...props} />;
    case 'ssrf':
      return <FiLink {...props} />;
    case 'business_logic':
      return <FiBriefcase {...props} />;
    case 'zero_day':
      return <FiShield {...props} />;
    case 'vuln':
      return <FiAlertCircle {...props} />;
    case 'mobile':
      return <FiSmartphone {...props} />;
    case 'custom':
      return <FiEye {...props} />;
    default:
      return <FiTag {...props} />;
  }
};

export const getScanCategoryIcon = (key, { size = 22, className = '' } = {}) => {
  const props = { size, className };
  switch (key) {
    case 'recon':
      return <FiSearch {...props} />;
    case 'web':
      return <FiGlobe {...props} />;
    case 'api':
      return <FiCpu {...props} />;
    case 'vuln':
      return <FiAlertTriangle {...props} />;
    case 'mobile':
      return <FiSmartphone {...props} />;
    case 'custom':
      return <FiEye {...props} />;
    case 'injection':
      return <FiTerminal {...props} />;
    default:
      return <FiTag {...props} />;
  }
};

export const CheckIcon = ({ size = 16, className = '' } = {}) => (
  <FiCheck size={size} className={className} />
);

export const DangerIcon = ({ size = 16, className = '' } = {}) => (
  <FiAlertTriangle size={size} className={className} />
);
