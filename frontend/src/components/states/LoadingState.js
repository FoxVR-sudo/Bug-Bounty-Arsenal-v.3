import React from 'react';
import { FiLoader } from 'react-icons/fi';

export default function LoadingState({
  title = 'Loading…',
  subtitle,
  className = '',
  minHeightClassName = 'min-h-[40vh]',
}) {
  return (
    <div className={`ui-page flex items-center justify-center ${minHeightClassName} ${className}`.trim()}>
      <div className="ui-card p-6 flex items-center gap-3">
        <FiLoader className="animate-spin text-primary" />
        <div>
          <div className="font-semibold text-gray-900 dark:text-white">{title}</div>
          {subtitle ? <div className="text-sm text-gray-600 dark:text-gray-300">{subtitle}</div> : null}
        </div>
      </div>
    </div>
  );
}
