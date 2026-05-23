import React from 'react';

export default function EmptyState({
  title = 'Nothing here yet',
  message,
  action,
  className = '',
}) {
  return (
    <div className={`ui-card p-6 text-center ${className}`.trim()}>
      <h3 className="text-lg font-semibold text-gray-900 dark:text-white">{title}</h3>
      {message ? <p className="text-sm text-gray-600 dark:text-gray-300 mt-2">{message}</p> : null}
      {action ? <div className="mt-4 flex justify-center">{action}</div> : null}
    </div>
  );
}
