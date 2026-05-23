import React from 'react';
import { FiAlertTriangle } from 'react-icons/fi';

export default function ErrorState({
  title = 'Something went wrong',
  message,
  action,
  className = '',
  minHeightClassName = 'min-h-[40vh]',
}) {
  return (
    <div className={`ui-page flex items-center justify-center ${minHeightClassName} ${className}`.trim()}>
      <div className="ui-card p-8 text-center max-w-xl">
        <FiAlertTriangle className="mx-auto text-red-500 mb-4" size={48} />
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">{title}</h2>
        {message ? <p className="text-gray-600 dark:text-gray-300 mb-6">{message}</p> : null}
        {action ? <div className="flex justify-center">{action}</div> : null}
      </div>
    </div>
  );
}
