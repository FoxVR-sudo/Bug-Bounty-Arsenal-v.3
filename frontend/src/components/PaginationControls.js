import React from 'react';

export default function PaginationControls({
  page,
  totalPages,
  hasPrev,
  hasNext,
  onPrev,
  onNext,
  className = '',
}) {
  return (
    <div className={`flex items-center justify-between gap-3 ${className}`.trim()}>
      <div className="text-sm text-gray-600 dark:text-gray-300">
        Page {page}
        {typeof totalPages === 'number' ? ` of ${Math.max(1, totalPages)}` : ''}
      </div>
      <div className="flex items-center gap-2">
        <button
          onClick={onPrev}
          disabled={!hasPrev}
          className="ui-btn ui-btn-secondary"
          type="button"
        >
          Prev
        </button>
        <button
          onClick={onNext}
          disabled={!hasNext}
          className="ui-btn ui-btn-secondary"
          type="button"
        >
          Next
        </button>
      </div>
    </div>
  );
}
