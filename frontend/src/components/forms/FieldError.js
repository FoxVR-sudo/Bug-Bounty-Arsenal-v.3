import React from 'react';

export default function FieldError({ id, message, className = '' }) {
  if (!message) return null;
  return (
    <p
      id={id}
      role="alert"
      aria-live="polite"
      className={`ui-field-error ${className}`.trim()}
    >
      {message}
    </p>
  );
}
