import { useEffect, useRef } from 'react';

const FOCUSABLE_SELECTOR = [
  'a[href]',
  'area[href]',
  'button:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  'iframe',
  'object',
  'embed',
  '[contenteditable="true"]',
  '[tabindex]:not([tabindex="-1"])',
].join(',');

const getFocusable = (container) => {
  if (!container) return [];
  const nodes = Array.from(container.querySelectorAll(FOCUSABLE_SELECTOR));
  return nodes.filter((el) => {
    if (!(el instanceof HTMLElement)) return false;
    const style = window.getComputedStyle(el);
    return style.visibility !== 'hidden' && style.display !== 'none';
  });
};

/**
 * Minimal modal accessibility helper:
 * - focuses first focusable element when opened
 * - traps Tab key within the modal
 * - closes on Escape
 * - disables background scroll while open
 */
export default function useModalA11y(open, { onClose } = {}) {
  const dialogRef = useRef(null);

  useEffect(() => {
    if (!open) return;

    const dialog = dialogRef.current;
    const previousActive = document.activeElement;

    // Disable background scroll
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    // Focus first focusable control inside modal
    const focusables = getFocusable(dialog);
    const initial = focusables[0] || dialog;
    if (initial && typeof initial.focus === 'function') {
      initial.focus();
    }

    const onKeyDown = (e) => {
      if (!open) return;

      if (e.key === 'Escape') {
        if (typeof onClose === 'function') onClose();
        return;
      }

      if (e.key !== 'Tab') return;

      const items = getFocusable(dialog);
      if (items.length === 0) {
        e.preventDefault();
        return;
      }

      const first = items[0];
      const last = items[items.length - 1];
      const active = document.activeElement;

      if (e.shiftKey) {
        if (active === first || !dialog.contains(active)) {
          e.preventDefault();
          last.focus();
        }
      } else {
        if (active === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };

    document.addEventListener('keydown', onKeyDown);

    return () => {
      document.removeEventListener('keydown', onKeyDown);
      document.body.style.overflow = prevOverflow;

      if (previousActive && typeof previousActive.focus === 'function') {
        previousActive.focus();
      }
    };
  }, [open, onClose]);

  return dialogRef;
}
