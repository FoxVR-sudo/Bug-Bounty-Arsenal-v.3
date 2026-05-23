/* BugBounty Arsenal — Force Jazzmin dark mode (data-bs-theme) */
(function () {
  // Jazzmin 3.x reads localStorage key 'jazzmin-theme-mode' in its inline <head> script.
  // Set it to 'dark' so every subsequent page load activates dark mode immediately.
  try { localStorage.setItem('jazzmin-theme-mode', 'dark'); } catch (_) {}
  // Also set the attribute now (for the current page load).
  document.documentElement.setAttribute('data-bs-theme', 'dark');
})();
