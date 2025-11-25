(() => {
  const themeToggle = document.querySelector('[data-theme-toggle]');
  if (themeToggle) {
    themeToggle.addEventListener('click', () => {
      const html = document.documentElement;
      const current = html.getAttribute('data-bs-theme') || 'dark';
      const next = current === 'dark' ? 'light' : 'dark';
      html.setAttribute('data-bs-theme', next);
      localStorage.setItem('hw-theme', next);
    });
    const saved = localStorage.getItem('hw-theme');
    if (saved) document.documentElement.setAttribute('data-bs-theme', saved);
  }
})();

// Clear stored secrets on logout to force re-entry
(() => {
  document.querySelectorAll('[data-logout]').forEach((link) => {
    link.addEventListener('click', () => {
      try {
        sessionStorage.removeItem('hw-secrets');
      } catch (e) {
        // ignore
      }
    });
  });
})();

// Register service worker for PWA/installable experience
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/static/js/sw.js').catch(() => {});
  });
}
