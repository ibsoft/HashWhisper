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

// Auto-dismiss flash alerts after a short delay
(() => {
  document.querySelectorAll('.alert').forEach((el) => {
    const inst = bootstrap.Alert.getOrCreateInstance(el);
    setTimeout(() => {
      try { inst.close(); } catch (e) { /* ignore */ }
    }, 3000);
  });
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

// Mobile PWA install prompt
(() => {
  let deferredPrompt = null;
  const isStandalone = () => window.matchMedia('(display-mode: standalone)').matches || navigator.standalone;
  const isMobile = /Android|iPhone|iPad|iPod/i.test(navigator.userAgent || '');

  window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredPrompt = e;
    // prompt only on user action to satisfy browser requirements
  });

  function showPwaPrompt() {
    if (!deferredPrompt) return;
    const shouldInstall = confirm('Install HashWhisper as an app?');
    if (!shouldInstall) return;
    deferredPrompt.prompt();
    deferredPrompt.userChoice.finally(() => {
      deferredPrompt = null;
    });
  }
})();
