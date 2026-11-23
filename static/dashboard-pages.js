(() => {
  'use strict';
  const names = {config: 'Configuration', overlay: 'Overlay Editor', 'wasm-store': 'WASM Store', 'sdr-ui': 'SDR UI Editor'};
  const panels = { config: 'config-page', overlay: 'overlay-page', 'wasm-store': 'wasm-store-page', 'sdr-ui': 'sdr-ui-page' };
  let current = null;
  function route() {
    const page = window.location.hash.replace(/^#\/?/, '').toLowerCase();
    return Object.prototype.hasOwnProperty.call(panels, page) ? page : 'config';
  }
  function show(page) {
    if (!Object.prototype.hasOwnProperty.call(panels, page)) page = 'config';
    if (current === page) return;
    for (const [id, elementId] of Object.entries(panels)) {
      document.getElementById(elementId).hidden = id !== page;
      const btn = document.querySelector(`.page-tab[data-page="${id}"]`);
      btn?.classList.toggle('is-active', id === page);
      btn?.setAttribute('aria-pressed', String(id === page));
    }
    document.getElementById('dashboard-section-label').textContent = names[page];
    // Saving a config should never be mistaken for saving the overlay or WASM state.
    for (const btn of document.querySelectorAll('[data-config-action]')) btn.hidden = page !== 'config';
    current = page;
    // Switching the main page starts at its heading, not the previous page scroll.
    window.scrollTo(0, 0);
    document.dispatchEvent(new CustomEvent('dashboard-page', { detail: { page } }));
  }
  document.addEventListener('DOMContentLoaded', () => {
    for (const btn of document.querySelectorAll('.page-tab')) {
      btn.addEventListener('click', () => {
        const page = btn.dataset.page;
        if (route() === page) show(page);
        else window.location.hash = `/${page}`;
      });
    }
    window.addEventListener('hashchange', () => show(route()));
    show(route());
  });
})();
