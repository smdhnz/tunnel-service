document.addEventListener('click', (event) => {
  const open = event.target.closest('[data-modal-open]');
  if (open) document.getElementById(open.dataset.modalOpen)?.showModal();
  if (event.target.closest('[data-modal-close]')) event.target.closest('dialog')?.close();
  const copy = event.target.closest('[data-copy]');
  if (copy) {
    const value = document.querySelector(copy.dataset.copy)?.textContent || '';
    navigator.clipboard.writeText(value).then(() => {
      const old = copy.textContent; copy.textContent = 'Copied';
      setTimeout(() => copy.textContent = old, 1200);
    });
  }
  if (event.target.closest('#menu-toggle')) document.querySelector('.sidebar')?.classList.toggle('open');
});
document.addEventListener('submit', (event) => {
  const message = event.target.dataset.confirm;
  if (message && !window.confirm(message)) event.preventDefault();
});
