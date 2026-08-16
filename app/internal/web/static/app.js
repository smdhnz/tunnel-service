document.querySelectorAll('time.local-time[datetime]').forEach((element) => {
  const value = new Date(element.dateTime);
  if (Number.isNaN(value.getTime())) return;
  element.textContent = new Intl.DateTimeFormat('ja-JP', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false,
  }).format(value);
  element.title = `${Intl.DateTimeFormat().resolvedOptions().timeZone} の時刻`;
});

document.addEventListener('click', (event) => {
  const open = event.target.closest('[data-modal-open]');
  if (open) document.getElementById(open.dataset.modalOpen)?.showModal();
  if (event.target.closest('[data-modal-close]')) event.target.closest('dialog')?.close();
  const copy = event.target.closest('[data-copy]');
  if (copy) {
    const value = document.querySelector(copy.dataset.copy)?.textContent || '';
    navigator.clipboard.writeText(value).then(() => {
      const old = copy.textContent; copy.textContent = 'コピー済み';
      setTimeout(() => copy.textContent = old, 1200);
    });
  }
  const menu = event.target.closest('#menu-toggle');
  if (menu) {
    const sidebar = document.querySelector('.sidebar');
    const expanded = sidebar?.classList.toggle('open') || false;
    menu.setAttribute('aria-expanded', String(expanded));
  }
});
document.addEventListener('submit', (event) => {
  const message = event.target.dataset.confirm;
  if (message && !window.confirm(message)) event.preventDefault();
});
