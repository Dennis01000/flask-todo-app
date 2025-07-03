window.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.card').forEach((card, i) => {
    card.style.opacity = 0;
    setTimeout(() => {
      card.style.transition = 'opacity 0.5s ease-out';
      card.style.opacity = 1;
    }, i * 100);
  });
});
