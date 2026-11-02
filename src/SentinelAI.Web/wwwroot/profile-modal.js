window.openModal = function (id) {
    const modal = document.getElementById(id);
    if (!modal) return;

    modal.classList.add('is-open');
    modal.setAttribute('aria-hidden', 'false');
    document.body.classList.add('modal-open');
    modal.querySelector('.modal-close')?.focus();
};

window.closeModal = function (id) {
    const modal = document.getElementById(id);
    if (!modal) return;

    modal.classList.remove('is-open');
    modal.setAttribute('aria-hidden', 'true');
    document.body.classList.remove('modal-open');
};

document.addEventListener('keydown', function (event) {
    if (event.key !== 'Escape') return;

    document.querySelectorAll('.modal-backdrop.is-open').forEach(function (modal) {
        closeModal(modal.id);
    });
});
