/**
 * Adds scroll effect to the header
 * Makes header stick to top and adds scrolled class
 */
function initHeaderScrollEffect() {
    const header = document.querySelector('.main-header');
    
    window.addEventListener('scroll', () => {
  
        if (window.scrollY > 10) {
            header.classList.add('scrolled');
        } else {
            header.classList.remove('scrolled');
        }
    });
    
    if (window.scrollY > 10) {
        header.classList.add('scrolled');
    }
}

export { initHeaderScrollEffect };
