async function loadHeader() {
    try {
        console.log('Loading header...');
        const response = await fetch('/components/header.html');
        if (!response.ok) {
            throw new Error(`Failed to load header: ${response.status} ${response.statusText}`);
        }
        const html = await response.text();
        console.log('Header loaded successfully');
        
        const headerPlaceholder = document.getElementById('header-placeholder');
        if (!headerPlaceholder) {
            throw new Error('Header placeholder not found in DOM');
        }
        headerPlaceholder.innerHTML = html;
        
        const currentPath = window.location.pathname;
        const navLinks = document.querySelectorAll('.nav-link');
        navLinks.forEach(link => {
            if (link.getAttribute('href') === currentPath) {
                link.classList.add('active');
            }
        });
    } catch (error) {
        console.error('Error loading header:', error);
    }
}

export { loadHeader };
