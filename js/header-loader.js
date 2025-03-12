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
        
        // Insert header HTML
        headerPlaceholder.innerHTML = html;
        
        // Setup nav links
        const currentPath = window.location.pathname;
        const navLinks = document.querySelectorAll('.nav-link');
        navLinks.forEach(link => {
            if (link.getAttribute('href') === currentPath) {
                link.classList.add('active');
            }
        });
        
        // Initialize dropdown functionality
        console.log('Setting up dropdown after header load');
        
        // We need to ensure the dropdown script exists and is loaded
        await loadDropdownScript();
        
        // Then initialize the dropdown
        if (typeof window.initializeAccountDropdown === 'function') {
            window.initializeAccountDropdown();
        } else {
            console.error('Account dropdown function not found');
        }
    } catch (error) {
        console.error('Error loading header:', error);
    }
}

async function loadDropdownScript() {
    return new Promise((resolve) => {
        // Check if script already exists
        if (document.querySelector('script[src$="account-dropdown.js"]')) {
            resolve();
            return;
        }
        
        // Load the script if it doesn't exist
        const script = document.createElement('script');
        script.src = '/js/account-dropdown.js';
        script.onload = () => resolve();
        script.onerror = () => {
            console.error('Failed to load dropdown script');
            resolve(); // Resolve anyway to prevent hanging
        };
        document.head.appendChild(script);
    });
}

export { loadHeader };
