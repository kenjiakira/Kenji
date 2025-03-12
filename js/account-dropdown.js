/**
 * Simple, direct account dropdown functionality
 */

// Initialize dropdown as soon as DOM is loaded
document.addEventListener('DOMContentLoaded', initializeDropdown);

// Also set up a mutation observer to watch for dynamically loaded content
const observer = new MutationObserver(function(mutations) {
    // Check if our button exists now
    if (document.getElementById('account-btn')) {
        initializeDropdown();
        observer.disconnect(); // Stop observing once we've initialized
    }
});

// Start observing
observer.observe(document, {
    childList: true,
    subtree: true
});

/**
 * Initialize dropdown functionality
 */
function initializeDropdown() {
    console.log('Initializing account dropdown');
    
    // Get elements
    const accountBtn = document.getElementById('account-btn');
    const dropdownContent = document.getElementById('auth-dropdown-content');
    
    // Exit if elements don't exist
    if (!accountBtn || !dropdownContent) {
        console.log('Account dropdown elements not found, will try again later');
        return;
    }
    
    // Ensure no existing click listeners by using a fresh event handler
    accountBtn.onclick = function(e) {
        e.preventDefault();
        e.stopPropagation();
        console.log('Account button clicked');
        toggleDropdown();
    };
    
    // Simple toggle function
    function toggleDropdown() {
        if (dropdownContent.classList.contains('show')) {
            dropdownContent.classList.remove('show');
            accountBtn.setAttribute('aria-expanded', 'false');
        } else {
            dropdownContent.classList.add('show');
            accountBtn.setAttribute('aria-expanded', 'true');
        }
    }
    
    // Close dropdown when clicking anywhere else
    document.addEventListener('click', function(e) {
        // If dropdown is open and click is outside button and dropdown
        if (dropdownContent.classList.contains('show') && 
            !accountBtn.contains(e.target) && 
            !dropdownContent.contains(e.target)) {
            dropdownContent.classList.remove('show');
            accountBtn.setAttribute('aria-expanded', 'false');
        }
    });
    
    // Setup logout functionality
    const logoutLink = document.getElementById('logout-link');
    if (logoutLink) {
        logoutLink.onclick = function(e) {
            e.preventDefault();
            console.log('Logout clicked');
            
            fetch('/api/auth/logout', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'same-origin'
            })
            .then(response => {
                console.log('Logout response received');
                if (!response.ok) {
                    throw new Error('Logout failed');
                }
                return response.json();
            })
            .then(data => {
                console.log('Logout successful');
                // Redirect to home page
                window.location.href = '/';
            })
            .catch(error => {
                console.error('Logout error:', error);
                // Redirect anyway
                window.location.href = '/';
            });
        };
    }
    
    console.log('Account dropdown initialized');
}

// Make function available globally
window.initializeAccountDropdown = initializeDropdown;
