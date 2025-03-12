import { setupAuthUI } from './js/auth-status.js';

document.addEventListener('DOMContentLoaded', function() {

    setupAuthUI();
    
    const accountBtn = document.getElementById('account-btn');
    if (accountBtn) {
        accountBtn.addEventListener('click', function() {
            const dropdownContent = document.getElementById('auth-dropdown-content');
            dropdownContent.style.display = dropdownContent.style.display === 'block' ? 'none' : 'block';
        });
        
        window.addEventListener('click', function(event) {
            if (!event.target.matches('#account-btn')) {
                const dropdownContent = document.getElementById('auth-dropdown-content');
                if (dropdownContent && dropdownContent.style.display === 'block') {
                    dropdownContent.style.display = 'none';
                }
            }
        });
    }
});
