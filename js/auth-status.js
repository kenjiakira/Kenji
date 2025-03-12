let currentUser = null;
let csrfToken = null;

export async function setupAuthUI() {
    try {
        // Fetch CSRF token as early as possible
        await fetchCsrfToken();
        
        const accountBtn = document.getElementById('account-btn');
        const dropdownContent = document.getElementById('auth-dropdown-content');
        
        if (!accountBtn || !dropdownContent) {
            console.error('Account elements not found in DOM');
            return { isAuthenticated: false };
        }
        
        dropdownContent.style.display = 'none';
        
        accountBtn.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            

            if (dropdownContent.style.display === 'none' || dropdownContent.style.display === '') {
                dropdownContent.style.display = 'block';
                dropdownContent.classList.add('show');
            } else {
                dropdownContent.style.display = 'none';
                dropdownContent.classList.remove('show');
            }
        });
        
        document.addEventListener('click', function(e) {
            if (!e.target.closest('.auth-dropdown') && dropdownContent.classList.contains('show')) {
                dropdownContent.style.display = 'none';
                dropdownContent.classList.remove('show');
            }
        });
        
        const loginLink = document.getElementById('login-link');
        const registerLink = document.getElementById('register-link');
        const logoutLink = document.getElementById('logout-link');
        
        if (loginLink) {
            loginLink.addEventListener('click', function(e) {
                e.preventDefault();
                dropdownContent.style.display = 'none';
                dropdownContent.classList.remove('show');
                toggleLoginForm(e);
            });
        }
        
        if (registerLink) {
            registerLink.addEventListener('click', function(e) {
                e.preventDefault();
                dropdownContent.style.display = 'none';
                dropdownContent.classList.remove('show');
                toggleSignupForm(e);
            });
        }
        
        const response = await fetch('/api/auth/session');
        const data = await response.json();
        
        if (data.isAuthenticated) {
            const authDropdown = accountBtn.closest('.auth-dropdown');
            if (authDropdown) {
                authDropdown.classList.add('logged-in');
            }
            
            if (loginLink) loginLink.style.display = 'none';
            if (registerLink) registerLink.style.display = 'none';
            if (logoutLink) logoutLink.style.display = 'flex';
            
            accountBtn.innerHTML = `
                <i class="fas fa-user-circle"></i>
                <span>${data.user.displayName || 'Account'}</span>
            `;
            
            if (logoutLink) {
                logoutLink.addEventListener('click', async (e) => {
                    e.preventDefault();
                    try {
                        await fetch('/api/auth/logout', { method: 'POST' });
                        window.location.reload();
                    } catch (error) {
                        console.error('Logout failed:', error);
                    }
                });
            }
        }
        
        return data;
    } catch (error) {
        console.error('Error setting up auth UI:', error);
        return { isAuthenticated: false };
    }
}

async function fetchCsrfToken() {
    try {
        const response = await fetch('/api/csrf-token');
        const data = await response.json();
        csrfToken = data.csrfToken;
        return csrfToken;
    } catch (error) {
        console.error('Error fetching CSRF token:', error);
        throw error;
    }
}

async function checkAuthStatus() {
    const response = await fetch('/api/auth/session');
    const data = await response.json();
    
    if (data.isAuthenticated) {
        handleAuthenticatedUser(data.user);
        return data.user;
    } else {
        handleUnauthenticatedUser();
        return null;
    }
}

function handleAuthenticatedUser(user) {
    currentUser = user;
    
    const dropdownContent = document.getElementById('auth-dropdown-content');
    
    dropdownContent.innerHTML = `
        <a href="profile.html" class="dropdown-item">
            <i class="fas fa-user"></i> Profile
        </a>
        <a href="#" id="logout-btn" class="dropdown-item">
            <i class="fas fa-sign-out-alt"></i> Logout
        </a>
        <span class="user-greeting" style="padding: 12px 16px; display: block;">Hello, ${user.displayName || user.email}</span>
    `;
    
    document.getElementById('account-btn').textContent = 'My Account';
    
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', (e) => {
            e.preventDefault();
            handleLogout();
        });
    }
}

function handleUnauthenticatedUser() {
    currentUser = null;
    
    const dropdownContent = document.getElementById('auth-dropdown-content');
    
    dropdownContent.innerHTML = `
        <a href="#" id="login-btn">Login</a>
        <a href="#" id="signup-btn">Sign Up</a>
    `;
    
    document.getElementById('account-btn').textContent = 'Account';
    
    const loginBtn = document.getElementById('login-btn');
    const signupBtn = document.getElementById('signup-btn');
    
    if (loginBtn) loginBtn.addEventListener('click', toggleLoginForm);
    if (signupBtn) signupBtn.addEventListener('click', toggleSignupForm);
}

async function handleLogout() {
    try {
        // Make sure we have a CSRF token before making the request
        if (!csrfToken) {
            await fetchCsrfToken();
        }
        
        await fetch('/api/auth/logout', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'CSRF-Token': csrfToken
            }
        });
        
        window.location.href = 'index.html';
    } catch (error) {
        console.error('Error logging out:', error);
    }
}

function toggleLoginForm(e) {
    e.preventDefault();

    
    const signupFormContainer = document.getElementById('signup-form-container');
    if (signupFormContainer) signupFormContainer.style.display = 'none';

    let loginFormContainer = document.getElementById('login-form-container');
    
    if (!loginFormContainer) {
     
        loginFormContainer = document.createElement('div');
        loginFormContainer.id = 'login-form-container';
        loginFormContainer.className = 'auth-form-container';
        
        loginFormContainer.innerHTML = `
            <div class="auth-form">
                <h2>Login</h2>
                <form id="login-form">
                    <div class="form-group">
                        <label for="login-email">Email</label>
                        <input type="email" id="login-email" required>
                    </div>
                    <div class="form-group">
                        <label for="login-password">Password</label>
                        <input type="password" id="login-password" required>
                    </div>
                    <button type="submit" class="btn">Login</button>
                    <div class="error-message" id="login-error"></div>
                    <p class="form-switch">Don't have an account? <a href="#" id="switch-to-signup">Sign up</a></p>
                </form>
                <button class="close-btn" id="close-login-form">×</button>
            </div>
        `;
        
        document.body.appendChild(loginFormContainer);
        
        document.getElementById('login-form').addEventListener('submit', handleLogin);
        document.getElementById('close-login-form').addEventListener('click', () => {
            loginFormContainer.style.display = 'none';
        });
        document.getElementById('switch-to-signup').addEventListener('click', (e) => {
            e.preventDefault();
            loginFormContainer.style.display = 'none';
            toggleSignupForm(e);
        });
    } else {

        loginFormContainer.style.display = 'flex';
    }
}

function toggleSignupForm(e) {
    e.preventDefault();

    
    const loginFormContainer = document.getElementById('login-form-container');
    if (loginFormContainer) loginFormContainer.style.display = 'none';
    
    let signupFormContainer = document.getElementById('signup-form-container');
    
    if (!signupFormContainer) {
     
        signupFormContainer = document.createElement('div');
        signupFormContainer.id = 'signup-form-container';
        signupFormContainer.className = 'auth-form-container';
        
        signupFormContainer.innerHTML = `
            <div class="auth-form">
                <h2>Sign Up</h2>
                <form id="signup-form">
                    <div class="form-group">
                        <label for="signup-name">Name</label>
                        <input type="text" id="signup-name" required>
                    </div>
                    <div class="form-group">
                        <label for="signup-email">Email</label>
                        <input type="email" id="signup-email" required>
                    </div>
                    <div class="form-group">
                        <label for="signup-password">Password</label>
                        <input type="password" id="signup-password" required minlength="6">
                    </div>
                    <button type="submit" class="btn">Sign Up</button>
                    <div class="error-message" id="signup-error"></div>
                    <p class="form-switch">Already have an account? <a href="#" id="switch-to-login">Login</a></p>
                </form>
                <button class="close-btn" id="close-signup-form">×</button>
            </div>
        `;
        
        document.body.appendChild(signupFormContainer);
    
        document.getElementById('signup-form').addEventListener('submit', handleSignup);
        document.getElementById('close-signup-form').addEventListener('click', () => {
            signupFormContainer.style.display = 'none';
        });
        document.getElementById('switch-to-login').addEventListener('click', (e) => {
            e.preventDefault();
            signupFormContainer.style.display = 'none';
            toggleLoginForm(e);
        });
    } else {

        signupFormContainer.style.display = 'flex';
    }
}

async function handleLogin(e) {
    e.preventDefault();
    
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    const errorElement = document.getElementById('login-error');
    
    try {
        if (!csrfToken) {
            await fetchCsrfToken();
        }
        
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'CSRF-Token': csrfToken
            },
            body: JSON.stringify({ email, password })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || (data.errors && data.errors[0].msg) || 'Login failed');
        }
        
        document.getElementById('login-form-container').style.display = 'none';
        
        window.location.reload();
    } catch (error) {
        errorElement.textContent = error.message || 'Failed to login. Please try again.';
    }
}

async function handleSignup(e) {
    e.preventDefault();
    
    const displayName = document.getElementById('signup-name').value;
    const email = document.getElementById('signup-email').value;
    const password = document.getElementById('signup-password').value;
    const errorElement = document.getElementById('signup-error');
    
    try {
        if (!csrfToken) {
            await fetchCsrfToken();
        }
        
        const response = await fetch('/api/auth/signup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'CSRF-Token': csrfToken
            },
            body: JSON.stringify({ displayName, email, password })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || (data.errors && data.errors[0].msg) || 'Signup failed');
        }
        
        document.getElementById('signup-form-container').style.display = 'none';
        
        window.location.reload();
    } catch (error) {
        errorElement.textContent = error.message || 'Failed to sign up. Please try again.';
    }
}

export function getCurrentUser() {
    return fetch('/api/auth/session')
        .then(res => res.json())
        .then(data => data.user)
        .catch(() => null);
}

export async function isUserAdmin() {
    if (!currentUser) return false;
    return currentUser.role === 'admin';
}
