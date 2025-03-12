const express = require('express');
const path = require('path');
const dotenv = require('dotenv');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const { body, validationResult } = require('express-validator');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS || '12', 10);

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", 'data:', 'https://source.unsplash.com']
        }
    }
}));

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5, 
    message: { error: 'Too many login attempts, please try again later' }
});

const db = new sqlite3.Database('./blog.db', async (err) => {
    if (err) {
        console.error('Error connecting to SQLite database:', err);
        return;
    }
    
    console.log('Connected to SQLite database');
    
    try {
        await new Promise((resolve, reject) => {
            db.run(`
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    displayName TEXT,
                    role TEXT DEFAULT 'user',
                    createdAt TEXT,
                    lastLogin TEXT,
                    passwordResetToken TEXT,
                    passwordResetExpires TEXT
                )
            `, (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
        
        console.log('Users table ready');
        
        const adminEmail = process.env.ADMIN_EMAIL;
        const adminPassword = process.env.ADMIN_PASSWORD;
        
        if (!adminEmail || !adminPassword) {
            console.error('Admin credentials not found in environment variables');
            return;
        }
        
        const user = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM users WHERE email = ?', [adminEmail], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });
        
        if (!user) {
            
            const hash = await bcrypt.hash(adminPassword, SALT_ROUNDS);
            
            await new Promise((resolve, reject) => {
                db.run(
                    'INSERT INTO users (email, password, displayName, role, createdAt, lastLogin) VALUES (?, ?, ?, ?, ?, ?)',
                    [adminEmail, hash, 'Administrator', 'admin', new Date().toISOString(), new Date().toISOString()],
                    (err) => {
                        if (err) reject(err);
                        else resolve();
                    }
                );
            });
            
            console.log('Admin user created');
        }
    } catch (error) {
        console.error('Error during database initialization:', error);
    }
});

app.use(bodyParser.json({ limit: '10kb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '/'), {
    maxAge: 31536000 
}));

const sessionConfig = {
    secret: process.env.SESSION_SECRET || 'fallback_secret_do_not_use_in_production',
    name: 'blog_session', 
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true, 
        secure: process.env.COOKIE_SECURE === 'true',
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000 
    }
};

if (process.env.NODE_ENV === 'production') {
    app.set('trust proxy', 1); 
    sessionConfig.cookie.secure = true;
}

app.use(session(sessionConfig));

app.use(csrf({ cookie: true }));
app.use((req, res, next) => {
    res.locals.csrfToken = req.csrfToken();
    next();
});

app.get('/api/csrf-token', (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

app.use((err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') {
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }
    next(err);
});

const isAuthenticated = (req, res, next) => {
    if (req.session.userId) {
        next();
    } else {
        res.status(401).json({ error: 'Unauthorized' });
    }
};

app.post('/api/auth/signup', [
  
    body('email').isEmail().withMessage('Valid email is required'),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
    body('displayName').trim().notEmpty().withMessage('Name is required')
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, password, displayName } = req.body;
    
    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
        if (err) {
            console.error('Database error during signup:', err);
            return res.status(500).json({ error: 'Internal server error' });
        }
        
        if (user) {
            return res.status(400).json({ error: 'Email already in use' });
        }
        
        bcrypt.hash(password, SALT_ROUNDS, (err, hash) => {
            if (err) {
                console.error('Error hashing password:', err);
                return res.status(500).json({ error: 'Internal server error' });
            }
            
            db.run(
                'INSERT INTO users (email, password, displayName, role, createdAt) VALUES (?, ?, ?, ?, ?)',
                [email, hash, displayName, 'user', new Date().toISOString()],
                function(err) {
                    if (err) {
                        console.error('Error creating user:', err);
                        return res.status(500).json({ error: 'Internal server error' });
                    }
                    
                    // Set session
                    req.session.userId = this.lastID;
                    req.session.email = email;
                    req.session.displayName = displayName;
                    req.session.role = 'user';
                    
                    // Record login time
                    recordLoginTime(this.lastID);
                    
                    res.status(201).json({
                        message: 'User created successfully',
                        user: {
                            id: this.lastID,
                            email,
                            displayName,
                            role: 'user'
                        }
                    });
                }
            );
        });
    });
});

app.post('/api/auth/login', loginLimiter, [
    body('email').isEmail().withMessage('Valid email is required'),
    body('password').notEmpty().withMessage('Password is required')
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;
    
    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
        if (err) {
            console.error('Database error during login:', err);
            return res.status(500).json({ error: 'Internal server error' });
        }
        
        if (!user) {
            
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) {
                console.error('Error comparing passwords:', err);
                return res.status(500).json({ error: 'Internal server error' });
            }
            
            if (!isMatch) {
                return res.status(400).json({ error: 'Invalid credentials' });
            }

            req.session.userId = user.id;
            req.session.email = user.email;
            req.session.displayName = user.displayName;
            req.session.role = user.role;
            
            recordLoginTime(user.id);
            
            res.json({
                message: 'Login successful',
                user: {
                    id: user.id,
                    email: user.email,
                    displayName: user.displayName,
                    role: user.role
                }
            });
        });
    });
});

function recordLoginTime(userId) {
    db.run('UPDATE users SET lastLogin = ? WHERE id = ?', 
        [new Date().toISOString(), userId], 
        (err) => {
            if (err) {
                console.error('Error updating login time:', err);
            }
        }
    );
}

app.post('/api/auth/logout', isAuthenticated, (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error during logout:', err);
            return res.status(500).json({ error: 'Internal server error' });
        }
        
        res.clearCookie('blog_session');
        res.json({ message: 'Logout successful' });
    });
});

app.get('/api/auth/user', isAuthenticated, (req, res) => {
    db.get(
        'SELECT id, email, displayName, role, createdAt, lastLogin FROM users WHERE id = ?', 
        [req.session.userId], 
        (err, user) => {
            if (err) {
                console.error('Error fetching user data:', err);
                return res.status(500).json({ error: 'Internal server error' });
            }
            
            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }
            
            res.json({ user });
        }
    );
});

// Check current session
app.get('/api/auth/session', (req, res) => {
    if (req.session.userId) {
        res.json({
            isAuthenticated: true,
            user: {
                id: req.session.userId,
                email: req.session.email,
                displayName: req.session.displayName,
                role: req.session.role
            }
        });
    } else {
        res.json({ isAuthenticated: false });
    }
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get(['/account', '/profile.html', '/profile'], (req, res) => {
    res.sendFile(path.join(__dirname, 'profile.html'));
});

app.use((req, res) => {
    res.status(404).sendFile(path.join(__dirname, './components/404.html'));
});

app.listen(PORT, () => {
    console.log(`Server running on port http://localhost:${PORT}`);
});

process.on('SIGINT', () => {
    db.close(() => {
        console.log('SQLite database connection closed');
        process.exit(0);
    });
});
