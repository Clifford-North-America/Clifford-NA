# Security & Privacy

Security and privacy must be built into applications from the ground up. These practices help protect user data, prevent vulnerabilities, and maintain trust.

## 🎯 Core Principles

1. **Defense in Depth** - Implement multiple layers of security
2. **Least Privilege** - Grant minimum necessary permissions
3. **Privacy by Design** - Protect user data from the start
4. **Secure by Default** - Choose secure configurations and practices

## 🔐 Authentication & Authorization

### Password Security

### ✅ Good: Secure password handling

```javascript
import bcrypt from 'bcrypt';
import { rateLimit } from 'express-rate-limit';

// Strong password requirements
const PASSWORD_REQUIREMENTS = {
    minLength: 12,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    preventCommonPasswords: true
};

// Password validation
function validatePassword(password) {
    const errors = [];
    
    if (password.length < PASSWORD_REQUIREMENTS.minLength) {
        errors.push(`Password must be at least ${PASSWORD_REQUIREMENTS.minLength} characters`);
    }
    
    if (PASSWORD_REQUIREMENTS.requireUppercase && !/[A-Z]/.test(password)) {
        errors.push('Password must contain at least one uppercase letter');
    }
    
    if (PASSWORD_REQUIREMENTS.requireLowercase && !/[a-z]/.test(password)) {
        errors.push('Password must contain at least one lowercase letter');
    }
    
    if (PASSWORD_REQUIREMENTS.requireNumbers && !/\d/.test(password)) {
        errors.push('Password must contain at least one number');
    }
    
    if (PASSWORD_REQUIREMENTS.requireSpecialChars && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
        errors.push('Password must contain at least one special character');
    }
    
    // Check against common passwords
    if (PASSWORD_REQUIREMENTS.preventCommonPasswords && isCommonPassword(password)) {
        errors.push('Password is too common, please choose a stronger password');
    }
    
    return errors;
}

// Secure password hashing
async function hashPassword(password) {
    const saltRounds = 12; // High cost factor for security
    return await bcrypt.hash(password, saltRounds);
}

// Secure password verification
async function verifyPassword(plainPassword, hashedPassword) {
    return await bcrypt.compare(plainPassword, hashedPassword);
}

// Rate limiting for authentication attempts
const authRateLimit = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 requests per windowMs
    message: {
        error: 'Too many login attempts, please try again later',
        code: 'RATE_LIMIT_EXCEEDED'
    },
    standardHeaders: true,
    legacyHeaders: false
});

// Authentication endpoint with security measures
app.post('/api/auth/login', authRateLimit, async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Input validation
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                error: 'Email and password are required'
            });
        }
        
        // Find user (use constant-time lookup when possible)
        const user = await User.findByEmail(email);
        
        // Always verify password even if user doesn't exist (prevent timing attacks)
        const dummyHash = '$2b$12$dummy.hash.to.prevent.timing.attacks';
        const passwordToVerify = user ? user.passwordHash : dummyHash;
        const isPasswordValid = await bcrypt.compare(password, passwordToVerify);
        
        if (!user || !isPasswordValid) {
            // Log failed attempt for security monitoring
            logger.warn('Failed login attempt', {
                email: email,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date()
            });
            
            return res.status(401).json({
                success: false,
                error: 'Invalid email or password'
            });
        }
        
        // Check if account is locked
        if (user.isLocked && user.lockUntil > new Date()) {
            return res.status(423).json({
                success: false,
                error: 'Account is temporarily locked due to too many failed attempts'
            });
        }
        
        // Generate secure session token
        const token = generateSecureToken();
        const session = await createUserSession(user.id, token, req);
        
        // Log successful login
        logger.info('User logged in successfully', {
            userId: user.id,
            email: user.email,
            ip: req.ip,
            sessionId: session.id
        });
        
        res.json({
            success: true,
            token: token,
            user: sanitizeUserData(user)
        });
        
    } catch (error) {
        logger.error('Login error', { error: error.message, stack: error.stack });
        res.status(500).json({
            success: false,
            error: 'Authentication failed'
        });
    }
});
```

### ❌ Avoid: Insecure password practices

```javascript
// ❌ Weak password requirements
const isValidPassword = password => password.length >= 6;

// ❌ Storing plain text passwords
const user = {
    email: 'user@example.com',
    password: 'plainTextPassword' // Never do this!
};

// ❌ Weak hashing
const hashedPassword = crypto.createHash('md5').update(password).digest('hex');

// ❌ Revealing too much information
if (!user) {
    throw new Error('No user found with that email'); // Reveals email existence
}
if (!isPasswordValid) {
    throw new Error('Incorrect password'); // Confirms email exists
}
```

### JWT Token Security

### ✅ Good: Secure JWT implementation

```javascript
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const JWT_CONFIG = {
    accessTokenExpiry: '15m',   // Short-lived access tokens
    refreshTokenExpiry: '7d',   // Longer-lived refresh tokens
    algorithm: 'HS256',
    issuer: 'your-app-name',
    audience: 'your-app-users'
};

// Generate secure tokens
function generateTokenPair(user) {
    const payload = {
        userId: user.id,
        email: user.email,
        role: user.role,
        iss: JWT_CONFIG.issuer,
        aud: JWT_CONFIG.audience
    };
    
    const accessToken = jwt.sign(payload, process.env.JWT_ACCESS_SECRET, {
        expiresIn: JWT_CONFIG.accessTokenExpiry,
        algorithm: JWT_CONFIG.algorithm
    });
    
    const refreshToken = jwt.sign(
        { userId: user.id, tokenType: 'refresh' },
        process.env.JWT_REFRESH_SECRET,
        {
            expiresIn: JWT_CONFIG.refreshTokenExpiry,
            algorithm: JWT_CONFIG.algorithm
        }
    );
    
    return { accessToken, refreshToken };
}

// Secure token verification middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
    
    if (!token) {
        return res.status(401).json({
            success: false,
            error: 'Access token required'
        });
    }
    
    jwt.verify(token, process.env.JWT_ACCESS_SECRET, {
        algorithms: [JWT_CONFIG.algorithm],
        issuer: JWT_CONFIG.issuer,
        audience: JWT_CONFIG.audience
    }, (err, decoded) => {
        if (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json({
                    success: false,
                    error: 'Access token expired',
                    code: 'TOKEN_EXPIRED'
                });
            }
            
            return res.status(403).json({
                success: false,
                error: 'Invalid access token'
            });
        }
        
        req.user = decoded;
        next();
    });
}

// Token refresh endpoint
app.post('/api/auth/refresh', async (req, res) => {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
        return res.status(401).json({
            success: false,
            error: 'Refresh token required'
        });
    }
    
    try {
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        
        // Check if refresh token is still valid in database
        const isValidToken = await checkRefreshTokenValidity(decoded.userId, refreshToken);
        if (!isValidToken) {
            return res.status(403).json({
                success: false,
                error: 'Invalid refresh token'
            });
        }
        
        const user = await User.findById(decoded.userId);
        if (!user) {
            return res.status(403).json({
                success: false,
                error: 'User not found'
            });
        }
        
        // Generate new token pair
        const tokens = generateTokenPair(user);
        
        // Invalidate old refresh token and store new one
        await rotateRefreshToken(decoded.userId, refreshToken, tokens.refreshToken);
        
        res.json({
            success: true,
            ...tokens
        });
        
    } catch (error) {
        res.status(403).json({
            success: false,
            error: 'Invalid refresh token'
        });
    }
});
```

## 🛡️ Input Validation & Sanitization

### Prevent Injection Attacks

### ✅ Good: Comprehensive input validation

```javascript
import validator from 'validator';
import DOMPurify from 'isomorphic-dompurify';
import { body, param, query, validationResult } from 'express-validator';

// Input validation middleware
const validateUserInput = [
    body('email')
        .isEmail()
        .normalizeEmail()
        .withMessage('Please provide a valid email address'),
    
    body('firstName')
        .trim()
        .isLength({ min: 1, max: 50 })
        .matches(/^[a-zA-Z\s'-]+$/)
        .withMessage('First name must contain only letters, spaces, hyphens, and apostrophes'),
    
    body('lastName')
        .trim()
        .isLength({ min: 1, max: 50 })
        .matches(/^[a-zA-Z\s'-]+$/)
        .withMessage('Last name must contain only letters, spaces, hyphens, and apostrophes'),
    
    body('bio')
        .optional()
        .trim()
        .isLength({ max: 500 })
        .custom(value => {
            // Sanitize HTML content
            const sanitized = DOMPurify.sanitize(value);
            if (sanitized !== value) {
                throw new Error('Bio contains invalid HTML content');
            }
            return true;
        }),
    
    body('age')
        .optional()
        .isInt({ min: 13, max: 120 })
        .withMessage('Age must be between 13 and 120'),
    
    // Handle validation errors
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                error: 'Validation failed',
                details: errors.array()
            });
        }
        next();
    }
];

// SQL injection prevention with parameterized queries
async function getUserByEmail(email) {
    // ✅ Safe: Using parameterized query
    const query = 'SELECT * FROM users WHERE email = $1';
    const result = await database.query(query, [email]);
    return result.rows[0];
}

// ❌ Vulnerable to SQL injection
async function getUserByEmailUnsafe(email) {
    // Never do this - vulnerable to SQL injection
    const query = `SELECT * FROM users WHERE email = '${email}'`;
    const result = await database.query(query);
    return result.rows[0];
}

// NoSQL injection prevention
async function findUserById(userId) {
    // ✅ Validate input type
    if (!validator.isMongoId(userId)) {
        throw new ValidationError('Invalid user ID format');
    }
    
    // ✅ Use proper query methods
    return await User.findById(userId);
}

// XSS prevention
function sanitizeHtmlContent(content) {
    return DOMPurify.sanitize(content, {
        ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br'],
        ALLOWED_ATTR: []
    });
}

// CSRF protection
import csrf from 'csurf';
const csrfProtection = csrf({ cookie: true });

app.use(csrfProtection);

app.get('/api/csrf-token', (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});
```

## 🔒 Data Protection

### Environment Variables and Secrets

### ✅ Good: Secure configuration management

```javascript
// config/secrets.js
import crypto from 'crypto';

class SecretsManager {
    constructor() {
        this.validateRequiredSecrets();
    }
    
    validateRequiredSecrets() {
        const required = [
            'JWT_ACCESS_SECRET',
            'JWT_REFRESH_SECRET',
            'DATABASE_PASSWORD',
            'ENCRYPTION_KEY'
        ];
        
        const missing = required.filter(key => !process.env[key]);
        
        if (missing.length > 0) {
            throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
        }
        
        // Validate secret strength
        if (process.env.JWT_ACCESS_SECRET.length < 32) {
            throw new Error('JWT_ACCESS_SECRET must be at least 32 characters long');
        }
    }
    
    get jwtAccessSecret() {
        return process.env.JWT_ACCESS_SECRET;
    }
    
    get jwtRefreshSecret() {
        return process.env.JWT_REFRESH_SECRET;
    }
    
    get encryptionKey() {
        return Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
    }
}

export const secrets = new SecretsManager();

// Encryption utilities for sensitive data
class DataEncryption {
    constructor(key) {
        this.algorithm = 'aes-256-gcm';
        this.key = key;
    }
    
    encrypt(text) {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipher(this.algorithm, this.key, iv);
        
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        const authTag = cipher.getAuthTag();
        
        return {
            encrypted,
            iv: iv.toString('hex'),
            authTag: authTag.toString('hex')
        };
    }
    
    decrypt(encryptedData) {
        const { encrypted, iv, authTag } = encryptedData;
        const decipher = crypto.createDecipher(
            this.algorithm,
            this.key,
            Buffer.from(iv, 'hex')
        );
        
        decipher.setAuthTag(Buffer.from(authTag, 'hex'));
        
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        return decrypted;
    }
}

export const encryption = new DataEncryption(secrets.encryptionKey);
```

### ❌ Avoid: Hardcoded secrets

```javascript
// ❌ Never hardcode secrets
const JWT_SECRET = 'my-super-secret-key'; // Never do this!
const API_KEY = 'sk-1234567890abcdef'; // Never do this!
const DATABASE_URL = 'postgres://user:password@localhost/db'; // Never do this!

// ❌ Committing .env files
// .env should be in .gitignore

// ❌ Logging sensitive data
console.log('User password:', password); // Never log passwords
logger.info('API Key:', apiKey); // Never log API keys
```

### Personal Data Handling

### ✅ Good: Privacy-compliant data handling

```javascript
// Data minimization - only collect what you need
const createUserProfile = {
    // ✅ Necessary data
    email: 'required',
    firstName: 'required',
    lastName: 'required',
    
    // ✅ Optional with clear purpose
    dateOfBirth: 'optional', // For age verification
    phone: 'optional', // For account security
    
    // ❌ Don't collect unnecessary data
    // socialSecurityNumber: 'no business need',
    // mothersMaidenName: 'outdated security practice'
};

// Data anonymization for analytics
function anonymizeUserData(user) {
    return {
        id: hashUserId(user.id), // One-way hash for analytics
        ageGroup: getAgeGroup(user.dateOfBirth), // Instead of exact age
        country: user.address?.country, // General location only
        accountType: user.accountType,
        createdAt: user.createdAt,
        // Remove all personally identifiable information
    };
}

// Data retention policies
class DataRetentionManager {
    async cleanupExpiredData() {
        const policies = [
            {
                table: 'user_sessions',
                retentionDays: 30,
                condition: 'expired_at < NOW() - INTERVAL %d DAY'
            },
            {
                table: 'audit_logs',
                retentionDays: 365,
                condition: 'created_at < NOW() - INTERVAL %d DAY'
            },
            {
                table: 'password_reset_tokens',
                retentionDays: 1,
                condition: 'created_at < NOW() - INTERVAL %d DAY'
            }
        ];
        
        for (const policy of policies) {
            await this.deleteExpiredRecords(policy);
        }
    }
    
    async deleteExpiredRecords({ table, retentionDays, condition }) {
        const query = `DELETE FROM ${table} WHERE ${condition}`;
        const result = await database.query(query, [retentionDays]);
        
        logger.info('Cleaned up expired data', {
            table,
            deletedRecords: result.affectedRows,
            retentionDays
        });
    }
}

// GDPR compliance utilities
class GDPRCompliance {
    async exportUserData(userId) {
        const userData = await this.getAllUserData(userId);
        
        return {
            personal: {
                profile: userData.profile,
                preferences: userData.preferences,
                addresses: userData.addresses
            },
            activity: {
                orders: userData.orders.map(order => ({
                    id: order.id,
                    date: order.createdAt,
                    items: order.items,
                    total: order.total
                })),
                loginHistory: userData.loginHistory
            },
            technical: {
                accountCreated: userData.createdAt,
                lastLogin: userData.lastLogin,
                dataProcessingConsent: userData.consents
            }
        };
    }
    
    async deleteUserData(userId, reason) {
        // Log the deletion request
        logger.info('User data deletion requested', {
            userId,
            reason,
            timestamp: new Date()
        });
        
        // Soft delete user account
        await User.update(userId, {
            isDeleted: true,
            deletedAt: new Date(),
            deletionReason: reason
        });
        
        // Anonymize historical data
        await this.anonymizeUserHistory(userId);
        
        // Schedule hard deletion after grace period
        await this.scheduleHardDeletion(userId, 30); // 30 days
    }
}
```

## 🌐 API Security

### Rate Limiting and DDoS Protection

### ✅ Good: Comprehensive rate limiting

```javascript
import { rateLimit } from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import redis from 'redis';

const redisClient = redis.createClient({
    host: process.env.REDIS_HOST,
    port: process.env.REDIS_PORT
});

// Different rate limits for different endpoints
const createRateLimit = (windowMs, max, message) => rateLimit({
    store: new RedisStore({
        sendCommand: (...args) => redisClient.sendCommand(args),
    }),
    windowMs,
    max,
    message: {
        error: message,
        code: 'RATE_LIMIT_EXCEEDED'
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        // Use different keys for authenticated vs anonymous users
        return req.user ? `user:${req.user.id}` : `ip:${req.ip}`;
    }
});

// Apply different limits to different routes
app.use('/api/auth/login', createRateLimit(
    15 * 60 * 1000, // 15 minutes
    5, // 5 attempts
    'Too many login attempts, please try again later'
));

app.use('/api/auth/register', createRateLimit(
    60 * 60 * 1000, // 1 hour
    3, // 3 registrations
    'Too many registration attempts from this IP'
));

app.use('/api/password-reset', createRateLimit(
    60 * 60 * 1000, // 1 hour
    3, // 3 reset requests
    'Too many password reset requests'
));

app.use('/api/', createRateLimit(
    15 * 60 * 1000, // 15 minutes
    100, // 100 requests
    'Too many requests, please slow down'
));

// Advanced rate limiting with different tiers
function tieredRateLimit(req, res, next) {
    const userTier = req.user?.tier || 'free';
    
    const limits = {
        free: { requests: 100, windowMs: 60 * 60 * 1000 }, // 100/hour
        premium: { requests: 1000, windowMs: 60 * 60 * 1000 }, // 1000/hour
        enterprise: { requests: 10000, windowMs: 60 * 60 * 1000 } // 10000/hour
    };
    
    const limit = limits[userTier] || limits.free;
    
    return createRateLimit(
        limit.windowMs,
        limit.requests,
        `Rate limit exceeded for ${userTier} tier`
    )(req, res, next);
}

app.use('/api/data', authenticateToken, tieredRateLimit);
```

### CORS and Security Headers

### ✅ Good: Secure CORS and headers

```javascript
import cors from 'cors';
import helmet from 'helmet';

// Secure CORS configuration
const corsOptions = {
    origin: function (origin, callback) {
        // Allow requests from specific domains
        const allowedOrigins = [
            'https://yourapp.com',
            'https://www.yourapp.com',
            'https://admin.yourapp.com'
        ];
        
        // Allow requests with no origin (mobile apps, Postman, etc.)
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true, // Allow cookies
    optionsSuccessStatus: 200, // Support legacy browsers
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    allowedHeaders: [
        'Content-Type',
        'Authorization',
        'X-Requested-With',
        'X-CSRF-Token'
    ]
};

app.use(cors(corsOptions));

// Security headers with Helmet
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "https:"],
            scriptSrc: ["'self'"],
            connectSrc: ["'self'", "https://api.yourapp.com"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"],
            frameAncestors: ["'none'"]
        }
    },
    hsts: {
        maxAge: 31536000, // 1 year
        includeSubDomains: true,
        preload: true
    }
}));

// Additional security headers
app.use((req, res, next) => {
    // Prevent MIME type sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');
    
    // Prevent clickjacking
    res.setHeader('X-Frame-Options', 'DENY');
    
    // Enable XSS protection
    res.setHeader('X-XSS-Protection', '1; mode=block');
    
    // Referrer policy
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    next();
});
```

## 🔍 Security Monitoring

### Audit Logging

### ✅ Good: Comprehensive audit logging

```javascript
class SecurityAuditLogger {
    constructor(logger) {
        this.logger = logger;
    }
    
    logAuthEvent(event, userId, details = {}) {
        this.logger.info('Security Event', {
            category: 'authentication',
            event: event,
            userId: userId,
            ip: details.ip,
            userAgent: details.userAgent,
            timestamp: new Date(),
            success: details.success,
            reason: details.reason
        });
    }
    
    logDataAccess(userId, resource, action, details = {}) {
        this.logger.info('Data Access', {
            category: 'data_access',
            userId: userId,
            resource: resource,
            action: action,
            ip: details.ip,
            timestamp: new Date(),
            success: details.success,
            recordCount: details.recordCount
        });
    }
    
    logPrivilegeEscalation(userId, fromRole, toRole, adminId) {
        this.logger.warn('Privilege Change', {
            category: 'privilege_escalation',
            userId: userId,
            fromRole: fromRole,
            toRole: toRole,
            adminId: adminId,
            timestamp: new Date()
        });
    }
    
    logSuspiciousActivity(type, details) {
        this.logger.warn('Suspicious Activity', {
            category: 'security_alert',
            type: type,
            ...details,
            timestamp: new Date()
        });
    }
}

// Usage in middleware
function auditMiddleware(req, res, next) {
    res.on('finish', () => {
        if (req.user) {
            auditLogger.logDataAccess(req.user.id, req.route.path, req.method, {
                ip: req.ip,
                success: res.statusCode < 400,
                recordCount: res.locals.recordCount
            });
        }
    });
    next();
}
```

## ✅ Quick Checklist

- [ ] Passwords are hashed with strong algorithms (bcrypt, Argon2)
- [ ] JWT tokens are properly secured and have appropriate expiration
- [ ] All inputs are validated and sanitized
- [ ] Parameterized queries prevent SQL injection
- [ ] Rate limiting protects against abuse
- [ ] CORS is properly configured for your domains
- [ ] Security headers are set (CSP, HSTS, etc.)
- [ ] Secrets are stored in environment variables, not code
- [ ] Sensitive data is encrypted at rest
- [ ] Audit logging captures security events
- [ ] Data retention policies comply with privacy laws
- [ ] GDPR/privacy rights are implemented (export, delete)
- [ ] Error messages don't reveal sensitive information

---

**Next:** [Performance](./performance.md)
