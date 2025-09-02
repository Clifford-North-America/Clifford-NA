# Error Handling & Logging

Proper error handling makes applications robust and debuggable. Good logging provides insights into application behavior and helps diagnose issues in production.

## 🎯 Core Principles

1. **Fail Fast and Clearly** - Detect and report errors as early as possible
2. **Provide Meaningful Messages** - Help users and developers understand what went wrong
3. **Log Strategically** - Capture important events without creating noise
4. **Protect Sensitive Data** - Never expose secrets or personal information in logs

## 🚨 Error Handling Patterns

### Handle Errors Gracefully

#### ✅ Good: Descriptive error handling

```javascript
async function createUserAccount(userData) {
    try {
        // Validate input data
        if (!userData.email) {
            throw new ValidationError('Email address is required', {
                field: 'email',
                code: 'MISSING_REQUIRED_FIELD'
            });
        }
        
        if (!isValidEmail(userData.email)) {
            throw new ValidationError('Email address format is invalid', {
                field: 'email',
                value: userData.email,
                code: 'INVALID_EMAIL_FORMAT'
            });
        }
        
        // Check for existing user
        const existingUser = await userRepository.findByEmail(userData.email);
        if (existingUser) {
            throw new ConflictError('An account with this email already exists', {
                email: userData.email,
                code: 'DUPLICATE_EMAIL'
            });
        }
        
        // Create the user
        const hashedPassword = await hashPassword(userData.password);
        const newUser = await userRepository.create({
            ...userData,
            password: hashedPassword,
            createdAt: new Date()
        });
        
        // Send welcome email
        try {
            await emailService.sendWelcomeEmail(newUser);
        } catch (emailError) {
            // Log the email error but don't fail the user creation
            logger.warn('Failed to send welcome email', {
                userId: newUser.id,
                email: newUser.email,
                error: emailError.message
            });
        }
        
        return newUser;
        
    } catch (error) {
        // Log the error with context
        logger.error('Failed to create user account', {
            email: userData.email,
            error: error.message,
            stack: error.stack
        });
        
        // Re-throw to let the caller handle it
        throw error;
    }
}
```

#### ❌ Avoid: Silent failures and vague errors

```javascript
async function createUserAccount(userData) {
    try {
        // No input validation
        const user = await userRepository.create(userData);
        emailService.sendWelcomeEmail(user); // No error handling
        return user;
    } catch (error) {
        console.log('Error'); // Vague message, no context
        return null; // Silent failure - caller doesn't know what happened
    }
}
```

### Custom Error Classes

Create specific error types for different scenarios:

```javascript
// errors/BaseError.js
export class BaseError extends Error {
    constructor(message, details = {}) {
        super(message);
        this.name = this.constructor.name;
        this.details = details;
        this.timestamp = new Date().toISOString();
        
        // Capture stack trace
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, this.constructor);
        }
    }
    
    toJSON() {
        return {
            name: this.name,
            message: this.message,
            details: this.details,
            timestamp: this.timestamp
        };
    }
}

// errors/ValidationError.js
export class ValidationError extends BaseError {
    constructor(message, details = {}) {
        super(message, details);
        this.statusCode = 400;
    }
}

// errors/NotFoundError.js
export class NotFoundError extends BaseError {
    constructor(message, details = {}) {
        super(message, details);
        this.statusCode = 404;
    }
}

// errors/ConflictError.js
export class ConflictError extends BaseError {
    constructor(message, details = {}) {
        super(message, details);
        this.statusCode = 409;
    }
}

// errors/AuthenticationError.js
export class AuthenticationError extends BaseError {
    constructor(message, details = {}) {
        super(message, details);
        this.statusCode = 401;
    }
}
```

### Error Handling in Express.js

```javascript
// middleware/errorHandler.js
import { BaseError } from '../errors/BaseError.js';
import { logger } from '../utils/logger.js';

export function errorHandler(error, req, res, next) {
    // Log the error
    logger.error('Request failed', {
        method: req.method,
        url: req.url,
        userAgent: req.get('User-Agent'),
        ip: req.ip,
        error: error.message,
        stack: error.stack
    });
    
    // Handle known error types
    if (error instanceof BaseError) {
        return res.status(error.statusCode).json({
            success: false,
            error: {
                message: error.message,
                code: error.details.code,
                details: error.details
            }
        });
    }
    
    // Handle specific types of errors
    if (error.name === 'ValidationError') {
        return res.status(400).json({
            success: false,
            error: {
                message: 'Validation failed',
                details: error.details
            }
        });
    }
    
    if (error.code === 'ECONNREFUSED') {
        return res.status(503).json({
            success: false,
            error: {
                message: 'Service temporarily unavailable',
                code: 'SERVICE_UNAVAILABLE'
            }
        });
    }
    
    // Default to 500 for unknown errors
    res.status(500).json({
        success: false,
        error: {
            message: 'An internal server error occurred',
            code: 'INTERNAL_SERVER_ERROR'
        }
    });
}

// Usage in routes
app.use('/api', routes);
app.use(errorHandler);
```

## 📊 Structured Logging

### Logger Configuration

```javascript
// utils/logger.js
import winston from 'winston';

const logLevel = process.env.LOG_LEVEL || 'info';
const isProduction = process.env.NODE_ENV === 'production';

// Custom format for structured logging
const logFormat = winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json(),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
        return JSON.stringify({
            timestamp,
            level,
            message,
            ...meta
        });
    })
);

export const logger = winston.createLogger({
    level: logLevel,
    format: logFormat,
    defaultMeta: {
        service: 'user-service',
        version: process.env.APP_VERSION || 'unknown'
    },
    transports: [
        // Console transport for development
        new winston.transports.Console({
            format: isProduction 
                ? logFormat 
                : winston.format.combine(
                    winston.format.colorize(),
                    winston.format.simple()
                )
        }),
        
        // File transport for production
        ...(isProduction ? [
            new winston.transports.File({
                filename: 'logs/error.log',
                level: 'error',
                maxsize: 5242880, // 5MB
                maxFiles: 10
            }),
            new winston.transports.File({
                filename: 'logs/combined.log',
                maxsize: 5242880, // 5MB
                maxFiles: 10
            })
        ] : [])
    ]
});
```

### Effective Logging Patterns

#### ✅ Good: Structured, informative logging

```javascript
class OrderService {
    async processOrder(userId, orderData) {
        const correlationId = generateCorrelationId();
        
        logger.info('Order processing started', {
            correlationId,
            userId,
            orderValue: orderData.total,
            itemCount: orderData.items.length
        });
        
        try {
            // Validate user
            const user = await this.getUserById(userId);
            if (!user) {
                throw new NotFoundError('User not found', { userId });
            }
            
            logger.debug('User validation completed', {
                correlationId,
                userId,
                userStatus: user.status
            });
            
            // Process payment
            const paymentResult = await this.processPayment(orderData.payment);
            
            logger.info('Payment processed successfully', {
                correlationId,
                userId,
                paymentId: paymentResult.id,
                amount: paymentResult.amount
            });
            
            // Create order
            const order = await this.createOrder(userId, orderData, paymentResult);
            
            logger.info('Order processing completed', {
                correlationId,
                userId,
                orderId: order.id,
                status: order.status,
                processingTimeMs: Date.now() - startTime
            });
            
            return order;
            
        } catch (error) {
            logger.error('Order processing failed', {
                correlationId,
                userId,
                error: error.message,
                errorCode: error.details?.code,
                stack: error.stack
            });
            
            throw error;
        }
    }
    
    async processPayment(paymentData) {
        const startTime = Date.now();
        
        try {
            const result = await paymentGateway.charge(paymentData);
            
            logger.info('Payment gateway request completed', {
                paymentGateway: 'stripe',
                amount: paymentData.amount,
                currency: paymentData.currency,
                responseTime: Date.now() - startTime,
                success: true
            });
            
            return result;
            
        } catch (error) {
            logger.warn('Payment gateway request failed', {
                paymentGateway: 'stripe',
                amount: paymentData.amount,
                currency: paymentData.currency,
                responseTime: Date.now() - startTime,
                error: error.message,
                errorCode: error.code
            });
            
            throw new PaymentError('Payment processing failed', {
                gateway: 'stripe',
                code: error.code,
                originalError: error.message
            });
        }
    }
}
```

### Log Levels and When to Use Them

```javascript
// ERROR: System errors, exceptions, failures
logger.error('Database connection failed', {
    database: 'users',
    host: config.db.host,
    error: error.message
});

// WARN: Recoverable problems, deprecated usage, unusual conditions
logger.warn('API rate limit approaching', {
    currentRequests: 450,
    limit: 500,
    resetTime: new Date(resetTimestamp)
});

// INFO: Important business events, major state changes
logger.info('User registered successfully', {
    userId: user.id,
    email: user.email,
    registrationMethod: 'email'
});

// DEBUG: Detailed information for troubleshooting
logger.debug('Cache hit for user preferences', {
    userId: user.id,
    cacheKey: cacheKey,
    hitRate: cache.getHitRate()
});

// VERBOSE/TRACE: Very detailed execution information
logger.verbose('SQL query executed', {
    query: 'SELECT * FROM users WHERE id = ?',
    params: [userId],
    executionTime: 23
});
```

## 🔒 Security in Error Handling

### Protect Sensitive Information

#### ✅ Good: Safe error responses

```javascript
async function authenticateUser(email, password) {
    try {
        const user = await userRepository.findByEmail(email);
        
        if (!user) {
            // Don't reveal whether the email exists
            throw new AuthenticationError('Invalid email or password', {
                code: 'INVALID_CREDENTIALS'
            });
        }
        
        const isPasswordValid = await bcrypt.compare(password, user.hashedPassword);
        
        if (!isPasswordValid) {
            // Log the attempt for security monitoring
            logger.warn('Failed login attempt', {
                email: email,
                ip: request.ip,
                userAgent: request.get('User-Agent'),
                timestamp: new Date()
            });
            
            throw new AuthenticationError('Invalid email or password', {
                code: 'INVALID_CREDENTIALS'
            });
        }
        
        return user;
        
    } catch (error) {
        // Log internal errors but don't expose them
        if (!(error instanceof AuthenticationError)) {
            logger.error('Authentication system error', {
                email: email,
                error: error.message,
                stack: error.stack
            });
            
            // Return generic error to user
            throw new AuthenticationError('Authentication failed', {
                code: 'AUTH_SYSTEM_ERROR'
            });
        }
        
        throw error;
    }
}
```

#### ❌ Avoid: Exposing sensitive details

```javascript
async function authenticateUser(email, password) {
    const user = await userRepository.findByEmail(email);
    
    if (!user) {
        throw new Error(`No user found with email: ${email}`); // Reveals if email exists
    }
    
    if (!bcrypt.compare(password, user.hashedPassword)) {
        throw new Error(`Password hash ${user.hashedPassword} does not match`); // Exposes hash
    }
}
```

### Sanitize Error Messages

```javascript
function sanitizeError(error, isProduction = false) {
    const sanitized = {
        message: error.message,
        code: error.code,
        timestamp: new Date().toISOString()
    };
    
    // In development, include more details
    if (!isProduction) {
        sanitized.stack = error.stack;
        sanitized.details = error.details;
    }
    
    // Remove sensitive patterns
    if (sanitized.message) {
        sanitized.message = sanitized.message
            .replace(/password=\w+/gi, 'password=***')
            .replace(/token=[\w-]+/gi, 'token=***')
            .replace(/key=[\w-]+/gi, 'key=***')
            .replace(/secret=[\w-]+/gi, 'secret=***');
    }
    
    return sanitized;
}
```

## 🔄 Retry Logic and Circuit Breakers

### Implementing Retry Logic

```javascript
async function withRetry(operation, options = {}) {
    const {
        maxAttempts = 3,
        baseDelay = 1000,
        maxDelay = 10000,
        backoffMultiplier = 2,
        retryCondition = (error) => error.isRetryable
    } = options;
    
    let lastError;
    
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        try {
            return await operation();
        } catch (error) {
            lastError = error;
            
            if (attempt === maxAttempts || !retryCondition(error)) {
                logger.error('Operation failed after all retry attempts', {
                    operation: operation.name,
                    attempts: attempt,
                    error: error.message
                });
                throw error;
            }
            
            const delay = Math.min(
                baseDelay * Math.pow(backoffMultiplier, attempt - 1),
                maxDelay
            );
            
            logger.warn('Operation failed, retrying', {
                operation: operation.name,
                attempt: attempt,
                nextRetryIn: delay,
                error: error.message
            });
            
            await new Promise(resolve => setTimeout(resolve, delay));
        }
    }
    
    throw lastError;
}

// Usage
const result = await withRetry(
    () => externalAPI.fetchData(userId),
    {
        maxAttempts: 3,
        retryCondition: (error) => error.status >= 500 || error.code === 'NETWORK_ERROR'
    }
);
```

## 📝 Error Documentation

### API Error Response Format

```javascript
// Standardized error response format
{
    "success": false,
    "error": {
        "code": "VALIDATION_FAILED",
        "message": "The request data is invalid",
        "details": {
            "field": "email",
            "value": "invalid-email",
            "constraint": "Must be a valid email address"
        }
    },
    "timestamp": "2024-01-15T10:30:00Z",
    "requestId": "req_abc123xyz"
}
```

### Error Code Documentation

```markdown
## Error Codes

### Authentication Errors (AUTH_*)
- `AUTH_INVALID_CREDENTIALS` - Email or password is incorrect
- `AUTH_TOKEN_EXPIRED` - Authentication token has expired
- `AUTH_TOKEN_INVALID` - Authentication token is malformed or invalid
- `AUTH_INSUFFICIENT_PERMISSIONS` - User lacks required permissions

### Validation Errors (VALIDATION_*)
- `VALIDATION_REQUIRED_FIELD` - A required field is missing
- `VALIDATION_INVALID_FORMAT` - Field format is invalid (e.g., email format)
- `VALIDATION_OUT_OF_RANGE` - Value is outside acceptable range

### Business Logic Errors (BUSINESS_*)
- `BUSINESS_INSUFFICIENT_FUNDS` - User account balance is too low
- `BUSINESS_ITEM_OUT_OF_STOCK` - Requested item is not available
- `BUSINESS_DUPLICATE_ORDER` - Order has already been placed

### System Errors (SYSTEM_*)
- `SYSTEM_DATABASE_ERROR` - Database operation failed
- `SYSTEM_EXTERNAL_SERVICE_ERROR` - External service is unavailable
- `SYSTEM_RATE_LIMIT_EXCEEDED` - Too many requests in time window
```

## ✅ Quick Checklist

- [ ] Errors include meaningful, user-friendly messages
- [ ] Sensitive information is never exposed in error messages
- [ ] Errors are logged with appropriate context and level
- [ ] Custom error types are used for different scenarios
- [ ] Retry logic is implemented for transient failures
- [ ] Error responses follow a consistent format
- [ ] Log messages include correlation IDs for request tracing
- [ ] Different log levels are used appropriately
- [ ] Errors don't reveal system internals to end users
- [ ] Error handling doesn't silently fail

---

**Next:** [Version Control](./version-control.md)
