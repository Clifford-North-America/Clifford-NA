# Code Organization

Well-organized code is easier to understand, maintain, and debug. Good organization follows clear patterns and groups related functionality together.

## 🎯 Core Principles

1. **Single Responsibility** - Each function/class should have one clear purpose
2. **Logical Grouping** - Related code should be physically close
3. **Consistent Structure** - Follow established patterns throughout the project
4. **Clear Hierarchy** - Organize from general to specific, public to private

## 🏗️ Function Organization

### Keep Functions Small and Focused

#### ✅ Good Example

```javascript
// Each function has a single, clear responsibility
function validateEmailFormat(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function checkEmailExists(email) {
    return users.some(user => user.email === email);
}

function createUserAccount(email, password) {
    if (!validateEmailFormat(email)) {
        throw new Error('Invalid email format');
    }
    
    if (checkEmailExists(email)) {
        throw new Error('Email already exists');
    }
    
    return {
        id: generateId(),
        email: email,
        password: hashPassword(password),
        createdAt: new Date()
    };
}
```

#### ❌ Avoid: Monolithic Functions

```javascript
// Too many responsibilities in one function
function processUser(email, password, profileData) {
    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        throw new Error('Invalid email');
    }
    
    // Check if exists
    for (let i = 0; i < users.length; i++) {
        if (users[i].email === email) {
            throw new Error('Email exists');
        }
    }
    
    // Hash password
    const salt = generateSalt();
    const hashedPassword = hash(password + salt);
    
    // Validate profile
    if (!profileData.firstName || profileData.firstName.length < 2) {
        throw new Error('Invalid first name');
    }
    
    // Create user... (continues for 50+ lines)
}
```

### Function Ordering

Organize functions from high-level to low-level (top-down approach):

```javascript
// ✅ Good: High-level function first
function processUserRegistration(registrationData) {
    const validatedData = validateRegistrationData(registrationData);
    const user = createUser(validatedData);
    const welcome = sendWelcomeEmail(user);
    return { user, emailSent: welcome };
}

function validateRegistrationData(data) {
    validateEmail(data.email);
    validatePassword(data.password);
    validateProfile(data.profile);
    return data;
}

function createUser(userData) {
    // User creation logic
}

function sendWelcomeEmail(user) {
    // Email sending logic
}

// Low-level utility functions
function validateEmail(email) {
    // Detailed email validation
}

function validatePassword(password) {
    // Detailed password validation
}
```

## 📁 File and Directory Structure

### Logical Grouping by Feature

#### ✅ Good: Feature-based Organization

```text
src/
├── components/
│   ├── user/
│   │   ├── UserProfile.js
│   │   ├── UserSettings.js
│   │   └── UserList.js
│   ├── payment/
│   │   ├── PaymentForm.js
│   │   ├── PaymentHistory.js
│   │   └── PaymentProcessor.js
│   └── common/
│       ├── Button.js
│       ├── Modal.js
│       └── LoadingSpinner.js
├── services/
│   ├── userService.js
│   ├── paymentService.js
│   └── emailService.js
├── utils/
│   ├── validation.js
│   ├── formatting.js
│   └── constants.js
└── config/
    ├── database.js
    ├── api.js
    └── environment.js
```

#### ❌ Avoid: Technical-only Grouping

```text
src/
├── controllers/
│   ├── UserController.js
│   ├── PaymentController.js
│   ├── EmailController.js
│   └── OrderController.js
├── models/
│   ├── User.js
│   ├── Payment.js
│   ├── Email.js
│   └── Order.js
├── views/
│   ├── UserView.js
│   ├── PaymentView.js
│   └── OrderView.js
└── helpers/
    └── (everything else mixed together)
```

### Project Architecture Patterns

#### MVC (Model-View-Controller)

```text
src/
├── models/
│   ├── User.js          // Data structure and business logic
│   ├── Product.js
│   └── Order.js
├── views/
│   ├── UserView.js      // UI components and templates
│   ├── ProductView.js
│   └── OrderView.js
├── controllers/
│   ├── UserController.js // Request handling and coordination
│   ├── ProductController.js
│   └── OrderController.js
└── routes/
    ├── userRoutes.js    // URL routing configuration
    ├── productRoutes.js
    └── orderRoutes.js
```

#### Layered Architecture

```text
src/
├── presentation/        // UI layer
│   ├── components/
│   ├── pages/
│   └── layouts/
├── business/           // Business logic layer
│   ├── services/
│   ├── validators/
│   └── processors/
├── data/              // Data access layer
│   ├── repositories/
│   ├── models/
│   └── migrations/
└── infrastructure/    // External concerns
    ├── config/
    ├── logging/
    └── security/
```

## 🔧 Class Organization

### Class Structure Order

```javascript
class UserService {
    // 1. Static properties and methods
    static DEFAULT_ROLE = 'user';
    static validateId(id) { /* validation logic */ }
    
    // 2. Instance properties
    constructor(database, emailService) {
        this.database = database;
        this.emailService = emailService;
        this.cache = new Map();
    }
    
    // 3. Public methods (most important first)
    async createUser(userData) {
        const validatedData = this._validateUserData(userData);
        const user = await this.database.users.create(validatedData);
        await this._sendWelcomeEmail(user);
        return user;
    }
    
    async getUserById(id) {
        UserService.validateId(id);
        return this._getCachedUser(id) || await this._fetchUser(id);
    }
    
    // 4. Private methods (helpers)
    _validateUserData(userData) {
        // Validation logic
    }
    
    _sendWelcomeEmail(user) {
        // Email logic
    }
    
    _getCachedUser(id) {
        // Cache logic
    }
    
    _fetchUser(id) {
        // Database fetch logic
    }
}
```

## 📋 Configuration Management

### Centralized Configuration

```javascript
// config/index.js
const config = {
    database: {
        host: process.env.DB_HOST || 'localhost',
        port: process.env.DB_PORT || 5432,
        name: process.env.DB_NAME || 'app_db'
    },
    
    api: {
        port: process.env.PORT || 3000,
        timeout: 30000,
        rateLimit: {
            windowMs: 15 * 60 * 1000, // 15 minutes
            max: 100 // requests per window
        }
    },
    
    email: {
        provider: process.env.EMAIL_PROVIDER || 'sendgrid',
        apiKey: process.env.EMAIL_API_KEY,
        fromAddress: process.env.FROM_EMAIL || 'noreply@app.com'
    }
};

export default config;
```

### Constants Organization

```javascript
// utils/constants.js
export const USER_ROLES = {
    ADMIN: 'admin',
    MODERATOR: 'moderator',
    USER: 'user'
};

export const ORDER_STATUS = {
    PENDING: 'pending',
    PROCESSING: 'processing',
    SHIPPED: 'shipped',
    DELIVERED: 'delivered',
    CANCELLED: 'cancelled'
};

export const VALIDATION_RULES = {
    EMAIL_MAX_LENGTH: 255,
    PASSWORD_MIN_LENGTH: 8,
    USERNAME_MIN_LENGTH: 3,
    USERNAME_MAX_LENGTH: 30
};

export const ERROR_CODES = {
    VALIDATION_FAILED: 'VALIDATION_FAILED',
    UNAUTHORIZED: 'UNAUTHORIZED',
    NOT_FOUND: 'NOT_FOUND',
    INTERNAL_ERROR: 'INTERNAL_ERROR'
};
```

## 🔄 Import Organization

### Import Grouping and Ordering

```javascript
// 1. Third-party libraries
import React from 'react';
import { Router } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

// 2. Internal modules (absolute imports)
import { UserService } from '@/services/UserService';
import { EmailService } from '@/services/EmailService';
import { validateRequest } from '@/middleware/validation';

// 3. Relative imports (same directory/subdirectories)
import { hashPassword } from './utils/crypto';
import { sendWelcomeEmail } from './email/templates';
import UserModel from './models/User';

// 4. Configuration and constants
import config from '@/config';
import { USER_ROLES, ERROR_CODES } from '@/utils/constants';
```

## 🗂️ Module Pattern Examples

### Service Module

```javascript
// services/UserService.js
import { validateEmail, validatePassword } from '@/utils/validation';
import { hashPassword } from '@/utils/crypto';
import UserModel from '@/models/User';

class UserService {
    constructor(database, emailService) {
        this.database = database;
        this.emailService = emailService;
    }
    
    async registerUser(userData) {
        await this._validateUserData(userData);
        const hashedPassword = await hashPassword(userData.password);
        
        const user = await UserModel.create({
            ...userData,
            password: hashedPassword
        });
        
        await this.emailService.sendWelcomeEmail(user);
        return user;
    }
    
    // Private methods
    async _validateUserData(userData) {
        if (!validateEmail(userData.email)) {
            throw new Error('Invalid email format');
        }
        
        if (!validatePassword(userData.password)) {
            throw new Error('Password does not meet requirements');
        }
        
        const existingUser = await UserModel.findByEmail(userData.email);
        if (existingUser) {
            throw new Error('Email already registered');
        }
    }
}

export default UserService;
```

### Utility Module

```javascript
// utils/validation.js
export function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

export function validatePassword(password) {
    return password &&
           password.length >= 8 &&
           /[A-Z]/.test(password) &&
           /[a-z]/.test(password) &&
           /\d/.test(password);
}

export function validatePhoneNumber(phone) {
    const phoneRegex = /^\+?[\d\s\-\(\)]+$/;
    return phoneRegex.test(phone) && phone.replace(/\D/g, '').length >= 10;
}

export function sanitizeInput(input) {
    return input.trim().replace(/[<>]/g, '');
}
```

## ✅ Quick Checklist

- [ ] Functions are small and have single responsibility
- [ ] Related functionality is grouped together
- [ ] Files follow consistent naming patterns
- [ ] Directory structure reflects application architecture
- [ ] Configuration is centralized and environment-aware
- [ ] Constants are organized by domain
- [ ] Imports are grouped and ordered logically
- [ ] Public APIs are clearly separated from private implementation
- [ ] Code flows from high-level to low-level functions

---

**Next:** [Comments & Documentation](./comments-documentation.md)
