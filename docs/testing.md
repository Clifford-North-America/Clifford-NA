# Testing

Good tests are your safety net. They catch bugs early, document expected behavior, and give you confidence to refactor and add new features.

## 🎯 Core Principles

1. **Test Behavior, Not Implementation** - Focus on what the code does, not how it does it
2. **Independent Tests** - Each test should run in isolation
3. **Clear and Descriptive** - Test names should explain what is being tested
4. **Fast and Reliable** - Tests should run quickly and consistently

## 🧪 Types of Tests

### Unit Tests

Test individual functions or methods in isolation:

### ✅ Good Unit Test Example

```javascript
// userService.test.js
import { describe, it, expect, beforeEach } from '@jest/globals';
import { UserService } from '../src/services/UserService.js';

describe('UserService', () => {
    let userService;
    let mockDatabase;
    let mockEmailService;
    
    beforeEach(() => {
        // Set up fresh mocks for each test
        mockDatabase = {
            users: {
                create: jest.fn(),
                findByEmail: jest.fn(),
                findById: jest.fn()
            }
        };
        
        mockEmailService = {
            sendWelcomeEmail: jest.fn()
        };
        
        userService = new UserService(mockDatabase, mockEmailService);
    });
    
    describe('createUser', () => {
        it('should create a user with valid data', async () => {
            // Arrange
            const userData = {
                email: 'test@example.com',
                password: 'securePassword123',
                firstName: 'John',
                lastName: 'Doe'
            };
            
            const expectedUser = { id: 1, ...userData };
            mockDatabase.users.findByEmail.mockResolvedValue(null); // No existing user
            mockDatabase.users.create.mockResolvedValue(expectedUser);
            
            // Act
            const result = await userService.createUser(userData);
            
            // Assert
            expect(result).toEqual(expectedUser);
            expect(mockDatabase.users.create).toHaveBeenCalledWith(
                expect.objectContaining({
                    email: userData.email,
                    firstName: userData.firstName,
                    lastName: userData.lastName
                })
            );
            expect(mockEmailService.sendWelcomeEmail).toHaveBeenCalledWith(expectedUser);
        });
        
        it('should throw error when email already exists', async () => {
            // Arrange
            const userData = {
                email: 'existing@example.com',
                password: 'password123',
                firstName: 'Jane'
            };
            
            mockDatabase.users.findByEmail.mockResolvedValue({ id: 1, email: userData.email });
            
            // Act & Assert
            await expect(userService.createUser(userData)).rejects.toThrow('Email already exists');
            expect(mockDatabase.users.create).not.toHaveBeenCalled();
            expect(mockEmailService.sendWelcomeEmail).not.toHaveBeenCalled();
        });
        
        it('should throw error when email format is invalid', async () => {
            // Arrange
            const userData = {
                email: 'invalid-email',
                password: 'password123',
                firstName: 'Jane'
            };
            
            // Act & Assert
            await expect(userService.createUser(userData)).rejects.toThrow('Invalid email format');
            expect(mockDatabase.users.findByEmail).not.toHaveBeenCalled();
        });
    });
    
    describe('getUserById', () => {
        it('should return user when found', async () => {
            // Arrange
            const userId = 1;
            const expectedUser = { id: userId, email: 'test@example.com' };
            mockDatabase.users.findById.mockResolvedValue(expectedUser);
            
            // Act
            const result = await userService.getUserById(userId);
            
            // Assert
            expect(result).toEqual(expectedUser);
            expect(mockDatabase.users.findById).toHaveBeenCalledWith(userId);
        });
        
        it('should return null when user not found', async () => {
            // Arrange
            const userId = 999;
            mockDatabase.users.findById.mockResolvedValue(null);
            
            // Act
            const result = await userService.getUserById(userId);
            
            // Assert
            expect(result).toBeNull();
        });
    });
});
```

### Integration Tests

Test how multiple components work together:

### ✅ Good Integration Test Example

```javascript
// userRegistration.integration.test.js
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import request from 'supertest';
import { app } from '../src/app.js';
import { database } from '../src/config/database.js';

describe('User Registration Integration', () => {
    beforeEach(async () => {
        // Set up test database
        await database.migrate.latest();
        await database.seed.run();
    });
    
    afterEach(async () => {
        // Clean up test database
        await database.migrate.rollback();
    });
    
    it('should successfully register a new user', async () => {
        // Arrange
        const newUser = {
            email: 'newuser@example.com',
            password: 'securePassword123',
            firstName: 'New',
            lastName: 'User'
        };
        
        // Act
        const response = await request(app)
            .post('/api/auth/register')
            .send(newUser)
            .expect(201);
        
        // Assert
        expect(response.body).toMatchObject({
            success: true,
            user: {
                email: newUser.email,
                firstName: newUser.firstName,
                lastName: newUser.lastName
            }
        });
        expect(response.body.user.password).toBeUndefined(); // Password should not be returned
        
        // Verify user was created in database
        const createdUser = await database('users').where({ email: newUser.email }).first();
        expect(createdUser).toBeDefined();
        expect(createdUser.email).toBe(newUser.email);
    });
    
    it('should handle registration with duplicate email', async () => {
        // Arrange
        const existingUser = {
            email: 'existing@example.com',
            password: 'password123',
            firstName: 'Existing',
            lastName: 'User'
        };
        
        // Create user first
        await request(app)
            .post('/api/auth/register')
            .send(existingUser)
            .expect(201);
        
        // Act - Try to register with same email
        const response = await request(app)
            .post('/api/auth/register')
            .send(existingUser)
            .expect(409);
        
        // Assert
        expect(response.body).toMatchObject({
            success: false,
            error: 'Email already exists'
        });
    });
});
```

## 📊 Test Structure Patterns

### AAA Pattern (Arrange, Act, Assert)

Structure your tests clearly:

```javascript
it('should calculate order total with tax', () => {
    // Arrange - Set up test data
    const order = {
        items: [
            { price: 10.00, quantity: 2 },
            { price: 15.00, quantity: 1 }
        ]
    };
    const taxRate = 0.08;
    
    // Act - Execute the function being tested
    const result = calculateOrderTotal(order, taxRate);
    
    // Assert - Verify the results
    expect(result.subtotal).toBe(35.00);
    expect(result.tax).toBe(2.80);
    expect(result.total).toBe(37.80);
});
```

### Descriptive Test Names

Use descriptive names that explain the scenario:

### ✅ Good: Descriptive test names

```javascript
describe('Password Validation', () => {
    it('should accept password with uppercase, lowercase, number and special character', () => {
        // Test implementation
    });
    
    it('should reject password shorter than 8 characters', () => {
        // Test implementation
    });
    
    it('should reject password without uppercase letter', () => {
        // Test implementation
    });
    
    it('should reject password that is a common password', () => {
        // Test implementation
    });
});
```

### ❌ Avoid: Vague test names

```javascript
describe('Password Validation', () => {
    it('should work', () => {
        // What does "work" mean?
    });
    
    it('test password', () => {
        // What about password?
    });
    
    it('should return true', () => {
        // When should it return true?
    });
});
```

## 🎭 Mocking and Test Doubles

### Mock External Dependencies

```javascript
// paymentService.test.js
import { PaymentService } from '../src/services/PaymentService.js';

describe('PaymentService', () => {
    let paymentService;
    let mockPaymentGateway;
    let mockDatabase;
    
    beforeEach(() => {
        mockPaymentGateway = {
            charge: jest.fn(),
            refund: jest.fn()
        };
        
        mockDatabase = {
            transactions: {
                create: jest.fn(),
                update: jest.fn()
            }
        };
        
        paymentService = new PaymentService(mockPaymentGateway, mockDatabase);
    });
    
    it('should process payment successfully', async () => {
        // Arrange
        const paymentData = {
            amount: 100.00,
            currency: 'USD',
            cardToken: 'tok_test_card'
        };
        
        const gatewayResponse = {
            id: 'ch_test_charge',
            status: 'succeeded',
            amount: 10000 // Gateway returns amount in cents
        };
        
        mockPaymentGateway.charge.mockResolvedValue(gatewayResponse);
        mockDatabase.transactions.create.mockResolvedValue({ id: 1 });
        
        // Act
        const result = await paymentService.processPayment(paymentData);
        
        // Assert
        expect(result.success).toBe(true);
        expect(mockPaymentGateway.charge).toHaveBeenCalledWith({
            amount: 10000, // Service should convert to cents
            currency: 'USD',
            source: 'tok_test_card'
        });
        expect(mockDatabase.transactions.create).toHaveBeenCalledWith(
            expect.objectContaining({
                gatewayId: 'ch_test_charge',
                amount: 100.00,
                status: 'completed'
            })
        );
    });
    
    it('should handle payment gateway failure', async () => {
        // Arrange
        const paymentData = {
            amount: 100.00,
            currency: 'USD',
            cardToken: 'tok_test_card'
        };
        
        const gatewayError = new Error('Card declined');
        mockPaymentGateway.charge.mockRejectedValue(gatewayError);
        
        // Act
        const result = await paymentService.processPayment(paymentData);
        
        // Assert
        expect(result.success).toBe(false);
        expect(result.error).toBe('Card declined');
        expect(mockDatabase.transactions.create).toHaveBeenCalledWith(
            expect.objectContaining({
                status: 'failed',
                errorMessage: 'Card declined'
            })
        );
    });
});
```

## 🎯 Test Coverage Guidelines

### Focus on Critical Logic

```javascript
// Example: Testing edge cases for a discount calculator
describe('DiscountCalculator', () => {
    const calculator = new DiscountCalculator();
    
    // Test the happy path
    it('should apply 10% discount for orders over $100', () => {
        const result = calculator.calculateDiscount(150, 'SAVE10');
        expect(result.discountAmount).toBe(15);
        expect(result.finalAmount).toBe(135);
    });
    
    // Test edge cases
    it('should not apply discount for orders exactly at minimum threshold', () => {
        const result = calculator.calculateDiscount(100, 'SAVE10');
        expect(result.discountAmount).toBe(0);
        expect(result.finalAmount).toBe(100);
    });
    
    it('should cap discount at maximum amount', () => {
        const result = calculator.calculateDiscount(10000, 'SAVE10');
        expect(result.discountAmount).toBe(500); // Max discount is $500
        expect(result.finalAmount).toBe(9500);
    });
    
    // Test error conditions
    it('should throw error for invalid discount code', () => {
        expect(() => {
            calculator.calculateDiscount(150, 'INVALID');
        }).toThrow('Invalid discount code');
    });
    
    it('should throw error for negative order amount', () => {
        expect(() => {
            calculator.calculateDiscount(-50, 'SAVE10');
        }).toThrow('Order amount must be positive');
    });
});
```

### Test Data Builders for Complex Objects

```javascript
// testUtils/builders.js
export class UserBuilder {
    constructor() {
        this.user = {
            id: 1,
            email: 'test@example.com',
            firstName: 'Test',
            lastName: 'User',
            isActive: true,
            role: 'user',
            createdAt: new Date(),
            preferences: {
                theme: 'light',
                notifications: true
            }
        };
    }
    
    withEmail(email) {
        this.user.email = email;
        return this;
    }
    
    withRole(role) {
        this.user.role = role;
        return this;
    }
    
    inactive() {
        this.user.isActive = false;
        return this;
    }
    
    withPreferences(preferences) {
        this.user.preferences = { ...this.user.preferences, ...preferences };
        return this;
    }
    
    build() {
        return { ...this.user };
    }
}

// Usage in tests
import { UserBuilder } from '../testUtils/builders.js';

it('should deny access for inactive admin users', () => {
    const user = new UserBuilder()
        .withRole('admin')
        .inactive()
        .build();
    
    const hasAccess = authService.checkAccess(user, 'admin-panel');
    
    expect(hasAccess).toBe(false);
});
```

## 🚫 Testing Anti-Patterns

### Avoid Testing Implementation Details

### ❌ Bad: Testing internal implementation

```javascript
it('should call validateEmail method', () => {
    const spy = jest.spyOn(userService, 'validateEmail');
    userService.createUser(userData);
    expect(spy).toHaveBeenCalled();
});
```

### ✅ Good: Testing behavior

```javascript
it('should reject user creation with invalid email', async () => {
    const userData = { email: 'invalid-email', password: 'pass123' };
    
    await expect(userService.createUser(userData))
        .rejects.toThrow('Invalid email format');
});
```

### Avoid Overly Complex Test Setup

### ❌ Bad: Complex, hard-to-understand setup

```javascript
it('should process complex order', () => {
    const user = { id: 1, name: 'John', credits: 500, purchases: [{ id: 1, amount: 100 }, { id: 2, amount: 200 }], preferences: { currency: 'USD', notifications: true }, address: { street: '123 Main St', city: 'Anytown' } };
    const product = { id: 1, name: 'Widget', price: 50, inventory: 10, categories: ['electronics', 'gadgets'], supplier: { id: 1, name: 'ACME Corp', rating: 4.5 } };
    // ... many more lines of setup
});
```

### ✅ Good: Simple, focused setup

```javascript
it('should process order when user has sufficient credits', () => {
    const user = new UserBuilder().withCredits(500).build();
    const product = new ProductBuilder().withPrice(50).build();
    
    const result = orderService.processOrder(user, product, 1);
    
    expect(result.success).toBe(true);
});
```

## 📈 Test Organization

### Group Related Tests

```javascript
describe('OrderService', () => {
    describe('createOrder', () => {
        it('should create order with valid data', () => {
            // Test implementation
        });
        
        it('should validate user has sufficient balance', () => {
            // Test implementation
        });
        
        it('should check product availability', () => {
            // Test implementation
        });
    });
    
    describe('cancelOrder', () => {
        it('should cancel order within cancellation window', () => {
            // Test implementation
        });
        
        it('should refund payment for cancelled order', () => {
            // Test implementation
        });
        
        it('should restore product inventory', () => {
            // Test implementation
        });
    });
    
    describe('updateOrder', () => {
        it('should allow quantity updates before processing', () => {
            // Test implementation
        });
        
        it('should prevent updates after shipping', () => {
            // Test implementation
        });
    });
});
```

## ✅ Quick Checklist

- [ ] Tests are independent and can run in any order
- [ ] Test names clearly describe what is being tested
- [ ] Each test follows the Arrange-Act-Assert pattern
- [ ] External dependencies are mocked appropriately
- [ ] Edge cases and error conditions are tested
- [ ] Tests are fast and don't depend on external services
- [ ] Test data is created using builders or factories
- [ ] Tests focus on behavior, not implementation details
- [ ] Coverage focuses on critical business logic
- [ ] Tests serve as documentation for expected behavior

---

**Next:** [Error Handling](./error-handling.md)
