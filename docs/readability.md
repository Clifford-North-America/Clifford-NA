# Readability

Readable code is maintainable code. When code is easy to read and understand, it reduces bugs, speeds up development, and makes collaboration more effective.

## 🎯 Core Principles

1. **Clarity Over Cleverness** - Choose the obvious solution over the clever one
2. **Consistent Formatting** - Use the same style throughout your codebase
3. **Logical Flow** - Organize code in a way that follows natural reading patterns
4. **Appropriate Complexity** - Break down complex expressions into simpler parts

## 📏 Line Length and Formatting

### Line Length Guidelines

Keep lines to a reasonable length (80-120 characters) for better readability:

#### ✅ Good

```javascript
const userPreferences = await getUserPreferences(userId);
const theme = userPreferences.theme || DEFAULT_THEME;
const language = userPreferences.language || DEFAULT_LANGUAGE;

const config = {
    theme: theme,
    language: language,
    notifications: userPreferences.notifications
};
```

#### ❌ Avoid: Long lines

```javascript
const config = { theme: userPreferences.theme || DEFAULT_THEME, language: userPreferences.language || DEFAULT_LANGUAGE, notifications: userPreferences.notifications };
```

### Breaking Long Expressions

#### ✅ Good: Multi-line with clear structure

```javascript

```javascript
```

### Whitespace and Formatting

#### ❌ Avoid: Cramped formatting

```javascript

## 🔤 Indentation and Spacing

### Consistent Indentation

Use consistent indentation (2 or 4 spaces, never mix with tabs):

**✅ Good:**
```javascript
function processUserData(users) {
    const results = [];
    
    for (const user of users) {
        if (user.isActive) {
            const processedUser = {
                id: user.id,
                name: user.name,
                email: user.email.toLowerCase(),
                lastLogin: formatDate(user.lastLogin)
            };
            
            results.push(processedUser);
        }
    }
    
    return results;
}
```

### Logical Spacing

Use whitespace to separate logical blocks:

#### ✅ Good: Clear separation

```javascript
function calculateOrderTotal(order) {
    // Validate input
    if (!order || !order.items) {
        throw new Error('Invalid order data');
    }
    
    // Calculate subtotal
    const subtotal = order.items.reduce((sum, item) => {
        return sum + (item.price * item.quantity);
    }, 0);
    
    // Apply discounts
    const discount = calculateDiscount(order, subtotal);
    const discountedTotal = subtotal - discount;
    
    // Calculate tax
    const tax = discountedTotal * TAX_RATE;
    
    // Return final total
    return {
        subtotal: subtotal,
        discount: discount,
        tax: tax,
        total: discountedTotal + tax
    };
}
```

#### ❌ Avoid: No visual separation

```javascript
function calculateOrderTotal(order) {
    if (!order || !order.items) {
        throw new Error('Invalid order data');
    }
    const subtotal = order.items.reduce((sum, item) => {
        return sum + (item.price * item.quantity);
    }, 0);
    const discount = calculateDiscount(order, subtotal);
    const discountedTotal = subtotal - discount;
    const tax = discountedTotal * TAX_RATE;
    return {
        subtotal: subtotal,
        discount: discount,
        tax: tax,
        total: discountedTotal + tax
    };
}
```

## 🔧 Expression Clarity

### Break Down Complex Expressions

### Logical Grouping

#### ✅ Good: Clear intermediate steps

```javascript
```javascript
function isValidPurchase(user, product, quantity) {
    // Check user eligibility
    const hasValidAccount = user.isActive && !user.isSuspended;
    const hasPaymentMethod = user.paymentMethods.length > 0;
    const userIsEligible = hasValidAccount && hasPaymentMethod;
    
    // Check product availability
    const productIsAvailable = product.isActive && !product.isDiscontinued;
    const hasEnoughStock = product.inventory >= quantity;
    const productMeetsRequirements = productIsAvailable && hasEnoughStock;
    
    // Check purchase limits
    const withinQuantityLimit = quantity <= MAX_QUANTITY_PER_ORDER;
    const withinPriceLimit = (product.price * quantity) <= user.purchaseLimit;
    const purchaseIsWithinLimits = withinQuantityLimit && withinPriceLimit;
    
    return userIsEligible && productMeetsRequirements && purchaseIsWithinLimits;
}
```

#### ❌ Avoid: Complex one-liner

```javascript
function isValidPurchase(user, product, quantity) {
    return user.isActive && !user.isSuspended && user.paymentMethods.length > 0 && product.isActive && !product.isDiscontinued && product.inventory >= quantity && quantity <= MAX_QUANTITY_PER_ORDER && (product.price * quantity) <= user.purchaseLimit;
}
```

### Use Meaningful Variable Names for Calculations

#### ✅ Good: Self-documenting calculations

```javascript
function calculateShippingCost(weight, distance, shippingMethod) {
    const baseRate = shippingMethod.baseRate;
    const weightMultiplier = shippingMethod.perKgRate;
    const distanceMultiplier = shippingMethod.perKmRate;
    
    const weightCost = weight * weightMultiplier;
    const distanceCost = distance * distanceMultiplier;
    
    return Math.max(
        baseRate + weightCost + distanceCost,
        shippingMethod.minimumCost
    );
}
```

#### ❌ Avoid: Magic numbers and unclear calculations

```javascript
function calculateShippingCost(weight, distance, method) {
    return Math.max(
        RATES[method] + 
        Math.ceil(weight / 5) * 2.5 + 
        Math.ceil(distance / 100) * 1.8 + 
        (method === 'EXPRESS' ? 15 : 0) + 
        (weight > 50 ? weight * 0.1 : 0),
        10
    );
}
```

## 📋 Object and Array Formatting

### Object Formatting

#### ✅ Good: Consistent object structure

```javascript
// Simple objects: one line
const point = { x: 10, y: 20 };
const user = { id: 1, name: 'John', email: 'john@example.com' };

// Complex objects: multi-line with trailing commas
const userProfile = {
    personal: {
        firstName: 'John',
        lastName: 'Doe',
        email: 'john.doe@example.com',
        phone: '+1-555-0123',
    },
    preferences: {
        theme: 'dark',
        language: 'en',
        notifications: {
            email: true,
            push: false,
            sms: true,
        },
    },
    metadata: {
        createdAt: new Date(),
        lastLogin: null,
        loginCount: 0,
    },
};
```

### Array Formatting

#### ✅ Good: Appropriate array formatting

```javascript
// Simple arrays: one line
const colors = ['red', 'green', 'blue'];
const numbers = [1, 2, 3, 4, 5];

// Complex arrays: one item per line
const menuItems = [
    {
        id: 'file',
        label: 'File',
        submenu: ['new', 'open', 'save', 'exit'],
    },
    {
        id: 'edit',
        label: 'Edit',
        submenu: ['cut', 'copy', 'paste', 'undo'],
    },
    {
        id: 'view',
        label: 'View',
        submenu: ['zoom-in', 'zoom-out', 'fullscreen'],
    },
];

// Function calls with multiple arguments
const result = processData([
    transformA(data.input),
    transformB(data.config),
    transformC(data.metadata),
]);
```

## 🎨 Code Structure Patterns

### Guard Clauses for Early Returns

### Control Flow

#### ✅ Good: Early returns reduce nesting

```javascript
```javascript
function processUserOrder(user, order) {
    // Guard clauses
    if (!user) {
        throw new Error('User is required');
    }
    
    if (!user.isActive) {
        return { success: false, reason: 'User account is inactive' };
    }
    
    if (!order || order.items.length === 0) {
        return { success: false, reason: 'Order is empty' };
    }
    
    if (order.total > user.creditLimit) {
        return { success: false, reason: 'Order exceeds credit limit' };
    }
    
    // Main processing logic (not deeply nested)
    const processedOrder = {
        id: generateOrderId(),
        userId: user.id,
        items: order.items,
        total: order.total,
        status: 'processing',
    };
    
    return { success: true, order: processedOrder };
}
```

}

#### ❌ Avoid: Deep nesting

```javascript
```javascript
function processUserOrder(user, order) {
    if (user) {
        if (user.isActive) {
            if (order && order.items.length > 0) {
                if (order.total <= user.creditLimit) {
                    // Main logic buried in nested conditions
                    const processedOrder = {
                        id: generateOrderId(),
                        userId: user.id,
                        items: order.items,
                        total: order.total,
                        status: 'processing',
                    };
                    return { success: true, order: processedOrder };
                } else {
                    return { success: false, reason: 'Order exceeds credit limit' };
                }
            } else {
                return { success: false, reason: 'Order is empty' };
            }
        } else {
            return { success: false, reason: 'User account is inactive' };
        }
    } else {
        throw new Error('User is required');
    }
}
```

### Consistent Return Patterns

#### ✅ Good: Consistent structure

```javascript
async function getUserProfile(userId) {
    try {
        const user = await database.users.findById(userId);
        
        if (!user) {
            return {
                success: false,
                error: 'User not found',
                data: null,
            };
        }
        
        const profile = await buildUserProfile(user);
        
        return {
            success: true,
            error: null,
            data: profile,
        };
        
    } catch (error) {
        return {
            success: false,
            error: error.message,
            data: null,
        };
    }
}
```

## 🔍 Template Strings and Interpolation

### Use Template Literals for Readability

#### ✅ Good: Clear template strings

```javascript
// Simple interpolation
const message = `Welcome back, ${user.firstName}!`;
const url = `${API_BASE_URL}/users/${userId}/profile`;

// Multi-line templates
const emailTemplate = `
    Dear ${user.firstName} ${user.lastName},
    
    Your order #${order.id} has been shipped.
    
    Tracking number: ${order.trackingNumber}
    Estimated delivery: ${formatDate(order.estimatedDelivery)}
    
    Best regards,
    The ${COMPANY_NAME} Team
`.trim();

// Complex expressions
const summaryMessage = `
    Order Summary:
    - Items: ${order.items.length}
    - Subtotal: ${formatCurrency(order.subtotal)}
    - Tax: ${formatCurrency(order.tax)}
    - Total: ${formatCurrency(order.total)}
`;
```

#### ❌ Avoid: String concatenation for complex strings

```javascript
const message = 'Welcome back, ' + user.firstName + '!';
const url = API_BASE_URL + '/users/' + userId + '/profile';

const emailTemplate = 'Dear ' + user.firstName + ' ' + user.lastName + ',\n\n' +
    'Your order #' + order.id + ' has been shipped.\n\n' +
    'Tracking number: ' + order.trackingNumber + '\n' +
    'Estimated delivery: ' + formatDate(order.estimatedDelivery) + '\n\n' +
    'Best regards,\nThe ' + COMPANY_NAME + ' Team';
```

## ✅ Quick Checklist

- [ ] Lines are reasonably short (80-120 characters)
- [ ] Consistent indentation throughout the file
- [ ] Logical blocks are separated by whitespace
- [ ] Complex expressions are broken into smaller, named parts
- [ ] Objects and arrays are formatted consistently
- [ ] Guard clauses are used to reduce nesting
- [ ] Template literals are used for string interpolation
- [ ] Function returns follow consistent patterns
- [ ] Code flows naturally from top to bottom
- [ ] Variable names clearly indicate their purpose

---

**Next:** [Testing](./testing.md)
