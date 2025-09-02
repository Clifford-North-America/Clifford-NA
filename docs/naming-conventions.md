# Naming Conventions

Clear, consistent naming is the foundation of readable code. Good names make code self-documenting and reduce the need for comments.

## 🎯 Core Principles

1. **Be Descriptive** - Names should clearly indicate purpose and content
2. **Be Consistent** - Follow the same patterns throughout your codebase
3. **Be Concise** - Avoid unnecessarily long names while maintaining clarity
4. **Avoid Abbreviations** - Use full words unless the abbreviation is universally recognized

## 📝 Casing Conventions

### Variables & Functions

Use **camelCase** for variables and functions:

```javascript
// ✅ Good
const userEmail = 'user@example.com';
const isLoggedIn = true;
const maxRetryAttempts = 3;

function calculateTotalPrice(items) {
    return items.reduce((sum, item) => sum + item.price, 0);
}

function validateUserInput(input) {
    // validation logic
}
```

```javascript
// ❌ Avoid
const user_email = 'user@example.com';  // snake_case
const IsLoggedIn = true;                // PascalCase
const MAX_RETRY_ATTEMPTS = 3;           // SCREAMING_SNAKE_CASE

function Calculate_total_price(items) { // mixed casing
    // logic
}
```

### Classes & Constructors

Use **PascalCase** for classes and constructors:

```javascript
// ✅ Good
class UserAccount {
    constructor(email, password) {
        this.email = email;
        this.password = password;
    }
}

class PaymentProcessor {
    processPayment(amount, method) {
        // processing logic
    }
}
```

```javascript
// ❌ Avoid
class userAccount {           // camelCase
class payment_processor {     // snake_case
```

### Constants

Use **SCREAMING_SNAKE_CASE** for constants:

```javascript
// ✅ Good
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
const API_BASE_URL = 'https://api.example.com';
const DEFAULT_TIMEOUT = 5000;
const ERROR_MESSAGES = {
    INVALID_EMAIL: 'Please enter a valid email address',
    NETWORK_ERROR: 'Network connection failed'
};
```

### Files & Directories

Use **kebab-case** for files and directories:

```text
// ✅ Good
user-service.js
payment-processor.js
email-validator.js
components/
  user-profile/
  shopping-cart/
  product-list/
```

```text
// ❌ Avoid
UserService.js          // PascalCase
user_service.js         // snake_case
emailvalidator.js       // no separation
```

## 🏷️ Naming Patterns

### Boolean Variables

Use clear, descriptive names that ask a yes/no question:

const isUserLoggedIn = checkAuthentication();

### Counters & Quantities

Use descriptive names that indicate what is being counted:

```javascript
// ✅ Good
const itemCount = items.length;
const totalUsers = users.length;
const maxRetries = 3;
const currentIndex = 0;
const pageNumber = 1;
```

### Collections

Use plural nouns for arrays and collections:

```javascript
// ✅ Good
const users = fetchAllUsers();
const activeConnections = getActiveConnections();
const pendingRequests = [];
const errorMessages = [];

// Single items
const selectedUser = users[0];
const currentConnection = activeConnections.find(conn => conn.isActive);
```

### Functions

Use verb-noun combinations that describe the action:

```javascript
// ✅ Good - CRUD operations
function createUser(userData) { }
function getUserById(id) { }
function updateUserProfile(userId, updates) { }
function deleteUserAccount(userId) { }

// ✅ Good - Action descriptions
function validateEmailFormat(email) { }
function calculateShippingCost(items, destination) { }
function formatCurrency(amount, locale) { }
function parseApiResponse(response) { }

// ✅ Good - Question format for boolean returns
function isValidEmail(email) { }
function hasAdminRights(user) { }
function canAccessResource(user, resource) { }
```

## 🚫 Common Anti-Patterns

### Avoid Generic Names

```javascript
// ❌ Avoid
const data = fetchUsers();
const info = getUserInfo();
const obj = createObject();
const temp = processData();
const result = calculate();

// ✅ Better
const users = fetchUsers();
const userProfile = getUserInfo();
const userAccount = createObject();
const processedItems = processData();
const totalPrice = calculate();
```

### Avoid Misleading Names

```javascript
// ❌ Misleading
const userList = new Set();  // It's a Set, not a List
const userCount = ['user1', 'user2'];  // It's an array, not a count
const isReady = 'pending';  // String value, not boolean

// ✅ Clear
const userSet = new Set();
const userList = ['user1', 'user2'];
const status = 'pending';
const isReady = status === 'ready';
```

### Avoid Mental Mapping

```javascript
// ❌ Requires mental mapping
const d = new Date();
const u = users.find(x => x.id === id);
const i = 0;

// ✅ Self-explanatory
const currentDate = new Date();
const targetUser = users.find(user => user.id === userId);
const currentIndex = 0;
```

## 🎨 Language-Specific Conventions

### Python

```python
# Variables and functions: snake_case
user_email = 'user@example.com'
max_retry_attempts = 3

def calculate_total_price(items):
    return sum(item.price for item in items)

# Classes: PascalCase
class UserAccount:
    def __init__(self, email, password):
        self.email = email
        self.password = password

# Constants: SCREAMING_SNAKE_CASE
MAX_FILE_SIZE = 10 * 1024 * 1024
API_BASE_URL = 'https://api.example.com'
```

### C-Sharp

```csharp
// Properties and Methods: PascalCase
public class UserAccount
{
    public string Email { get; set; }
    public bool IsActive { get; set; }
    
    public void UpdateProfile(UserProfile profile)
    {
        // implementation
    }
}

// Local variables: camelCase
var userEmail = "user@example.com";
var isLoggedIn = true;

// Constants: PascalCase
public const int MaxFileSize = 10 * 1024 * 1024;
```

## ✅ Quick Checklist

- [ ] Names clearly describe their purpose
- [ ] Consistent casing throughout the project
- [ ] Boolean variables use is/has/can/should prefixes
- [ ] Functions use verb-noun combinations
- [ ] Collections use plural nouns
- [ ] No abbreviations unless universally known
- [ ] No mental mapping required
- [ ] Context-appropriate length (neither too short nor too long)

---

**Next:** [Code Organization](./code-organization.md)
