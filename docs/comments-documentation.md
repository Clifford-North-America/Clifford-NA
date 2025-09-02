# Comments & Documentation

Good documentation explains the "why" behind your code, not just the "what." It helps future developers (including yourself) understand the reasoning and context behind implementation decisions.

## 🎯 Core Principles

1. **Explain Intent, Not Implementation** - Focus on why, not what
2. **Keep Comments Current** - Outdated comments are worse than no comments
3. **Write for Your Future Self** - Assume you'll forget the context
4. **Document Complex Logic** - If it took time to figure out, document it

## 📝 Comment Types and When to Use Them

### Explain the "Why" (✅ Good)

```javascript
// We cache user preferences for 24 hours to reduce database load
// during peak traffic periods when users frequently switch themes
const PREFERENCE_CACHE_TTL = 24 * 60 * 60 * 1000;

function processPayment(amount, currency) {
    // Round to 2 decimal places to prevent floating-point precision issues
    // that could cause payment discrepancies with financial institutions
    const roundedAmount = Math.round(amount * 100) / 100;
    
    // Use exponential backoff for retries because payment APIs
    // are often rate-limited and temporary failures are common
    return retryWithBackoff(() => paymentAPI.charge(roundedAmount, currency));
}

// Intentionally using a less efficient algorithm here because
// the dataset is small (< 100 items) and readability is more
// important than micro-optimizations for this use case
function findDuplicateNames(users) {
    const duplicates = [];
    for (let i = 0; i < users.length; i++) {
        for (let j = i + 1; j < users.length; j++) {
            if (users[i].name === users[j].name) {
                duplicates.push(users[i].name);
            }
        }
    }
    return duplicates;
}
```

### Avoid Obvious Comments (❌ Bad)

```javascript
// ❌ These comments just restate what the code does
let count = 0; // Initialize count to zero
count++; // Increment count by one
const users = getUsers(); // Get users
if (users.length > 0) { // If users array has items
    // Loop through each user
    users.forEach(user => {
        console.log(user.name); // Print user name to console
    });
}
```

### Document Complex Algorithms

```javascript
/**
 * Implements the Damerau-Levenshtein distance algorithm to find
 * the minimum number of operations (insertions, deletions, substitutions,
 * or transpositions) needed to transform one string into another.
 * 
 * Used for fuzzy search functionality where we want to find
 * product names even with typos or slight misspellings.
 * 
 * Time complexity: O(m * n) where m and n are string lengths
 * Space complexity: O(m * n) for the distance matrix
 */
function calculateEditDistance(source, target) {
    const sourceLength = source.length;
    const targetLength = target.length;
    
    // Create matrix to store intermediate distances
    const matrix = Array(sourceLength + 1)
        .fill(null)
        .map(() => Array(targetLength + 1).fill(0));
    
    // Initialize first row and column (base cases)
    for (let i = 0; i <= sourceLength; i++) matrix[i][0] = i;
    for (let j = 0; j <= targetLength; j++) matrix[0][j] = j;
    
    // Fill the matrix using dynamic programming
    for (let i = 1; i <= sourceLength; i++) {
        for (let j = 1; j <= targetLength; j++) {
            const cost = source[i - 1] === target[j - 1] ? 0 : 1;
            
            matrix[i][j] = Math.min(
                matrix[i - 1][j] + 1,     // deletion
                matrix[i][j - 1] + 1,     // insertion
                matrix[i - 1][j - 1] + cost // substitution
            );
            
            // Check for transposition (Damerau extension)
            if (i > 1 && j > 1 &&
                source[i - 1] === target[j - 2] &&
                source[i - 2] === target[j - 1]) {
                matrix[i][j] = Math.min(
                    matrix[i][j],
                    matrix[i - 2][j - 2] + cost // transposition
                );
            }
        }
    }
    
    return matrix[sourceLength][targetLength];
}
```

### Explain Workarounds and Technical Debt

```javascript
function getUserData(userId) {
    // TODO: This should use a proper user service, but we're directly
    // accessing the database for now due to tight deadline. 
    // Refactor after v2.1 release to use UserService.getById()
    const user = database.query('SELECT * FROM users WHERE id = ?', [userId]);
    
    // HACK: The legacy API returns null for missing users, but our
    // frontend expects an empty object. Remove this when we migrate
    // to the new API endpoint in Q2 2025
    return user || {};
}

function calculateShipping(weight, distance) {
    // WORKAROUND: The shipping API occasionally returns negative values
    // for international shipments. This is a known bug (ticket #1234)
    // but the vendor hasn't fixed it yet. We clamp to zero as a safeguard.
    const cost = shippingAPI.calculate(weight, distance);
    return Math.max(0, cost);
}
```

## 📚 Documentation Formats

### Function Documentation (JSDoc Style)

```javascript
/**
 * Processes a batch of user registrations with validation and error handling.
 * 
 * This function validates each user's data, creates accounts for valid users,
 * and returns a summary of successful and failed registrations. Failed
 * registrations include detailed error information for debugging.
 * 
 * @param {Array<Object>} userDataList - Array of user objects to register
 * @param {string} userDataList[].email - User's email address (required)
 * @param {string} userDataList[].password - User's password (min 8 chars)
 * @param {string} userDataList[].firstName - User's first name (required)
 * @param {string} [userDataList[].lastName] - User's last name (optional)
 * @param {Object} options - Configuration options
 * @param {boolean} [options.sendWelcomeEmail=true] - Whether to send welcome emails
 * @param {boolean} [options.validateDuplicates=true] - Whether to check for existing emails
 * 
 * @returns {Promise<Object>} Registration results summary
 * @returns {Array<Object>} returns.successful - Successfully created users
 * @returns {Array<Object>} returns.failed - Failed registrations with error details
 * @returns {number} returns.total - Total number of users processed
 * 
 * @throws {ValidationError} When userDataList is not an array or is empty
 * @throws {ConfigurationError} When required services are not available
 * 
 * @example
 * const users = [
 *   { email: 'john@example.com', password: 'securePass1', firstName: 'John' },
 *   { email: 'jane@example.com', password: 'securePass2', firstName: 'Jane' }
 * ];
 * 
 * const result = await batchRegisterUsers(users, { sendWelcomeEmail: false });
 * console.log(`${result.successful.length} users created successfully`);
 * 
 * @since 2.1.0
 * @see {@link validateUserData} for individual user validation rules
 */
async function batchRegisterUsers(userDataList, options = {}) {
    // Implementation here...
}
```

### Class Documentation

```javascript
/**
 * Service for managing user authentication and authorization.
 * 
 * Handles login/logout, token management, password resets, and role-based
 * access control. Integrates with external OAuth providers and maintains
 * session state across multiple devices.
 * 
 * @class
 * @example
 * const authService = new AuthenticationService(database, emailService);
 * 
 * // Login user
 * const session = await authService.login('user@example.com', 'password');
 * 
 * // Check permissions
 * const canEdit = authService.hasPermission(session.user, 'posts:edit');
 */
class AuthenticationService {
    /**
     * Creates an instance of AuthenticationService.
     * 
     * @param {Database} database - Database connection for user storage
     * @param {EmailService} emailService - Service for sending password reset emails
     * @param {Object} [config={}] - Configuration options
     * @param {number} [config.sessionTimeout=3600] - Session timeout in seconds
     * @param {boolean} [config.enableOAuth=false] - Enable OAuth integration
     */
    constructor(database, emailService, config = {}) {
        this.database = database;
        this.emailService = emailService;
        this.config = { sessionTimeout: 3600, enableOAuth: false, ...config };
        this.activeSessions = new Map();
    }
    
    /**
     * Authenticates a user with email and password.
     * 
     * @param {string} email - User's email address
     * @param {string} password - User's password (will be hashed for comparison)
     * @returns {Promise<Object>} Session object with user data and token
     * @throws {AuthenticationError} When credentials are invalid
     * @throws {AccountLockedError} When account is temporarily locked
     */
    async login(email, password) {
        // Implementation...
    }
}
```

### README Documentation Structure

```markdown
# Project Name

Brief description of what this project does and why it exists.

## Features

- Key feature 1 with brief explanation
- Key feature 2 with brief explanation  
- Key feature 3 with brief explanation

## Quick Start

```bash
# Install dependencies
npm install

# Configure environment
cp .env.example .env
# Edit .env with your values

# Run the application
npm start
```

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `PORT` | Server port | `3000` | No |
| `DATABASE_URL` | Database connection string | - | Yes |
| `JWT_SECRET` | Secret for token signing | - | Yes |

### Configuration Files

- `config/database.js` - Database connection settings
- `config/email.js` - Email service configuration
- `config/security.js` - Security and authentication settings

## API Documentation

### Authentication

```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```

Response:

```json
{
  "token": "jwt-token-here",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "role": "user"
  }
}
```

## Development

### Project Structure

```text
src/
├── controllers/     # Request handlers
├── models/         # Data models
├── services/       # Business logic
├── middleware/     # Express middleware
├── utils/          # Helper functions
└── config/         # Configuration files
```

### Running Tests

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Generate coverage report
npm run test:coverage
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```text
End of README content
```

## 🚫 Documentation Anti-Patterns

### Outdated Comments

```javascript
// ❌ Comment doesn't match the code anymore
// Calculate tax at 8% rate
const taxRate = 0.12; // Tax rate is now 12%, comment is wrong

// ❌ Function signature changed but comment didn't
/**
 * Gets user by ID
 * @param {number} id - User ID
 */
function getUser(email, includePermissions = false) {
    // Function now takes email and optional flag, not just ID
}
```

### Over-Commenting

```javascript
// ❌ Too many obvious comments clutter the code
function calculateTotal(items) {
    let total = 0; // Initialize total to zero
    
    // Loop through each item in the items array
    for (let i = 0; i < items.length; i++) {
        const item = items[i]; // Get current item
        total += item.price; // Add item price to total
    }
    
    return total; // Return the calculated total
}

// ✅ Better: Only comment the non-obvious parts
function calculateTotal(items) {
    let total = 0;
    
    // Include tax calculation if item is taxable
    for (const item of items) {
        total += item.price;
        if (item.taxable) {
            total += item.price * TAX_RATE;
        }
    }
    
    return total;
}
```

### Commented-Out Code

```javascript
// ❌ Don't leave commented-out code
function processOrder(order) {
    validateOrder(order);
    
    // Old implementation - remove this!
    // const total = order.items.reduce((sum, item) => sum + item.price, 0);
    // order.total = total;
    
    calculateOrderTotal(order);
    saveOrder(order);
}
```

## ✅ Quick Checklist

- [ ] Comments explain "why," not "what"
- [ ] Complex algorithms are documented with time/space complexity
- [ ] Workarounds and technical debt are clearly marked
- [ ] Function documentation includes parameters, return values, and examples
- [ ] Comments are up-to-date with the current code
- [ ] No commented-out code left in the repository
- [ ] README provides clear setup and usage instructions
- [ ] API endpoints are documented with examples
- [ ] Configuration options are explained

---

**Next:** [Readability](./readability.md)
