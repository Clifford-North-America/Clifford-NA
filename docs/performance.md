# Performance & Efficiency

Performance optimization should be approached methodically: measure first, identify bottlenecks, then optimize. Premature optimization often leads to complex code with minimal gains.

## 🎯 Core Principles

1. **Measure Before Optimizing** - Use profiling tools to identify real bottlenecks
2. **Optimize for the Common Case** - Focus on the most frequent operations
3. **Consider the Full Stack** - Database, network, and frontend all matter
4. **Balance Performance and Maintainability** - Don't sacrifice code clarity for micro-optimizations

## 📊 Performance Monitoring

### Application Performance Monitoring

#### ✅ Good: Comprehensive performance tracking

```javascript
import { performance, PerformanceObserver } from 'perf_hooks';

class PerformanceMonitor {
    constructor(logger) {
        this.logger = logger;
        this.metrics = new Map();
        this.setupObservers();
    }
    
    setupObservers() {
        // Monitor HTTP requests
        const httpObserver = new PerformanceObserver((list) => {
            for (const entry of list.getEntries()) {
                this.logger.info('HTTP Request Performance', {
                    method: entry.detail?.method,
                    url: entry.detail?.url,
                    duration: entry.duration,
                    startTime: entry.startTime
                });
            }
        });
        httpObserver.observe({ entryTypes: ['measure'] });
        
        // Monitor database queries
        const dbObserver = new PerformanceObserver((list) => {
            for (const entry of list.getEntries()) {
                if (entry.duration > 1000) { // Log slow queries (> 1s)
                    this.logger.warn('Slow Database Query', {
                        query: entry.detail?.query,
                        duration: entry.duration,
                        parameters: entry.detail?.parameters
                    });
                }
            }
        });
        dbObserver.observe({ entryTypes: ['measure'] });
    }
    
    // Measure function execution time
    measureFunction(name, fn) {
        return async (...args) => {
            const startTime = performance.now();
            
            try {
                const result = await fn(...args);
                const duration = performance.now() - startTime;
                
                this.recordMetric(name, duration);
                
                if (duration > 500) { // Log slow operations
                    this.logger.warn('Slow Function Execution', {
                        function: name,
                        duration: duration,
                        args: args.length
                    });
                }
                
                return result;
            } catch (error) {
                const duration = performance.now() - startTime;
                this.logger.error('Function Execution Error', {
                    function: name,
                    duration: duration,
                    error: error.message
                });
                throw error;
            }
        };
    }
    
    // Record and aggregate metrics
    recordMetric(name, value) {
        if (!this.metrics.has(name)) {
            this.metrics.set(name, {
                count: 0,
                total: 0,
                min: Infinity,
                max: 0,
                p95: []
            });
        }
        
        const metric = this.metrics.get(name);
        metric.count++;
        metric.total += value;
        metric.min = Math.min(metric.min, value);
        metric.max = Math.max(metric.max, value);
        metric.p95.push(value);
        
        // Keep only last 100 values for percentile calculation
        if (metric.p95.length > 100) {
            metric.p95.shift();
        }
    }
    
    // Get performance summary
    getMetrics() {
        const summary = {};
        
        for (const [name, metric] of this.metrics) {
            const sorted = [...metric.p95].sort((a, b) => a - b);
            const p95Index = Math.floor(sorted.length * 0.95);
            
            summary[name] = {
                count: metric.count,
                average: metric.total / metric.count,
                min: metric.min,
                max: metric.max,
                p95: sorted[p95Index] || 0
            };
        }
        
        return summary;
    }
}

const performanceMonitor = new PerformanceMonitor(logger);

// Middleware to measure HTTP request performance
function performanceMiddleware(req, res, next) {
    const startTime = performance.now();
    
    res.on('finish', () => {
        const duration = performance.now() - startTime;
        
        performanceMonitor.recordMetric('http_request_duration', duration);
        
        // Log slow requests
        if (duration > 2000) {
            logger.warn('Slow HTTP Request', {
                method: req.method,
                url: req.url,
                duration: duration,
                userAgent: req.get('User-Agent')
            });
        }
    });
    
    next();
}

app.use(performanceMiddleware);
```

## 🗃️ Database Optimization

### Query Optimization

#### ✅ Good: Efficient database queries

```javascript
class UserRepository {
    // Use indexes for frequent queries
    async findActiveUsers() {
        // ✅ Query uses index on (isActive, lastLoginAt)
        return await this.db.query(`
            SELECT id, email, firstName, lastName, lastLoginAt
            FROM users 
            WHERE isActive = true 
            ORDER BY lastLoginAt DESC
            LIMIT 50
        `);
    }
    
    // Batch operations instead of N+1 queries
    async getUsersWithOrders(userIds) {
        // ✅ Single query instead of multiple
        const query = `
            SELECT 
                u.id, u.email, u.firstName,
                COUNT(o.id) as orderCount,
                SUM(o.total) as totalSpent
            FROM users u
            LEFT JOIN orders o ON u.id = o.userId
            WHERE u.id = ANY($1)
            GROUP BY u.id, u.email, u.firstName
        `;
        
        return await this.db.query(query, [userIds]);
    }
    
    // Use pagination for large datasets
    async getUsersPaginated(page = 1, limit = 20) {
        const offset = (page - 1) * limit;
        
        // ✅ Limit results and use cursor-based pagination for large datasets
        const query = `
            SELECT id, email, firstName, lastName, createdAt
            FROM users
            WHERE createdAt > $1
            ORDER BY createdAt DESC
            LIMIT $2
        `;
        
        return await this.db.query(query, [offset, limit]);
    }
    
    // Use prepared statements for repeated queries
    constructor(database) {
        this.db = database;
        this.preparedStatements = {
            findById: this.db.prepare('SELECT * FROM users WHERE id = $1'),
            updateLastLogin: this.db.prepare('UPDATE users SET lastLoginAt = $1 WHERE id = $2')
        };
    }
    
    async findById(id) {
        return await this.preparedStatements.findById.execute([id]);
    }
}

// Connection pooling configuration
const dbConfig = {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    
    // Connection pool settings
    min: 2,          // Minimum connections
    max: 20,         // Maximum connections
    idleTimeoutMillis: 30000,  // Close idle connections after 30s
    connectionTimeoutMillis: 2000,  // Wait 2s for connection
    
    // Statement timeout
    statement_timeout: 30000,  // 30 second query timeout
    query_timeout: 30000,
    
    // SSL configuration for production
    ssl: process.env.NODE_ENV === 'production' ? {
        rejectUnauthorized: false
    } : false
};
```

### ❌ Avoid: Inefficient database patterns

```javascript
// ❌ N+1 query problem
async function getUsersWithOrderCounts(userIds) {
    const users = await db.query('SELECT * FROM users WHERE id = ANY($1)', [userIds]);
    
    for (const user of users) {
        // This creates N additional queries!
        const orderCount = await db.query('SELECT COUNT(*) FROM orders WHERE userId = $1', [user.id]);
        user.orderCount = orderCount.rows[0].count;
    }
    
    return users;
}

// ❌ No pagination
async function getAllUsers() {
    // Could return millions of records!
    return await db.query('SELECT * FROM users');
}

// ❌ No indexes on frequently queried columns
// Missing indexes on: email, isActive, createdAt, etc.
```

### Caching Strategies

### ✅ Good: Multi-layer caching

```javascript
import Redis from 'ioredis';
import NodeCache from 'node-cache';

class CacheManager {
    constructor() {
        // L1 Cache: In-memory (fastest, smallest)
        this.memoryCache = new NodeCache({
            stdTTL: 300,  // 5 minutes default
            checkperiod: 60,  // Check for expired keys every minute
            maxKeys: 1000  // Limit memory usage
        });
        
        // L2 Cache: Redis (fast, shared across instances)
        this.redisCache = new Redis({
            host: process.env.REDIS_HOST,
            port: process.env.REDIS_PORT,
            retryDelayOnFailover: 100,
            maxRetriesPerRequest: 3,
            lazyConnect: true
        });
        
        this.setupEventHandlers();
    }
    
    setupEventHandlers() {
        this.redisCache.on('error', (error) => {
            logger.error('Redis cache error', { error: error.message });
        });
        
        this.redisCache.on('connect', () => {
            logger.info('Redis cache connected');
        });
    }
    
    // Get value with fallback to database
    async get(key, fetchFunction, options = {}) {
        const { ttl = 300, useMemoryCache = true } = options;
        
        try {
            // Try L1 cache first
            if (useMemoryCache) {
                const memoryCacheValue = this.memoryCache.get(key);
                if (memoryCacheValue !== undefined) {
                    return memoryCacheValue;
                }
            }
            
            // Try L2 cache
            const redisCacheValue = await this.redisCache.get(key);
            if (redisCacheValue) {
                const parsed = JSON.parse(redisCacheValue);
                
                // Store in L1 cache
                if (useMemoryCache) {
                    this.memoryCache.set(key, parsed, ttl);
                }
                
                return parsed;
            }
            
            // Fetch from source (database)
            const freshValue = await fetchFunction();
            
            // Store in both caches
            await this.set(key, freshValue, { ttl, useMemoryCache });
            
            return freshValue;
            
        } catch (error) {
            logger.error('Cache get error', { key, error: error.message });
            
            // Fallback to direct fetch
            return await fetchFunction();
        }
    }
    
    async set(key, value, options = {}) {
        const { ttl = 300, useMemoryCache = true } = options;
        
        try {
            // Store in L1 cache
            if (useMemoryCache) {
                this.memoryCache.set(key, value, ttl);
            }
            
            // Store in L2 cache
            await this.redisCache.setex(key, ttl, JSON.stringify(value));
            
        } catch (error) {
            logger.error('Cache set error', { key, error: error.message });
        }
    }
    
    async invalidate(pattern) {
        try {
            // Clear from L1 cache
            this.memoryCache.flushAll();
            
            // Clear from L2 cache
            const keys = await this.redisCache.keys(pattern);
            if (keys.length > 0) {
                await this.redisCache.del(...keys);
            }
            
        } catch (error) {
            logger.error('Cache invalidation error', { pattern, error: error.message });
        }
    }
}

// Usage in service layer
class UserService {
    constructor(userRepository, cacheManager) {
        this.userRepository = userRepository;
        this.cache = cacheManager;
    }
    
    async getUserById(id) {
        const cacheKey = `user:${id}`;
        
        return await this.cache.get(
            cacheKey,
            () => this.userRepository.findById(id),
            { ttl: 600 } // Cache for 10 minutes
        );
    }
    
    async getUserProfile(id) {
        const cacheKey = `user_profile:${id}`;
        
        return await this.cache.get(
            cacheKey,
            async () => {
                const user = await this.userRepository.findById(id);
                const orders = await this.orderRepository.getRecentOrders(id, 5);
                const preferences = await this.preferenceRepository.findByUserId(id);
                
                return {
                    user,
                    recentOrders: orders,
                    preferences
                };
            },
            { ttl: 300 } // Cache for 5 minutes
        );
    }
    
    async updateUser(id, updates) {
        const user = await this.userRepository.update(id, updates);
        
        // Invalidate related caches
        await this.cache.invalidate(`user:${id}`);
        await this.cache.invalidate(`user_profile:${id}`);
        
        return user;
    }
}

const cacheManager = new CacheManager();
```

## 🚀 Frontend Performance

### Asset Optimization

### ✅ Good: Optimized asset delivery

```javascript
// webpack.config.js - Production optimization
const path = require('path');
const MiniCssExtractPlugin = require('mini-css-extract-plugin');
const TerserPlugin = require('terser-webpack-plugin');
const CompressionPlugin = require('compression-webpack-plugin');

module.exports = {
    mode: 'production',
    
    entry: {
        main: './src/index.js',
        vendor: ['react', 'react-dom', 'lodash'] // Separate vendor bundle
    },
    
    output: {
        path: path.resolve(__dirname, 'dist'),
        filename: '[name].[contenthash].js', // Cache busting
        chunkFilename: '[name].[contenthash].chunk.js'
    },
    
    optimization: {
        // Split chunks for better caching
        splitChunks: {
            chunks: 'all',
            cacheGroups: {
                vendor: {
                    test: /[\\/]node_modules[\\/]/,
                    name: 'vendors',
                    chunks: 'all'
                },
                common: {
                    name: 'common',
                    minChunks: 2,
                    chunks: 'all',
                    enforce: true
                }
            }
        },
        
        // Minimize JavaScript
        minimizer: [
            new TerserPlugin({
                terserOptions: {
                    compress: {
                        drop_console: true, // Remove console.log in production
                        drop_debugger: true
                    }
                }
            })
        ],
        
        // Generate module IDs based on path for better caching
        moduleIds: 'deterministic'
    },
    
    plugins: [
        // Extract CSS into separate files
        new MiniCssExtractPlugin({
            filename: '[name].[contenthash].css',
            chunkFilename: '[id].[contenthash].css'
        }),
        
        // Gzip compression
        new CompressionPlugin({
            algorithm: 'gzip',
            test: /\.(js|css|html|svg)$/,
            threshold: 8192,
            minRatio: 0.8
        })
    ],
    
    module: {
        rules: [
            {
                test: /\.(js|jsx)$/,
                exclude: /node_modules/,
                use: {
                    loader: 'babel-loader',
                    options: {
                        presets: ['@babel/preset-env', '@babel/preset-react'],
                        plugins: [
                            '@babel/plugin-proposal-class-properties',
                            'babel-plugin-transform-react-remove-prop-types' // Remove PropTypes in production
                        ]
                    }
                }
            },
            {
                test: /\.css$/,
                use: [
                    MiniCssExtractPlugin.loader,
                    'css-loader',
                    'postcss-loader' // For autoprefixer and other PostCSS plugins
                ]
            },
            {
                test: /\.(png|jpg|jpeg|gif|svg)$/,
                use: [
                    {
                        loader: 'url-loader',
                        options: {
                            limit: 8192, // Inline small images
                            name: 'images/[name].[contenthash].[ext]'
                        }
                    }
                ]
            }
        ]
    }
};

// React component optimization
import React, { memo, useMemo, useCallback } from 'react';

// ✅ Memoize expensive calculations
const UserDashboard = memo(({ user, orders, preferences }) => {
    // Memoize expensive computations
    const orderSummary = useMemo(() => {
        return orders.reduce((summary, order) => ({
            totalOrders: summary.totalOrders + 1,
            totalSpent: summary.totalSpent + order.total,
            averageOrderValue: (summary.totalSpent + order.total) / (summary.totalOrders + 1)
        }), { totalOrders: 0, totalSpent: 0, averageOrderValue: 0 });
    }, [orders]);
    
    // Memoize event handlers to prevent unnecessary re-renders
    const handleOrderClick = useCallback((orderId) => {
        // Handle order click
        router.push(`/orders/${orderId}`);
    }, [router]);
    
    const handlePreferenceChange = useCallback((key, value) => {
        updateUserPreferences(user.id, { [key]: value });
    }, [user.id]);
    
    return (
        <div className="dashboard">
            <UserProfile user={user} />
            <OrderSummary 
                summary={orderSummary} 
                onOrderClick={handleOrderClick} 
            />
            <PreferencesPanel 
                preferences={preferences}
                onChange={handlePreferenceChange}
            />
        </div>
    );
});

// ✅ Lazy loading for code splitting
const LazyAdminPanel = React.lazy(() => import('./AdminPanel'));

function App() {
    return (
        <Router>
            <Routes>
                <Route path="/" element={<Home />} />
                <Route path="/dashboard" element={<UserDashboard />} />
                <Route 
                    path="/admin" 
                    element={
                        <Suspense fallback={<LoadingSpinner />}>
                            <LazyAdminPanel />
                        </Suspense>
                    } 
                />
            </Routes>
        </Router>
    );
}
```

### HTTP Optimization

### ✅ Good: Optimized HTTP delivery

```javascript
import express from 'express';
import compression from 'compression';
import helmet from 'helmet';

const app = express();

// Enable gzip compression
app.use(compression({
    level: 6,  // Compression level (1-9)
    threshold: 1024,  // Only compress files larger than 1KB
    filter: (req, res) => {
        // Compress all text-based content
        return compression.filter(req, res);
    }
}));

// Static file serving with caching
app.use('/static', express.static('public', {
    maxAge: '1y',  // Cache static assets for 1 year
    etag: true,    // Enable ETags
    lastModified: true,
    setHeaders: (res, path) => {
        // Set specific cache headers based on file type
        if (path.endsWith('.html')) {
            res.setHeader('Cache-Control', 'no-cache'); // Don't cache HTML
        } else if (path.match(/\.(js|css)$/)) {
            res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
        } else if (path.match(/\.(png|jpg|jpeg|gif|svg|ico)$/)) {
            res.setHeader('Cache-Control', 'public, max-age=31536000');
        }
    }
}));

// API response caching
function cacheMiddleware(duration = 300) {
    return (req, res, next) => {
        // Only cache GET requests
        if (req.method !== 'GET') {
            return next();
        }
        
        const key = `cache:${req.originalUrl}`;
        
        // Check cache
        cacheManager.get(key).then(cached => {
            if (cached) {
                res.setHeader('X-Cache', 'HIT');
                return res.json(cached);
            }
            
            // Override res.json to cache the response
            const originalJson = res.json;
            res.json = function(data) {
                // Cache successful responses
                if (res.statusCode === 200) {
                    cacheManager.set(key, data, { ttl: duration });
                }
                
                res.setHeader('X-Cache', 'MISS');
                return originalJson.call(this, data);
            };
            
            next();
        }).catch(next);
    };
}

// Apply caching to specific routes
app.get('/api/products', cacheMiddleware(600), async (req, res) => {
    const products = await productService.getProducts();
    res.json(products);
});

app.get('/api/user/:id', cacheMiddleware(300), async (req, res) => {
    const user = await userService.getUserById(req.params.id);
    res.json(user);
});

// HTTP/2 Server Push (if using HTTP/2)
app.get('/', (req, res) => {
    // Push critical resources
    if (res.push) {
        res.push('/static/css/main.css');
        res.push('/static/js/main.js');
    }
    
    res.sendFile(path.join(__dirname, 'public/index.html'));
});
```

## 🔧 Memory Management

### Efficient Data Structures

### ✅ Good: Memory-efficient patterns

```javascript
// Use appropriate data structures
class PerformantUserManager {
    constructor() {
        // Use Map for O(1) lookups instead of arrays
        this.userMap = new Map();
        this.usersByEmail = new Map();
        
        // Use Set for unique collections
        this.activeUserIds = new Set();
        
        // Use WeakMap for object associations (allows garbage collection)
        this.userSessions = new WeakMap();
    }
    
    addUser(user) {
        this.userMap.set(user.id, user);
        this.usersByEmail.set(user.email, user);
        
        if (user.isActive) {
            this.activeUserIds.add(user.id);
        }
    }
    
    // Efficient batch processing
    processUsers(userIds, callback) {
        const batchSize = 100;
        
        for (let i = 0; i < userIds.length; i += batchSize) {
            const batch = userIds.slice(i, i + batchSize);
            
            // Process batch
            const users = batch.map(id => this.userMap.get(id)).filter(Boolean);
            callback(users);
            
            // Allow event loop to process other tasks
            if (i + batchSize < userIds.length) {
                setImmediate(() => {
                    // Continue processing in next tick
                });
            }
        }
    }
    
    // Memory cleanup
    removeUser(userId) {
        const user = this.userMap.get(userId);
        if (user) {
            this.userMap.delete(userId);
            this.usersByEmail.delete(user.email);
            this.activeUserIds.delete(userId);
        }
    }
    
    // Periodic cleanup of inactive data
    cleanupInactiveUsers() {
        const now = new Date();
        const inactiveThreshold = 30 * 24 * 60 * 60 * 1000; // 30 days
        
        for (const [id, user] of this.userMap) {
            if (now - user.lastActive > inactiveThreshold) {
                this.removeUser(id);
            }
        }
    }
}

// Stream processing for large datasets
import { Transform } from 'stream';

class UserDataProcessor extends Transform {
    constructor(options = {}) {
        super({ objectMode: true, ...options });
        this.processedCount = 0;
    }
    
    _transform(user, encoding, callback) {
        try {
            // Process user data
            const processed = this.processUser(user);
            
            this.processedCount++;
            
            // Report progress periodically
            if (this.processedCount % 1000 === 0) {
                this.emit('progress', this.processedCount);
            }
            
            callback(null, processed);
        } catch (error) {
            callback(error);
        }
    }
    
    processUser(user) {
        // Transform user data
        return {
            id: user.id,
            email: user.email,
            fullName: `${user.firstName} ${user.lastName}`,
            joinDate: user.createdAt,
            // Don't keep unnecessary data in memory
        };
    }
}

// Usage for processing large datasets
async function processLargeUserDataset(inputStream, outputStream) {
    const processor = new UserDataProcessor();
    
    processor.on('progress', (count) => {
        logger.info(`Processed ${count} users`);
    });
    
    return new Promise((resolve, reject) => {
        inputStream
            .pipe(processor)
            .pipe(outputStream)
            .on('finish', resolve)
            .on('error', reject);
    });
}
```

## 📈 Algorithm Optimization

### Common Optimization Patterns

### ✅ Good: Efficient algorithms

```javascript
// Debouncing for expensive operations
function debounce(func, delay) {
    let timeoutId;
    return function (...args) {
        clearTimeout(timeoutId);
        timeoutId = setTimeout(() => func.apply(this, args), delay);
    };
}

// Throttling for high-frequency events
function throttle(func, limit) {
    let inThrottle;
    return function (...args) {
        if (!inThrottle) {
            func.apply(this, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

// Memoization for expensive computations
function memoize(fn, getKey = (...args) => JSON.stringify(args)) {
    const cache = new Map();
    
    return function (...args) {
        const key = getKey(...args);
        
        if (cache.has(key)) {
            return cache.get(key);
        }
        
        const result = fn.apply(this, args);
        cache.set(key, result);
        
        return result;
    };
}

// Example: Memoized expensive calculation
const calculateComplexMetrics = memoize(async (userId, startDate, endDate) => {
    // Expensive database queries and calculations
    const orders = await getOrdersInRange(userId, startDate, endDate);
    const metrics = await computeAdvancedMetrics(orders);
    return metrics;
}, (userId, startDate, endDate) => `${userId}-${startDate}-${endDate}`);

// Binary search for sorted arrays
function binarySearch(array, target, compareFn = (a, b) => a - b) {
    let left = 0;
    let right = array.length - 1;
    
    while (left <= right) {
        const mid = Math.floor((left + right) / 2);
        const comparison = compareFn(array[mid], target);
        
        if (comparison === 0) {
            return mid;
        } else if (comparison < 0) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }
    
    return -1; // Not found
}

// Efficient array operations
function processLargeArray(items) {
    // ✅ Use built-in methods for better performance
    return items
        .filter(item => item.isActive)  // O(n)
        .map(item => transformItem(item))  // O(n)
        .sort((a, b) => a.priority - b.priority);  // O(n log n)
}

// ❌ Avoid: Inefficient nested loops
function findDuplicatesInefficient(array) {
    const duplicates = [];
    for (let i = 0; i < array.length; i++) {
        for (let j = i + 1; j < array.length; j++) {
            if (array[i] === array[j]) {
                duplicates.push(array[i]);
            }
        }
    }
    return duplicates; // O(n²)
}

// ✅ Better: Use Set for O(n) duplicate detection
function findDuplicatesEfficient(array) {
    const seen = new Set();
    const duplicates = new Set();
    
    for (const item of array) {
        if (seen.has(item)) {
            duplicates.add(item);
        } else {
            seen.add(item);
        }
    }
    
    return Array.from(duplicates); // O(n)
}
```

## ✅ Quick Checklist

- [ ] Performance monitoring is in place with metrics collection
- [ ] Database queries use indexes and avoid N+1 problems
- [ ] Caching is implemented at appropriate layers (memory, Redis, CDN)
- [ ] Frontend assets are optimized (minified, compressed, cache headers)
- [ ] Large datasets are processed in streams or batches
- [ ] Appropriate data structures are used (Map vs Object, Set vs Array)
- [ ] Expensive operations are memoized or debounced
- [ ] Memory leaks are prevented with proper cleanup
- [ ] Algorithms have reasonable time complexity for the data size
- [ ] Profiling tools are used to identify actual bottlenecks

---

**Next:** [Code Reviews](./code-reviews.md)
