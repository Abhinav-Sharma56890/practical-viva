const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { users, products, orders, refreshTokens, calculateTotal } = require('./db');
const { 
    authenticateToken, 
    authorizeRole, 
    schemas, 
    validateRequest, 
    ACCESS_TOKEN_SECRET 
} = require('./middleware');

const app = express();
app.use(express.json());

const REFRESH_TOKEN_SECRET = 'viva_refresh_secret_key_456';

// Rate Limiting: Prevent Brute Force/Spam
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    message: "Too many requests, please try again later."
});
app.use('/api/', apiLimiter);

// --- AUTH ROUTES ---

app.post('/api/register', validateRequest(schemas.register), async (req, res) => {
    const { name, email, password, role } = req.body;
    if (users.find(u => u.email === email)) return res.status(400).json({ message: 'User already exists' });

    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = { id: users.length + 1, name, email, passwordHash, role: role || 'user', createdAt: new Date() };
    users.push(newUser);

    res.status(201).json({ message: 'User registered successfully' });
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email);
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    const payload = { id: user.id, email: user.email, role: user.role };
    const accessToken = jwt.sign(payload, ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign(payload, REFRESH_TOKEN_SECRET);
    
    refreshTokens.add(refreshToken);
    res.json({ accessToken, refreshToken });
});

app.post('/api/token', (req, res) => {
    const { token } = req.body;
    if (!token || !refreshTokens.has(token)) return res.sendStatus(403);
    
    jwt.verify(token, REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        const accessToken = jwt.sign({ id: user.id, email: user.email, role: user.role }, ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
        res.json({ accessToken });
    });
});

// --- PRODUCT ROUTES (Admin Only) ---

app.post('/api/products', authenticateToken, authorizeRole('admin'), validateRequest(schemas.product), (req, res) => {
    const product = { id: products.length + 1, ...req.body };
    products.push(product);
    res.status(201).json(product);
});

app.delete('/api/products/:id', authenticateToken, authorizeRole('admin'), (req, res) => {
    const index = products.findIndex(p => p.id === parseInt(req.params.id));
    if (index === -1) return res.status(404).json({ message: 'Product not found' });
    products.splice(index, 1);
    res.json({ message: 'Product deleted' });
});

// --- ORDER ROUTES ---

app.post('/api/orders', authenticateToken, validateRequest(schemas.order), (req, res) => {
    const { items } = req.body; // Array of { productId, quantity }

    // Prevent ordering out-of-stock items
    for (const item of items) {
        const product = products.find(p => p.id === item.productId);
        if (!product) return res.status(404).json({ message: `Product ${item.productId} not found` });
        if (product.stock < item.quantity) {
            return res.status(400).json({ message: `Insufficient stock for ${product.name}` });
        }
    }

    // Deduct stock and Create Order
    items.forEach(item => {
        const product = products.find(p => p.id === item.productId);
        product.stock -= item.quantity;
    });

    const orderId = orders.length + 1;
    const newOrder = {
        id: orderId,
        userId: req.user.id,
        items,
        status: 'pending',
        createdAt: new Date()
    };

    orders.push(newOrder);
    
    // Use the logic challenge function to finalize order data
    newOrder.totalAmount = calculateTotal(orderId);

    res.status(201).json(newOrder);
});

app.get('/api/orders/me', authenticateToken, (req, res) => {
    const userOrders = orders.filter(o => o.userId === req.user.id);
    res.json(userOrders);
});

app.get('/api/products', (req, res) => {
    res.json(products);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`E-Commerce API running on http://localhost:${PORT}`);
});