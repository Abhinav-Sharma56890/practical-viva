const jwt = require('jsonwebtoken');
const Joi = require('joi');

const ACCESS_TOKEN_SECRET = 'viva_secret_access_key_123';

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ message: 'Access Denied: No Token Provided' });

    jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid or Expired Token' });
        req.user = user;
        next();
    });
};

// Role-Based Access Control (RBAC)
const authorizeRole = (role) => {
    return (req, res, next) => {
        if (req.user.role !== role) {
            return res.status(403).json({ message: `Access Denied: Requires ${role} role` });
        }
        next();
    };
};

// Input Validation Schemas
const schemas = {
    register: Joi.object({
        name: Joi.string().min(3).required(),
        email: Joi.string().email().required(),
        password: Joi.string().min(6).required(),
        role: Joi.string().valid('user', 'admin').default('user')
    }),
    product: Joi.object({
        name: Joi.string().required(),
        price: Joi.number().positive().required(),
        stock: Joi.number().integer().min(0).required(),
        category: Joi.string().required()
    }),
    order: Joi.object({
        items: Joi.array().items(
            Joi.object({
                productId: Joi.number().required(),
                quantity: Joi.number().integer().positive().required()
            })
        ).min(1).required()
    })
};

const validateRequest = (schema) => {
    return (req, res, next) => {
        const { error } = schema.validate(req.body);
        if (error) return res.status(400).json({ message: error.details[0].message });
        next();
    };
};

module.exports = { authenticateToken, authorizeRole, schemas, validateRequest, ACCESS_TOKEN_SECRET };