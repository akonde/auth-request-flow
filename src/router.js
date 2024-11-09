const express = require('express');
const jwt = require('jsonwebtoken');

const router = express.Router();

// Mock user data
const mockUser = {
    username: 'authguy',
    password: 'mypassword',
    profile: {
        firstName: 'Chris',
        lastName: 'Wolstenholme',
        age: 43
    }
};

// Secret key for JWT
const SECRET_KEY = 'anysecretkey';

// Login route to authenticate and generate token
router.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Check if username and password match mockUser
    if (username === mockUser.username && password === mockUser.password) {
        // Generate JWT with username as payload
        const token = jwt.sign({ username: mockUser.username }, SECRET_KEY, { expiresIn: '1h' });

        // Send token as response
        return res.json({ token });
    }

    // If credentials don't match, send an error
    return res.status(401).json({ error: 'Invalid credentials' });
});

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.sendStatus(401); // No token provided

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403); // Invalid token

        // Attach user to request for use in next handler
        req.user = user;
        next();
    });
};

// Protected profile route to return user profile
router.get('/profile', authenticateToken, (req, res) => {
    // Directly return mockUser's profile, as authentication is already done
    res.json(mockUser.profile);
});

module.exports = router;
