const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
const port = 5000;

// Middleware
app.use(cors());
app.use(express.json()); // Built-in middleware for parsing JSON
app.use(express.urlencoded({ extended: true })); // Built-in middleware for parsing URL-encoded data

// Database setup
const db = new sqlite3.Database('./users.db', (err) => {
    if (err) {
        console.error('Database opening error:', err.message);
    } else {
        console.log('Connected to the SQLite database.');
    }
});

// Create users table
db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
)`);

// Register endpoint
app.post('/register', (req, res) => {
    const { username, password } = req.body;
    
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            return res.status(500).json({ message: 'Error hashing password' });
        }
        
        const query = 'INSERT INTO users (username, password) VALUES (?, ?)';
        db.run(query, [username, hashedPassword], function(err) {
            if (err) {
                return res.status(500).json({ message: 'Error registering user' });
            }
            res.status(201).json({ id: this.lastID, username });
        });
    });
});

// Login endpoint
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    const query = 'SELECT * FROM users WHERE username = ?';
    db.get(query, [username], (err, row) => {
        if (err || !row) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        
        bcrypt.compare(password, row.password, (err, result) => {
            if (err || !result) {
                return res.status(401).json({ message: 'Invalid credentials' });
            }
            res.status(200).json({ message: 'Login successful', user: { id: row.id, username: row.username } });
        });
    });
});

// Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
