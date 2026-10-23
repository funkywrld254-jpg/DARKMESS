// server.js - darkmess Core Backend with SQLite Database
const express = require('express');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');

app.use(express.json());
app.use(express.static(__dirname));

let db;

(async () => {
    db = await open({
        filename: './database.sqlite',
        driver: sqlite3.Database
    });

    await db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            text TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    `);
    console.log('Database initialized successfully.');
})();

app.post('/api/signup', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ error: "Fill all fields" });
        
        const hashedPassword = await bcrypt.hash(password, 10);
        await db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);
        
        res.status(201).json({ success: true, username });
    } catch (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ error: "Username already taken" });
        }
        res.status(500).json({ error: "Server error" });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await db.get('SELECT * FROM users WHERE LOWER(username) = LOWER(?)', [username]);
        
        if (!user) return res.status(400).json({ error: "User not found" });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: "Wrong password" });

        res.json({ success: true, username: user.username });
    } catch (err) {
        res.status(500).json({ error: "Server error" });
    }
});

io.on('connection', (socket) => {
    socket.on('join chat', async (username) => {
        socket.username = username;
        try {
            const history = await db.all('SELECT username as user, text FROM messages ORDER BY id DESC LIMIT 50');
            socket.emit('chat history', history.reverse());
        } catch (err) {
            console.error('Error fetching history:', err);
        }
        io.emit('chat message', { user: 'System', text: `${username} joined darkmess.` });
    });

    socket.on('chat message', async (msg) => {
        const user = socket.username || 'Anonymous';
        try {
            await db.run('INSERT INTO messages (username, text) VALUES (?, ?)', [user, msg]);
        } catch (err) {
            console.error('Error saving message:', err);
        }
        io.emit('chat message', { user, text: msg });
    });

    socket.on('disconnect', () => {
        if(socket.username) {
            io.emit('chat message', { user: 'System', text: `${socket.username} left the chat.` });
        }
    });
});
const PORT = process.env.PORT || 3000;

http.listen(PORT, '0.0.0.0', () => {
    console.log(`darkmess is running on port ${PORT}`);
});
