
const express = require("express");
const http = require("http");
const path = require("path");
const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3").verbose();
const { open } = require("sqlite");
const session = require("express-session");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = process.env.PORT || 3000;
const SECRET = process.env.SESSION_SECRET;

if (!SECRET || SECRET.length < 32) {
  console.error("Add SESSION_SECRET in Render Environment (32+ characters).");
  process.exit(1);
}

app.set("trust proxy", 1);
app.use(express.json({ limit: "20kb" }));

const sessionMiddleware = session({
  name: "darkmess.sid",
  secret: SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
});

app.use(sessionMiddleware);
io.engine.use(sessionMiddleware);

// Serve index.html and other website files.
app.use(express.static(__dirname));
app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

let db;
const online = new Map();
const room = username => "user:" + username.toLowerCase();

function requireLogin(req, res, next) {
  if (!req.session.username) {
    return res.status(401).json({
      success: false,
      message: "Please log in first."
    });
  }
  next();
}

async function initDB() {
  db = await open({
    filename: process.env.DB_PATH || path.join(__dirname, "database.sqlite"),
    driver: sqlite3.Database
  });

  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT,
      text TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  const cols = await db.all("PRAGMA table_info(messages)");
  if (!cols.some(c => c.name === "recipient")) {
    await db.exec("ALTER TABLE messages ADD COLUMN recipient TEXT");
  }

  console.log("darkmess database ready.");
}

app.get("/api/health", (_req, res) => {
  res.json({ success: true });
});

app.post("/api/signup", async (req, res) => {
  try {
    const username = typeof req.body.username === "string"
      ? req.body.username.trim() : "";
    const password = typeof req.body.password === "string"
      ? req.body.password : "";

    if (!/^[a-zA-Z0-9_]{3,24}$/.test(username)) {
      return res.status(400).json({
        success: false,
        message: "Username must be 3–24 letters, numbers or underscores."
      });
    }
    if (password.length < 6 || password.length > 72) {
      return res.status(400).json({
        success: false,
        message: "Password must be 6–72 characters."
      });
    }

    const exists = await db.get(
      "SELECT id FROM users WHERE LOWER(username)=LOWER(?)", username
    );
    if (exists) {
      return res.status(409).json({
        success: false,
        message: "Username already taken."
      });
    }

    const hash = await bcrypt.hash(password, 12);
    const result = await db.run(
      "INSERT INTO users (username,password) VALUES (?,?)",
      [username, hash]
    );

    req.session.username = username;
    req.session.userId = result.lastID;
    req.session.save(err => {
      if (err) return res.status(500).json({
        success: false, message: "Account created, but login failed."
      });
      res.status(201).json({ success: true, username });
    });
  } catch (err) {
    console.error("Signup:", err);
    res.status(500).json({ success: false, message: "Signup failed." });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const username = typeof req.body.username === "string"
      ? req.body.username.trim() : "";
    const password = typeof req.body.password === "string"
      ? req.body.password : "";

    const user = await db.get(
      "SELECT * FROM users WHERE LOWER(username)=LOWER(?)", username
    );

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        success: false, message: "Incorrect username or password."
      });
    }

    req.session.regenerate(err => {
      if (err) return res.status(500).json({
        success: false, message: "Login failed."
      });
      req.session.username = user.username;
      req.session.userId = user.id;
      req.session.save(saveErr => {
        if (saveErr) return res.status(500).json({
          success: false, message: "Could not save login."
        });
        res.json({ success: true, username: user.username });
      });
    });
  } catch (err) {
    console.error("Login:", err);
    res.status(500).json({ success: false, message: "Login failed." });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ success: false });
    res.clearCookie("darkmess.sid");
    res.json({ success: true });
  });
});

app.get("/api/users", requireLogin, async (req, res) => {
  try {
    const users = await db.all(
      "SELECT username FROM users WHERE LOWER(username) != LOWER(?) ORDER BY username",
      req.session.username
    );
    res.json({
      users: users.map(u => ({
        username: u.username,
        online: (online.get(u.username.toLowerCase()) || 0) > 0
      }))
    });
  } catch (err) {
    console.error("Users:", err);
    res.status(500).json({ success: false, message: "Could not load users." });
  }
});

io.use((socket, next) => {
  const s = socket.request.session;
  if (!s || !s.username) return next(new Error("Please log in."));
  socket.username = s.username;
  next();
});

io.on("connection", socket => {
  const username = socket.username;
  const key = username.toLowerCase();
  socket.join(room(username));
  online.set(key, (online.get(key) || 0) + 1);
  io.emit("user online", { username });

  socket.on("open conversation", async data => {
    try {
      const other = typeof data?.with === "string" ? data.with.trim() : "";
      if (!other || other.toLowerCase() === key) return;

      const target = await db.get(
        "SELECT username FROM users WHERE LOWER(username)=LOWER(?)", other
      );
      if (!target) return;

      const history = await db.all(`
        SELECT id, username AS user, username, text, timestamp
        FROM messages
        WHERE (LOWER(username)=LOWER(?) AND LOWER(recipient)=LOWER(?))
           OR (LOWER(username)=LOWER(?) AND LOWER(recipient)=LOWER(?))
        ORDER BY id DESC LIMIT 100
      `, [username, target.username, target.username, username]);

      socket.emit("chat history", history.reverse());
    } catch (err) {
      console.error("History:", err);
    }
  });

  socket.on("chat message", async data => {
    try {
      const text = typeof data?.text === "string" ? data.text.trim() : "";
      const to = typeof data?.to === "string" ? data.to.trim() : "";
      if (!text || text.length > 4000 || !to || to.toLowerCase() === key) return;

      const target = await db.get(
        "SELECT username FROM users WHERE LOWER(username)=LOWER(?)", to
      );
      if (!target) {
        socket.emit("chat error", { message: "User not found." });
        return;
      }

      const result = await db.run(
        "INSERT INTO messages (username,text,recipient) VALUES (?,?,?)",
        [username, text, target.username]
      );

      const message = {
        id: result.lastID,
        user: username,
        username,
        text,
        timestamp: new Date().toISOString(),
        recipient: target.username
      };
      io.to(room(username)).emit("chat message", message);
      io.to(room(target.username)).emit("chat message", message);
    } catch (err) {
      console.error("Message:", err);
      socket.emit("chat error", { message: "Could not send message." });
    }
  });

  socket.on("disconnect", () => {
    const count = Math.max(0, (online.get(key) || 1) - 1);
    if (count) online.set(key, count);
    else {
      online.delete(key);
      io.emit("user offline", { username });
    }
  });
});

initDB().then(() => {
  server.listen(PORT, "0.0.0.0", () => {
    console.log(`darkmess is running on port ${PORT}`);
  });
}).catch(err => {
  console.error("Database startup failed:", err);
  process.exit(1);
});
              
