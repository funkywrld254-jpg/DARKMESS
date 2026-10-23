
const express = require("express");
const http = require("http");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3").verbose();
const { open } = require("sqlite");
const session = require("express-session");
const multer = require("multer");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error("Set SESSION_SECRET to a random string of at least 32 characters.");
  process.exit(1);
}

app.set("trust proxy", 1);
app.use(express.json({ limit: "20kb" }));

const sessionMiddleware = session({
  name: "darkmess.sid",
  secret: SESSION_SECRET,
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

const uploadDir = path.join(__dirname, "uploads");
fs.mkdirSync(uploadDir, { recursive: true });

const allowedTypes = new Set([
  "image/jpeg", "image/png", "image/gif", "image/webp",
  "video/mp4", "video/webm",
  "audio/webm", "audio/ogg", "audio/mpeg",
  "application/pdf", "text/plain"
]);

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, callback) => callback(null, uploadDir),
    filename: (_req, file, callback) => {
      const ext = path.extname(file.originalname).toLowerCase().slice(0, 10);
      callback(null, crypto.randomUUID() + ext);
    }
  }),
  limits: { fileSize: 15 * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, callback) => {
    if (!allowedTypes.has(file.mimetype)) {
      return callback(new Error("This file type is not allowed."));
    }
    callback(null, true);
  }
});

let db;
const onlineCounts = new Map();

function requireLogin(req, res, next) {
  if (!req.session || !req.session.username) {
    return res.status(401).json({
      success: false,
      message: "Please log in first."
    });
  }
  next();
}

function userRoom(name) {
  return "user:" + name.toLowerCase();
}

async function addColumnIfMissing(table, column, definition) {
  const columns = await db.all(`PRAGMA table_info(${table})`);
  if (!columns.some(col => col.name === column)) {
    await db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

async function initializeDatabase() {
  db = await open({
    filename: process.env.DB_PATH || path.join(__dirname, "database.sqlite"),
    driver: sqlite3.Database
  });

  await db.exec(`
    PRAGMA foreign_keys = ON;

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

  // Safely extend the existing messages table without deleting old rows.
  await addColumnIfMissing("messages", "recipient", "TEXT");
  await addColumnIfMissing("messages", "media_url", "TEXT");
  await addColumnIfMissing("messages", "media_type", "TEXT");
  await addColumnIfMissing("messages", "reply_to_text", "TEXT");
  await addColumnIfMissing("messages", "reaction", "TEXT");

  console.log("darkmess database is ready.");
}

app.get("/api/health", (_req, res) => {
  res.json({ success: true, status: "ok" });
});

app.post("/api/signup", async (req, res) => {
  try {
    const username = typeof req.body.username === "string"
      ? req.body.username.trim()
      : "";
    const password = typeof req.body.password === "string"
      ? req.body.password
      : "";

    if (!/^[a-zA-Z0-9_]{3,24}$/.test(username)) {
      return res.status(400).json({
        success: false,
        message: "Username must be 3–24 letters, numbers or underscores."
      });
    }

    if (password.length < 6 || password.length > 72) {
      return res.status(400).json({
        success: false,
        message: "Password must be between 6 and 72 characters."
      });
    }

    const existing = await db.get(
      "SELECT id FROM users WHERE LOWER(username) = LOWER(?)",
      username
    );

    if (existing) {
      return res.status(409).json({
        success: false,
        message: "Username already taken."
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const result = await db.run(
      "INSERT INTO users (username, password) VALUES (?, ?)",
      [username, hashedPassword]
    );

    req.session.username = username;
    req.session.userId = result.lastID;

    req.session.save(err => {
      if (err) {
        console.error("Session save error:", err);
        return res.status(500).json({
          success: false,
          message: "Account created, but login failed. Try logging in."
        });
      }
      res.status(201).json({ success: true, username });
    });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({
      success: false,
      message: "Could not create account. Please try again."
    });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const username = typeof req.body.username === "string"
      ? req.body.username.trim()
      : "";
    const password = typeof req.body.password === "string"
      ? req.body.password
      : "";

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Enter your username and password."
      });
    }

    const user = await db.get(
      "SELECT * FROM users WHERE LOWER(username) = LOWER(?)",
      username
    );

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        success: false,
        message: "Incorrect username or password."
      });
    }

    // Prevent the session ID from being reused after authentication.
    req.session.regenerate(err => {
      if (err) {
        console.error("Session regenerate error:", err);
        return res.status(500).json({
          success: false,
          message: "Login failed. Please try again."
        });
      }

      req.session.username = user.username;
      req.session.userId = user.id;

      req.session.save(saveErr => {
        if (saveErr) {
          console.error("Session save error:", saveErr);
          return res.status(500).json({
            success: false,
            message: "Could not save login session."
          });
        }
        res.json({ success: true, username: user.username });
      });
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({
      success: false,
      message: "Server error during login."
    });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({
        success: false,
        message: "Could not log out."
      });
    }
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
      users: users.map(user => ({
        username: user.username,
        online: (onlineCounts.get(user.username.toLowerCase()) || 0) > 0
      }))
    });
  } catch (err) {
    console.error("Users error:", err);
    res.status(500).json({ success: false, message: "Could not load users." });
  }
});

app.post("/api/upload", requireLogin, (req, res) => {
  upload.single("file")(req, res, err => {
    if (err) {
      const status = err instanceof multer.MulterError ? 400 : 400;
      return res.status(status).json({
        success: false,
        message: err.message || "Upload failed."
      });
    }

    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: "Choose a file first."
      });
    }

    res.status(201).json({
      success: true,
      url: "/uploads/" + req.file.filename,
      mimeType: req.file.mimetype
    });
  });
});

// Uploaded files are served by URL. This is not private media storage.
app.use("/uploads", express.static(uploadDir, {
  dotfiles: "deny",
  index: false,
  maxAge: "1h"
}));

io.use((socket, next) => {
  const sessionData = socket.request.session;
  if (!sessionData || !sessionData.username) {
    return next(new Error("Please log in first."));
  }
  socket.username = sessionData.username;
  next();
});

io.on("connection", socket => {
  const username = socket.username;
  const key = username.toLowerCase();

  socket.join(userRoom(username));
  onlineCounts.set(key, (onlineCounts.get(key) || 0) + 1);
  io.emit("user online", { username });

  socket.on("join chat", async () => {
    // Ignore usernames sent by the browser; use the authenticated session.
    try {
      const history = await db.all(
        `SELECT id, username AS user, username, text, timestamp,
                media_url AS mediaUrl, media_type AS mediaType,
                reply_to_text AS replyToText, reaction
         FROM messages
         WHERE recipient IS NULL
         ORDER BY id DESC LIMIT 50`
      );
      socket.emit("chat history", history.reverse());
    } catch (err) {
      console.error("History error:", err);
    }
  });

  socket.on("open conversation", async data => {
    try {
      const other = typeof data?.with === "string" ? data.with.trim() : "";
      if (!other || other.toLowerCase() === key) return;

      const target = await db.get(
        "SELECT username FROM users WHERE LOWER(username) = LOWER(?)",
        other
      );
      if (!target) return;

      const history = await db.all(
        `SELECT id, username AS user, username, text, timestamp,
                media_url AS mediaUrl, media_type AS mediaType,
                reply_to_text AS replyToText, reaction
         FROM messages
         WHERE (LOWER(username) = LOWER(?) AND LOWER(recipient) = LOWER(?))
            OR (LOWER(username) = LOWER(?) AND LOWER(recipient) = LOWER(?))
         ORDER BY id DESC LIMIT 100`,
        [username, target.username, target.username, username]
      );

      socket.emit("chat history", history.reverse());
    } catch (err) {
      console.error("Private history error:", err);
    }
  });

  socket.on("chat message", async data => {
    try {
      if (!data || typeof data !== "object") return;

      const text = typeof data.text === "string" ? data.text.trim() : "";
      const mediaUrl = typeof data.mediaUrl === "string" ? data.mediaUrl : null;
      const mediaType = typeof data.mediaType === "string" ? data.mediaType : null;
      const recipient = typeof data.to === "string" ? data.to.trim() : "";

      if ((!text && !mediaUrl) || text.length > 4000) return;
      if (!recipient || recipient.toLowerCase() === key) return;

      const target = await db.get(
        "SELECT username FROM users WHERE LOWER(username) = LOWER(?)",
        recipient
      );
      if (!target) {
        socket.emit("chat error", { message: "That user does not exist." });
        return;
      }

      if (mediaUrl && !/^\/uploads\/[a-zA-Z0-9-]+\.[a-zA-Z0-9]+$/.test(mediaUrl)) {
        return;
      }

      const result = await db.run(
        `INSERT INTO messages
          (username, text, recipient, media_url, media_type, reply_to_text)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [
          username, text, target.username, mediaUrl, mediaType,
          typeof data.replyToText === "string" ? data.replyToText.slice(0, 500) : null
        ]
      );

      const message = {
        id: result.lastID,
        username,
        user: username,
        text,
        recipient: target.username,
        mediaUrl,
        mediaType,
        replyToText: typeof data.replyToText === "string" ? data.replyToText : null,
        timestamp: new Date().toISOString()
      };

      io.to(userRoom(username)).emit("chat message", message);
      io.to(userRoom(target.username)).emit("chat message", message);
    } catch (err) {
      console.error("Message error:", err);
      socket.emit("chat error", { message: "Could not send message." });
    }
  });

  socket.on("typing", data => {
    if (!data || typeof data.to !== "string") return;
    const target = data.to.trim();
    if (!target || target.toLowerCase() === key) return;
    io.to(userRoom(target)).emit("typing", {
      username,
      isTyping: Boolean(data.isTyping)
    });
  });

  socket.on("message reaction", async data => {
    try {
      if (!data || !Number.isInteger(Number(data.id))) return;
      const allowedReactions = ["❤️", "😂", "😮", "😢", "👍", "🔥"];
      if (!allowedReactions.includes(data.reaction)) return;

      const message = await db.get(
        "SELECT username, recipient FROM messages WHERE id = ?",
        Number(data.id)
      );
      if (!message) return;

      const isParticipant =
        message.username.toLowerCase() === key ||
        (message.recipient && message.recipient.toLowerCase() === key);
      if (!isParticipant) return;

      await db.run("UPDATE messages SET reaction = ? WHERE id = ?", [
        data.reaction, Number(data.id)
      ]);

      const payload = { id: Number(data.id), reaction: data.reaction };
      io.to(userRoom(message.username)).emit("message reaction", payload);
      if (message.recipient) {
        io.to(userRoom(message.recipient)).emit("message reaction", payload);
      }
    } catch (err) {
      console.error("Reaction error:", err);
    }
  });

  socket.on("delete message", async data => {
    try {
      const id = Number(data?.id);
      if (!Number.isInteger(id) || id < 1) return;

      const message = await db.get(
        "SELECT id, username, recipient FROM messages WHERE id = ?",
        id
      );
      if (!message || message.username.toLowerCase() !== key) return;

      await db.run("DELETE FROM messages WHERE id = ?", id);
      const payload = { id };
      io.to(userRoom(message.username)).emit("message deleted", payload);
      if (message.recipient) {
        io.to(userRoom(message.recipient)).emit("message deleted", payload);
      }
    } catch (err) {
      console.error("Delete message error:", err);
    }
  });

  socket.on("disconnect", () => {
    const remaining = Math.max(0, (onlineCounts.get(key) || 1) - 1);
    if (remaining === 0) {
      onlineCounts.delete(key);
      io.emit("user offline", { username });
    } else {
      onlineCounts.set(key, remaining);
    }
  });
  app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

initializeDatabase()
  .then(() => {
    server.listen(PORT, "0.0.0.0", () => {
      console.log(`darkmess is running on port ${PORT}`);
    });
  })
  .catch(err => {
    console.error("Could not start darkmess:", err);
    process.exit(1);
  });
    
