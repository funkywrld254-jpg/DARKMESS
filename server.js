
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3");
const { open } = require("sqlite");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const SECRET = process.env.SESSION_SECRET;

if (!SECRET || SECRET.length < 32) {
  throw new Error("Set SESSION_SECRET to a random string of at least 32 characters.");
}

app.set("trust proxy", 1);
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

const uploadsDir = path.join(__dirname, "uploads");
fs.mkdirSync(uploadsDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, Date.now() + "-" + require("crypto").randomBytes(8).toString("hex") + ext);
  }
});

const allowedTypes = ["image/jpeg", "image/png", "image/gif", "image/webp"];

const upload = multer({
  storage,
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (allowedTypes.includes(file.mimetype)) cb(null, true);
    else cb(new Error("Use a JPG, PNG, GIF, or WebP image."));
  }
});

const sessionMiddleware = session({
  secret: SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: "auto",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
});

app.use(sessionMiddleware);
io.engine.use(sessionMiddleware);
app.use("/uploads", express.static(uploadsDir));
app.use(express.static(__dirname));

let db;

async function addColumnIfMissing(table, column, definition) {
  const columns = await db.all(`PRAGMA table_info(${table})`);
  if (!columns.some(c => c.name === column)) {
    await db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

async function initDatabase() {
  db = await open({
    filename: path.join(__dirname, "database.sqlite"),
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
      username TEXT NOT NULL,
      text TEXT,
      timestamp TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await addColumnIfMissing("users", "display_name", "TEXT");
  await addColumnIfMissing("users", "profile_picture", "TEXT");
  await addColumnIfMissing("messages", "recipient", "TEXT");
  await addColumnIfMissing("messages", "image", "TEXT");

  await db.exec(`
    CREATE INDEX IF NOT EXISTS messages_sender_idx
    ON messages(username);

    CREATE INDEX IF NOT EXISTS messages_recipient_idx
    ON messages(recipient);
  `);

  console.log("Database ready");
}

function currentUser(req) {
  return req.session?.username || null;
}

function requireLogin(req, res, next) {
  if (!currentUser(req)) {
    return res.status(401).json({ error: "Please log in first." });
  }
  next();
}

function cleanUsername(value) {
  return typeof value === "string" &&
    /^[a-zA-Z0-9_]{3,20}$/.test(value);
}

function publicUser(user) {
  return {
    username: user.username,
    displayName: user.display_name || user.username,
    profilePicture: user.profile_picture || null
  };
}

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/api/health", (req, res) => {
  res.json({ ok: true });
});

app.get("/api/me", requireLogin, async (req, res) => {
  const user = await db.get(
    "SELECT username, display_name, profile_picture FROM users WHERE username = ?",
    currentUser(req)
  );
  if (!user) return res.status(401).json({ error: "Account not found." });
  res.json(publicUser(user));
});

app.post("/api/signup", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");
    const displayName = String(req.body.displayName || username).trim().slice(0, 40);

    if (!cleanUsername(username)) {
      return res.status(400).json({
        error: "Username must be 3–20 characters using letters, numbers, or underscores."
      });
    }

    if (password.length < 8 || password.length > 100) {
      return res.status(400).json({ error: "Password must be 8–100 characters." });
    }

    const hash = await bcrypt.hash(password, 12);

    await db.run(
      "INSERT INTO users (username, password, display_name) VALUES (?, ?, ?)",
      username, hash, displayName || username
    );

    req.session.username = username;
    res.json({ ok: true, username });
  } catch (error) {
    if (error.code === "SQLITE_CONSTRAINT") {
      return res.status(409).json({ error: "That username is already taken." });
    }
    console.error(error);
    res.status(500).json({ error: "Could not create account." });
  }
});

app.post("/api/login", async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  const user = await db.get(
    "SELECT username, password FROM users WHERE username = ?",
    username
  );

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: "Incorrect username or password." });
  }

  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "Login failed." });
    req.session.username = user.username;
    res.json({ ok: true, username: user.username });
  });
});

app.post("/api/logout", (req, res) => {
  const username = currentUser(req);
  if (username) io.to(username).emit("user offline", username);

  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ ok: true });
  });
});

app.patch("/api/profile", requireLogin, async (req, res) => {
  const oldUsername = currentUser(req);
  const newUsername = req.body.username === undefined
    ? oldUsername
    : String(req.body.username).trim();

  const displayName = req.body.displayName === undefined
    ? undefined
    : String(req.body.displayName).trim().slice(0, 40);

  if (!cleanUsername(newUsername)) {
    return res.status(400).json({ error: "Username must be 3–20 letters, numbers, or underscores." });
  }

  try {
    const user = await db.get("SELECT * FROM users WHERE username = ?", oldUsername);
    if (!user) return res.status(404).json({ error: "Account not found." });

    if (newUsername !== oldUsername) {
      await db.run("UPDATE users SET username = ? WHERE username = ?", newUsername, oldUsername);
      await db.run("UPDATE messages SET username = ? WHERE username = ?", newUsername, oldUsername);
      await db.run("UPDATE messages SET recipient = ? WHERE recipient = ?", newUsername, oldUsername);
      req.session.username = newUsername;
    }

    if (displayName !== undefined) {
      await db.run(
        "UPDATE users SET display_name = ? WHERE username = ?",
        displayName || newUsername, newUsername
      );
    }

    res.json({ ok: true, username: newUsername });
  } catch (error) {
    if (error.code === "SQLITE_CONSTRAINT") {
      return res.status(409).json({ error: "That username is already taken." });
    }
    console.error(error);
    res.status(500).json({ error: "Could not update profile." });
  }
});

app.post("/api/profile-picture", requireLogin, upload.single("image"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Choose an image first." });

  const url = "/uploads/" + req.file.filename;
  await db.run(
    "UPDATE users SET profile_picture = ? WHERE username = ?",
    url, currentUser(req)
  );
  res.json({ ok: true, profilePicture: url });
});

app.post("/api/message-image", requireLogin, upload.single("image"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Choose an image first." });
  res.json({ url: "/uploads/" + req.file.filename });
});

app.get("/api/users", requireLogin, async (req, res) => {
  const me = currentUser(req);
  const q = String(req.query.q || "").trim().replace(/^@/, "");

  const users = await db.all(
    `SELECT username, display_name, profile_picture
     FROM users
     WHERE username != ?
       AND (username LIKE ? OR COALESCE(display_name, '') LIKE ?)
     ORDER BY username LIMIT 50`,
    me, `%${q}%`, `%${q}%`
  );

  res.json(users.map(u => ({
    ...publicUser(u),
    online: onlineUsers.has(u.username)
  })));
});

app.get("/api/inbox", requireLogin, async (req, res) => {
  const me = currentUser(req);

  const people = await db.all(
    `SELECT DISTINCT u.username, u.display_name, u.profile_picture
     FROM users u
     JOIN messages m
       ON (m.username = u.username AND m.recipient = ?)
       OR (m.recipient = u.username AND m.username = ?)
     WHERE u.username != ?
     ORDER BY u.username`,
    me, me, me
  );

  res.json(people.map(u => ({
    ...publicUser(u),
    online: onlineUsers.has(u.username)
  })));
});

const onlineUsers = new Set();

io.on("connection", socket => {
  const username = socket.request.session?.username;
  if (!username) return socket.disconnect(true);

  socket.join(username);
  onlineUsers.add(username);
  io.emit("user online", username);
  io.emit("online users", [...onlineUsers]);

  socket.on("open conversation", async data => {
    const target = String(data?.with || "");
    if (!target || target === username) return;

    const exists = await db.get("SELECT id FROM users WHERE username = ?", target);
    if (!exists) return;

    const history = await db.all(
      `SELECT id, username AS user, username, text, timestamp, recipient, image
       FROM messages
       WHERE (username = ? AND recipient = ?)
          OR (username = ? AND recipient = ?)
       ORDER BY id ASC LIMIT 500`,
      username, target, target, username
    );

    socket.emit("chat history", history);
  });

  socket.on("chat message", async data => {
    try {
      const target = String(data?.to || "");
      const messageText = typeof data?.text === "string" ? data.text.trim() : "";
      const image = typeof data?.image === "string" ? data.image : null;

      if (!target || target === username || (!messageText && !image)) return;
      if (messageText.length > 4000) return;

      const recipientExists = await db.get(
        "SELECT username FROM users WHERE username = ?", target
      );
      if (!recipientExists) return;

      if (image && !/^\/uploads\/[a-zA-Z0-9._-]+$/.test(image)) return;

      const result = await db.run(
        `INSERT INTO messages (username, text, recipient, image)
         VALUES (?, ?, ?, ?)`,
        username, messageText, target, image
      );

      const message = await db.get(
        `SELECT id, username AS user, username, text, timestamp, recipient, image
         FROM messages WHERE id = ?`,
        result.lastID
      );

      io.to(username).to(target).emit("chat message", message);
    } catch (error) {
      console.error("Message error:", error);
    }
  });

  socket.on("disconnect", () => {
    const stillConnected = [...io.sockets.sockets.values()].some(
      s => s.request.session?.username === username
    );
    if (!stillConnected) {
      onlineUsers.delete(username);
      io.emit("user offline", username);
      io.emit("online users", [...onlineUsers]);
    }
  });
});

app.use((err, req, res, next) => {
  console.error(err.message);
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: "Image too large. Maximum size is 8 MB." });
  }
  res.status(400).json({ error: err.message || "Request failed." });
});

initDatabase().then(() => {
  server.listen(PORT, "0.0.0.0", () => {
    console.log("Darkmess running on port " + PORT);
  });
}).catch(error => {
  console.error("Startup failed:", error);
  process.exit(1);
});
    
