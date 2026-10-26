
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const SESSION_SECRET = process.env.SESSION_SECRET;
const CLOUDINARY_URL = process.env.CLOUDINARY_URL;

if (!DATABASE_URL) throw new Error("Missing DATABASE_URL");
if (!SESSION_SECRET || SESSION_SECRET.length < 32)
  throw new Error("SESSION_SECRET must be at least 32 characters");
if (!CLOUDINARY_URL) throw new Error("Missing CLOUDINARY_URL");

cloudinary.config({ secure: true });

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL.includes("localhost")
    ? false
    : { rejectUnauthorized: false }
});

app.set("trust proxy", 1);
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

const sessionMiddleware = session({
  store: new pgSession({
    pool,
    tableName: "user_sessions",
    createTableIfMissing: true
  }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
});

app.use(sessionMiddleware);
app.use(express.static(__dirname));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 15 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowed =
      /^(image\/(jpeg|png|gif|webp)|video\/(mp4|webm|quicktime)|audio\/(mpeg|mp4|ogg|wav|webm)|application\/pdf|text\/plain)$/.test(file.mimetype);
    cb(allowed ? null : new Error("File type not supported"), allowed);
  }
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      display_name TEXT,
      profile_picture TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      username TEXT NOT NULL,
      recipient TEXT NOT NULL,
      text TEXT NOT NULL DEFAULT '',
      media_url TEXT,
      media_type TEXT,
      media_name TEXT,
      timestamp TIMESTAMPTZ DEFAULT NOW()
    );
  `);
}

function cleanUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    username: user.username,
    display_name: user.display_name || user.username,
    profile_picture: user.profile_picture || null
  };
}

function requireAuth(req, res, next) {
  if (!req.session.user)
    return res.status(401).json({ error: "Please log in again." });
  next();
}

app.get("/api/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, database: "connected" });
  } catch {
    res.status(500).json({ ok: false });
  }
});

app.get("/api/me", (req, res) => {
  res.json({ user: req.session.user || null });
});

app.post("/api/signup", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!/^[a-z0-9_]{3,20}$/.test(username))
      return res.status(400).json({
        error: "Username must be 3–20 letters, numbers or underscores."
      });

    if (password.length < 6 || password.length > 128)
      return res.status(400).json({
        error: "Password must be 6–128 characters."
      });

    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      `INSERT INTO users(username,password,display_name)
       VALUES($1,$2,$1)
       RETURNING id,username,display_name,profile_picture`,
      [username, hash]
    );

    req.session.user = cleanUser(result.rows[0]);
    res.json({ user: req.session.user });
  } catch (e) {
    if (e.code === "23505")
      return res.status(409).json({ error: "Username already exists." });
    console.error(e);
    res.status(500).json({ error: "Could not create account." });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const result = await pool.query(
      "SELECT * FROM users WHERE username=$1",
      [username]
    );

    if (!result.rows[0] ||
        !(await bcrypt.compare(password, result.rows[0].password))) {
      return res.status(401).json({
        error: "Incorrect username or password."
      });
    }

    req.session.user = cleanUser(result.rows[0]);
    res.json({ user: req.session.user });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Could not log in." });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/users", requireAuth, async (req, res) => {
  try {
    const q = String(req.query.q || "").trim().toLowerCase();
    const result = await pool.query(
      `SELECT id,username,display_name,profile_picture
       FROM users
       WHERE username <> $1
       AND ($2 = ''
         OR username ILIKE '%' || $2 || '%'
         OR COALESCE(display_name,'') ILIKE '%' || $2 || '%')
       ORDER BY username LIMIT 50`,
      [req.session.user.username, q]
    );
    res.json({ users: result.rows.map(cleanUser) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Could not load users." });
  }
});

app.get("/api/inbox", requireAuth, async (req, res) => {
  try {
    const me = req.session.user.username;
    const result = await pool.query(
      `SELECT DISTINCT ON (peer) peer, text, media_url, media_type, timestamp
       FROM (
         SELECT CASE WHEN username=$1 THEN recipient ELSE username END AS peer,
                text, media_url, media_type, timestamp
         FROM messages WHERE username=$1 OR recipient=$1
       ) t
       ORDER BY peer, timestamp DESC`,
      [me]
    );

    const peers = result.rows;
    if (!peers.length) return res.json({ conversations: [] });

    const users = await pool.query(
      `SELECT username,display_name,profile_picture
       FROM users WHERE username = ANY($1::text[])`,
      [peers.map(p => p.peer)]
    );

    const byName = Object.fromEntries(
      users.rows.map(u => [u.username, cleanUser(u)])
    );

    res.json({
      conversations: peers.map(p => ({
        ...p,
        user: byName[p.peer] || {
          username: p.peer,
          display_name: p.peer
        }
      }))
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Could not load conversations." });
  }
});

app.patch("/api/profile", requireAuth, async (req, res) => {
  try {
    const name = String(req.body.display_name || "").trim().slice(0, 40);
    if (!name)
      return res.status(400).json({ error: "Enter a display name." });

    const result = await pool.query(
      `UPDATE users SET display_name=$1 WHERE username=$2
       RETURNING id,username,display_name,profile_picture`,
      [name, req.session.user.username]
    );

    req.session.user = cleanUser(result.rows[0]);
    res.json({ user: req.session.user });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Could not update profile." });
  }
});

function uploadToCloudinary(file, folder) {
  return new Promise((resolve, reject) => {
    const resourceType = file.mimetype.startsWith("video/") ||
      file.mimetype.startsWith("audio/") ? "video" : "auto";

    const stream = cloudinary.uploader.upload_stream(
      { folder, resource_type: resourceType },
      (err, result) => {
        if (err) return reject(err);
        resolve({
          url: result.secure_url,
          type: file.mimetype,
          name: file.originalname
        });
      }
    );
    stream.end(file.buffer);
  });
}

app.post("/api/profile-picture", requireAuth, upload.single("image"),
  async (req, res) => {
    try {
      if (!req.file || !req.file.mimetype.startsWith("image/"))
        return res.status(400).json({ error: "Choose an image." });

      const media = await uploadToCloudinary(
        req.file, "darkmess/profiles"
      );

      const result = await pool.query(
        `UPDATE users SET profile_picture=$1 WHERE username=$2
         RETURNING id,username,display_name,profile_picture`,
        [media.url, req.session.user.username]
      );

      req.session.user = cleanUser(result.rows[0]);
      res.json({ user: req.session.user });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: "Profile photo upload failed." });
    }
  }
);

app.post("/api/message-upload", requireAuth, upload.single("file"),
  async (req, res) => {
    try {
      if (!req.file)
        return res.status(400).json({ error: "Choose a file." });

      const media = await uploadToCloudinary(
        req.file, "darkmess/messages"
      );
      res.json(media);
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: "Upload failed. Try a smaller file." });
    }
  }
);

app.get("/api/messages/:username", requireAuth, async (req, res) => {
  try {
    const me = req.session.user.username;
    const peer = String(req.params.username || "").toLowerCase();

    const result = await pool.query(
      `SELECT id,username,recipient,text,media_url,media_type,media_name,timestamp
       FROM messages
       WHERE (username=$1 AND recipient=$2)
          OR (username=$2 AND recipient=$1)
       ORDER BY timestamp ASC LIMIT 500`,
      [me, peer]
    );
    res.json({ messages: result.rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Could not load messages." });
  }
});

io.use((socket, next) =>
  sessionMiddleware(socket.request, {}, next)
);

const online = new Map();

io.on("connection", socket => {
  const user = socket.request.session?.user;
  if (!user) {
    socket.disconnect(true);
    return;
  }

  socket.username = user.username;
  online.set(user.username, (online.get(user.username) || 0) + 1);
  io.emit("presence", [...online.keys()]);

  socket.on("open conversation", async peer => {
    peer = String(peer || "").toLowerCase();
    socket.join([`user:${socket.username}`, `user:${peer}`]);

    try {
      const result = await pool.query(
        `SELECT id,username,recipient,text,media_url,media_type,media_name,timestamp
         FROM messages
         WHERE (username=$1 AND recipient=$2)
            OR (username=$2 AND recipient=$1)
         ORDER BY timestamp ASC LIMIT 500`,
        [socket.username, peer]
      );
      socket.emit("conversation history", result.rows);
    } catch (e) {
      console.error(e);
    }
  });

  socket.on("chat message", async payload => {
    try {
      const recipient = String(payload?.recipient || "").toLowerCase();
      const message = String(payload?.text || "").slice(0, 5000);
      const mediaUrl = typeof payload?.media_url === "string"
        ? payload.media_url.slice(0, 2000) : null;
      const mediaType = typeof payload?.media_type === "string"
        ? payload.media_type.slice(0, 100) : null;
      const mediaName = typeof payload?.media_name === "string"
        ? payload.media_name.slice(0, 255) : null;

      if (!recipient || recipient === socket.username ||
          (!message.trim() && !mediaUrl)) return;

      const exists = await pool.query(
        "SELECT 1 FROM users WHERE username=$1", [recipient]
      );
      if (!exists.rowCount)
        return socket.emit("chat error", "That user does not exist.");

      const result = await pool.query(
        `INSERT INTO messages
         (username,recipient,text,media_url,media_type,media_name)
         VALUES($1,$2,$3,$4,$5,$6)
         RETURNING id,username,recipient,text,media_url,media_type,media_name,timestamp`,
        [socket.username, recipient, message, mediaUrl, mediaType, mediaName]
      );

      io.to(`user:${socket.username}`)
        .to(`user:${recipient}`)
        .emit("new message", result.rows[0]);
    } catch (e) {
      console.error(e);
      socket.emit("chat error", "Message could not be sent.");
    }
  });

  socket.on("typing", peer => {
    if (typeof peer === "string" && peer !== socket.username)
      io.to(`user:${peer}`).emit("typing", socket.username);
  });

  socket.on("stop typing", peer => {
    if (typeof peer === "string" && peer !== socket.username)
      io.to(`user:${peer}`).emit("stop typing", socket.username);
  });

  socket.on("disconnect", () => {
    const count = (online.get(socket.username) || 1) - 1;
    if (count <= 0) online.delete(socket.username);
    else online.set(socket.username, count);
    io.emit("presence", [...online.keys()]);
  });
});

app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({
      error: err.code === "LIMIT_FILE_SIZE"
        ? "File must be 15 MB or smaller."
        : "Upload limit reached."
    });
  }
  res.status(400).json({ error: err.message || "Request failed." });
});

initDb()
  .then(() => server.listen(PORT, () =>
    console.log(`darkmess running on port ${PORT}`)
  ))
  .catch(err => {
    console.error("Database setup failed:", err);
    process.exit(1);
  });
