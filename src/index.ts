import express from "express";
import http from "http";
import { Server } from "socket.io";
import sqlite3 from "sqlite3";
import cors from "cors";
import multer from "multer";
import path from "path";
import fs from "fs";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"],
    },
});

app.use(cors());
app.use(express.json());

const JWT_SECRET = "your_super_secret_key";
const SALT_ROUNDS = 10;

const UPLOADS_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOADS_DIR)) {
    fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, UPLOADS_DIR);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
        const ext = path.extname(file.originalname);
        cb(null, file.fieldname + "-" + uniqueSuffix + ext);
    },
});
const upload = multer({
    storage,
    fileFilter: (req, file, cb) => {
        const allowed = /\.(jpg|jpeg|png|gif|webp|pdf|txt|docx)$/i;
        if (!allowed.test(file.originalname)) {
            return cb(new Error("Invalid file type"));
        }
        cb(null, true);
    },
    limits: { fileSize: 5 * 1024 * 1024 },
});

app.use("/uploads", express.static(UPLOADS_DIR));

const db = new sqlite3.Database("./chat.db", (err) => {
    if (err) console.error("DB error:", err);
    else console.log("Connected to SQLite");
});

// Create tables
db.run(`
    CREATE TABLE IF NOT EXISTS messages (
                                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                                            channel TEXT NOT NULL,
                                            user TEXT NOT NULL,
                                            message TEXT,
                                            fileUrl TEXT,
                                            fileName TEXT,
                                            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`);

db.run(`
    CREATE TABLE IF NOT EXISTS users (
                                         id INTEGER PRIMARY KEY AUTOINCREMENT,
                                         username TEXT UNIQUE NOT NULL,
                                         password_hash TEXT NOT NULL,
                                         created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`);

db.run(`
    CREATE TABLE IF NOT EXISTS channels (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL
    )
`);

// Insert default channels if not exist


// Type definitions
interface UserRow {
    id: number;
    username: string;
    password_hash: string;
    created_at: string;
}

interface ChannelRow {
    id: number;
    name: string;
}

interface MessageRow {
    id: number;
    channel: string;
    user: string;
    message: string;
    fileUrl?: string | null;
    fileName?: string | null;
    timestamp: string;
}

function sanitizeText(input: string, maxLen: number = 50): string {
    let clean = input.trim();
    clean = clean.replace(/[^a-zA-Z0-9 _-]/g, "");
    if (clean.length > maxLen) clean = clean.substring(0, maxLen);
    return clean;
}

// Signup endpoint
app.post("/signup", (req, res) => {
    const { username, password } = req.body;
    if (!username || !password)
        return res.status(400).json({ error: "Missing username or password" });

    const safeUser = sanitizeText(username, 30);
    if (!safeUser)
        return res.status(400).json({ error: "Invalid username" });

    db.get<UserRow>("SELECT * FROM users WHERE username = ?", [safeUser], async (err, row) => {
        if (err) return res.status(500).json({ error: "Database error" });
        if (row) return res.status(400).json({ error: "Username already taken" });

        try {
            const hash = await bcrypt.hash(password, SALT_ROUNDS);
            db.run(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                [safeUser, hash],
                function (err) {
                    if (err) return res.status(500).json({ error: "Database error" });
                    res.json({ message: "User created" });
                }
            );
        } catch {
            res.status(500).json({ error: "Server error" });
        }
    });
});

// Signin endpoint
app.post("/signin", (req, res) => {
    const { username, password } = req.body;
    if (!username || !password)
        return res.status(400).json({ error: "Missing username or password" });

    const safeUser = sanitizeText(username, 30);
    if (!safeUser)
        return res.status(400).json({ error: "Invalid username" });

    db.get<UserRow>("SELECT * FROM users WHERE username = ?", [safeUser], async (err, user) => {
        if (err) return res.status(500).json({ error: "Database error" });
        if (!user) return res.status(400).json({ error: "Invalid username or password" });

        try {
            const match = await bcrypt.compare(password, user.password_hash);
            if (!match) return res.status(400).json({ error: "Invalid username or password" });

            const token = jwt.sign({ username: safeUser }, JWT_SECRET, { expiresIn: "1h" });
            return res.json({ message: "Authenticated", token, username: safeUser });
        } catch {
            return res.status(500).json({ error: "Server error" });
        }
    });
});

// File upload
app.post("/upload", (req, res) => {
    upload.single("file")(req, res, (err) => {
        if (err) {
            console.error("Upload error:", err.message);
            return res.status(400).json({ error: err.message });
        }
        if (!req.file) {
            return res.status(400).json({ error: "No file uploaded" });
        }

        const fileUrl = `/uploads/${req.file.filename}`;
        const originalName = req.file.originalname;
        res.json({ url: fileUrl, originalName });
    });
});

// Get channels from DB
app.get("/channels", (req, res) => {
    db.all<ChannelRow>("SELECT name FROM channels ORDER BY name ASC", (err, rows) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: "Database error" });
        }
        res.json(rows.map(r => r.name));
    });
});

// Socket.io authentication middleware
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) return next(new Error("Authentication error"));

    jwt.verify(token, JWT_SECRET, (err: any, decoded: any) => {
        if (err) return next(new Error("Authentication error"));

        const username = decoded.username;
        db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
            if (err || !row) return next(new Error("Authentication error"));
            socket.data.username = username;
            next();
        });
    });
});


const onlineUsers = new Set<string>();

io.on("connection", (socket) => {
    const currentUser = socket.data.username;
    console.log("User connected:", socket.id, "username:", currentUser);

    if (currentUser) onlineUsers.add(currentUser);
    io.emit("online_users", Array.from(onlineUsers));

    socket.on("join_channel", (channel: string) => {
        const safeChannel = sanitizeText(channel, 30);
        if (!safeChannel) return;

        db.get<ChannelRow>("SELECT name FROM channels WHERE name = ?", [safeChannel], (err, row) => {
            if (err) {
                console.error("DB error on join_channel:", err);
                return;
            }
            if (!row) {
                console.warn(`Channel ${safeChannel} not found, join rejected`);
                return;
            }

            socket.join(safeChannel);
            console.log(`${socket.id} joined channel: ${safeChannel}`);

            db.all<MessageRow>(
                `SELECT * FROM messages WHERE channel = ? ORDER BY timestamp DESC LIMIT 100`,
                [safeChannel],
                (err, rows) => {
                    if (err) {
                        console.error(err);
                        return;
                    }
                    socket.emit("channel_history", rows.reverse());
                }
            );
        });
    });

    socket.on("send_message", (msg) => {
        const safeUser = socket.data.username;
        const safeChannel = sanitizeText(msg.channel, 30);
        const safeMessage = msg.message?.toString().trim() || "";

        if (!safeChannel || !safeUser || (!safeMessage && !msg.fileUrl)) {
            return; // invalid data
        }

        // Check user existence before inserting message
        db.get("SELECT * FROM users WHERE username = ?", [safeUser], (err, row) => {
            if (err) {
                console.error(err);
                return;
            }
            if (!row) {
                // User no longer exists — disconnect and notify client
                socket.emit("force_logout", "Your account was deleted.");
                socket.disconnect(true);
                return;
            }

            // User exists — proceed with message insertion
            db.run(
                `INSERT INTO messages (channel, user, message, fileUrl, fileName) VALUES (?, ?, ?, ?, ?)`,
                [safeChannel, safeUser, safeMessage, msg.fileUrl || null, msg.fileName || null],
                function (err) {
                    if (err) {
                        console.error(err);
                        return;
                    }
                    io.to(safeChannel).emit("receive_message", {
                        id: this.lastID,
                        channel: safeChannel,
                        user: safeUser,
                        message: safeMessage,
                        fileUrl: msg.fileUrl || null,
                        fileName: msg.fileName || null,
                        timestamp: new Date().toISOString(),
                    });
                }
            );
        });
    });


    socket.on("disconnect", () => {
        console.log("User disconnected:", socket.id);
        if (currentUser) {
            onlineUsers.delete(currentUser);
            io.emit("online_users", Array.from(onlineUsers));
        }
    });
});

const PORT = 3001;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
