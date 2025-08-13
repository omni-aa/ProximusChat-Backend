import sqlite3 from "sqlite3";

export  const db = new sqlite3.Database("./chat.db", (err) => {
    if (err) console.error("DB error:", err);
    else console.log("Connected to SQLite");
});