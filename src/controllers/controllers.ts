import bcrypt from "bcrypt";
import sanitizeText from "../sanitizeTextInput";
import {db} from "../db-connector/main-db";
import {SALT_ROUNDS} from "../index";



/*export  const signin = (req,res)=>{
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
}*/