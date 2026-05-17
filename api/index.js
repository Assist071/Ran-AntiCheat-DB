import express from 'express';
import pg from 'pg';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import rateLimit from 'express-rate-limit';

dotenv.config();

const { Pool } = pg;
const app = express();

// Trust Vercel's proxy for rate limiter to work correctly
app.set('trust proxy', 1);

app.use(cors());
app.use(express.json());

// --- RATE LIMITERS ---
const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 150, // Limit each IP to 150 requests per windowMs
    message: { error: 'Too many requests, please try again later.' }
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // Limit each IP to 10 login requests per windowMs
    message: { success: false, message: 'Too many login attempts, please try again later.' }
});

// Apply general limiter to all API routes
app.use('/api/', apiLimiter);

// Set Timezone to Manila for the database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } // Required for Neon
});

// Helper to get Client IP
const getClientIp = (req) => {
    const forwarded = req.headers['x-forwarded-for'];
    return forwarded ? forwarded.split(',')[0] : req.socket.remoteAddress;
};

// Auto-update database schema for instances
pool.query('ALTER TABLE logs ADD COLUMN IF NOT EXISTS instances INT DEFAULT 0;').catch(err => console.error("DB Alter Error:", err));

// Auto-create users table for authentication
const initAuthDb = async () => {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS admin_users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role VARCHAR(20) DEFAULT 'admin'
            );
        `);
        // Seed initial users if table is empty
        const checkUsers = await pool.query('SELECT * FROM admin_users LIMIT 1');
        if (checkUsers.rows.length === 0) {
            const adminHash = await bcrypt.hash('adminadmin', 10);
            await pool.query('INSERT INTO admin_users (username, password_hash, role) VALUES ($1, $2, $3)', ['crimsonranep9', adminHash, 'admin']);
            console.log("Default admin account created in DB!");
        }
    } catch (err) {
        console.error("Auth DB Init Error:", err);
    }
};
initAuthDb();

// --- CLIENT ENDPOINTS ---

app.post('/api/submit-log', async (req, res) => {
    const { hwid, status, details, instances } = req.body;
    const clientInstances = parseInt(instances) || 0;
    const ip = getClientIp(req);

    try {
        const checkLog = await pool.query('SELECT * FROM logs WHERE hwid = $1', [hwid]);

        if (checkLog.rows.length > 0) {
            await pool.query(
                'UPDATE logs SET ip = $1, status = $2, last_online = NOW(), instances = $3 WHERE hwid = $4',
                [ip, status || 'online', clientInstances, hwid]
            );
        } else {
            await pool.query(
                'INSERT INTO logs (hwid, ip, status, last_online, instances) VALUES ($1, $2, $3, NOW(), $4)',
                [hwid, ip, status || 'online', clientInstances]
            );
        }

        if (details) {
            await pool.query(
                'INSERT INTO activity_logs (hwid, action, details, timestamp) VALUES ($1, $2, $3, NOW())',
                [hwid, 'Detection', details]
            );

            await pool.query(
                'UPDATE logs SET violations = violations + 1 WHERE hwid = $1',
                [hwid]
            );

            if (details.includes("DENIED: Hash")) {
                const hashMatch = details.match(/Hash ([a-f0-9]+)/i);
                const extractedHash = hashMatch ? hashMatch[1] : 'Unknown';

                await pool.query(
                    'INSERT INTO denied_hashes (hash, attempted_by, timestamp, reason) VALUES ($1, $2, NOW(), $3)',
                    [extractedHash, hwid, 'DLL Hash not in whitelist']
                );
            }
        }

        res.json({ success: true, message: 'Log processed' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/check-auth/:hwid', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM blacklist WHERE hwid = $1', [req.params.hwid]);
        if (result.rows.length > 0) {
            return res.json({ banned: true, reason: result.rows[0].reason });
        }
        res.json({ banned: false });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- AUTHENTICATION ---
app.post('/api/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    
    try {
        const result = await pool.query('SELECT * FROM admin_users WHERE username = $1', [username]);
        if (result.rows.length === 0) {
            return res.status(401).json({ success: false, message: 'Invalid username or password' });
        }

        const user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (isMatch) {
            return res.json({ success: true, role: user.role });
        } else {
            return res.status(401).json({ success: false, message: 'Invalid username or password' });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- ADMIN ENDPOINTS ---

app.get('/api/dll-hashes', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM dll_hashes ORDER BY last_update DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/dll-hashes', async (req, res) => {
    const { hash } = req.body;
    try {
        const result = await pool.query(
            'INSERT INTO dll_hashes (hash, status) VALUES ($1, $2) RETURNING *',
            [hash, 'active']
        );
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/check-hash/:hash', async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT * FROM dll_hashes WHERE LOWER(hash) = LOWER($1) AND status = 'active'",
            [req.params.hash]
        );
        if (result.rows.length > 0) {
            return res.json({ approved: true });
        }
        res.json({ approved: false });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/dll-hashes/:id', async (req, res) => {
    try {
        await pool.query('DELETE FROM dll_hashes WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/logs', async (req, res) => {
    try {
        await pool.query("UPDATE logs SET status = 'offline', instances = 0 WHERE last_online < NOW() - INTERVAL '1 minute'");
        const result = await pool.query('SELECT * FROM logs ORDER BY id DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/denied-hashes', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM denied_hashes ORDER BY timestamp DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/activity-logs/:hwid', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM activity_logs WHERE hwid = $1 ORDER BY timestamp DESC',
            [req.params.hwid]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/blacklist', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM blacklist ORDER BY date_banned DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/blacklist', async (req, res) => {
    const { hwid, reason, ip } = req.body;
    try {
        await pool.query(
            'INSERT INTO blacklist (hwid, reason, ip, status, date_banned) VALUES ($1, $2, $3, $4, NOW())',
            [hwid, reason, ip || 'N/A', 'banned']
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/blacklist/:id', async (req, res) => {
    try {
        await pool.query('DELETE FROM blacklist WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Clear all activity and denied logs
app.delete('/api/logs/clear', async (req, res) => {
    try {
        await pool.query('DELETE FROM activity_logs');
        await pool.query('DELETE FROM denied_hashes');
        // Reset violations count in logs table to 0
        await pool.query('UPDATE logs SET violations = 0');
        res.json({ success: true, message: 'All logs cleared' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/stats', async (req, res) => {
    try {
        await pool.query("UPDATE logs SET status = 'offline', instances = 0 WHERE last_online < NOW() - INTERVAL '1 minute'");
        const hwidCount = await pool.query('SELECT COUNT(DISTINCT hwid) FROM logs');
        const onlineCount = await pool.query("SELECT COUNT(*) FROM logs WHERE status = 'online'");
        const offlineCount = await pool.query("SELECT COUNT(*) FROM logs WHERE status = 'offline'");
        const blockedCount = await pool.query("SELECT COUNT(*) FROM blacklist WHERE status = 'banned'");

        res.json({
            totalHwids: hwidCount.rows[0].count,
            online: onlineCount.rows[0].count,
            offline: offlineCount.rows[0].count,
            blocked: blockedCount.rows[0].count
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Important for Vercel: Export the app
export default app;
