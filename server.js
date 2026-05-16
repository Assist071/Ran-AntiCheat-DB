import express from 'express';
import pg from 'pg';
import cors from 'cors';
import dotenv from 'dotenv';

dotenv.config();

const { Pool } = pg;
const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// Set Timezone to Manila for the database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } // Required for Render/Neon
});

// Helper to get Client IP
const getClientIp = (req) => {
    const forwarded = req.headers['x-forwarded-for'];
    return forwarded ? forwarded.split(',')[0] : req.socket.remoteAddress;
};

// --- CLIENT ENDPOINTS (Para sa Game Client) ---

// Heartbeat and Log Submission
app.post('/api/submit-log', async (req, res) => {
    const { hwid, pc_name, username, status, details } = req.body;
    const ip_address = getClientIp(req);

    try {
        // 1. Update or Insert into Logs (Heartbeat)
        await pool.query(
            `INSERT INTO logs (hwid, pc_name, username, ip_address, status, last_online)
             VALUES ($1, $2, $3, $4, $5, NOW())
             ON CONFLICT (hwid) 
             DO UPDATE SET 
                pc_name = EXCLUDED.pc_name,
                username = EXCLUDED.username,
                ip_address = EXCLUDED.ip_address,
                status = EXCLUDED.status,
                last_online = NOW()`,
            [hwid, pc_name, username, ip_address, status || 'online']
        );

        // 2. If there are details (like a detection), save to activity_logs
        if (details) {
            await pool.query(
                'INSERT INTO activity_logs (hwid, action, details, timestamp) VALUES ($1, $2, $3, NOW())',
                [hwid, 'Detection', details]
            );
        }

        res.json({ success: true, message: 'Log processed' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// Check if HWID is blacklisted
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

// --- ADMIN ENDPOINTS (Para sa Dashboard) ---

// DLL Hashes
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

// Check if a specific hash is approved
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

// Logs (Dashboard view)
app.get('/api/logs', async (req, res) => {
    try {
        // Auto-set offline those who haven't sent heartbeat in 1 minute
        await pool.query("UPDATE logs SET status = 'offline' WHERE last_online < NOW() - INTERVAL '1 minute'");
        
        const result = await pool.query('SELECT * FROM logs ORDER BY last_online DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Blacklist
app.get('/api/blacklist', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM blacklist ORDER BY date_banned DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/blacklist', async (req, res) => {
    const { hwid, pc_name, username, reason } = req.body;
    try {
        await pool.query(
            'INSERT INTO blacklist (hwid, pc_name, username, reason, status, date_banned) VALUES ($1, $2, $3, $4, $5, NOW())',
            [hwid, pc_name, username, reason, 'banned']
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

// Stats
app.get('/api/stats', async (req, res) => {
    try {
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

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});

