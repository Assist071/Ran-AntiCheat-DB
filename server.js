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

// Auto-update database schema for instances
pool.query('ALTER TABLE logs ADD COLUMN IF NOT EXISTS instances INT DEFAULT 0;').catch(err => console.error("DB Alter Error:", err));

// --- CLIENT ENDPOINTS (Para sa Game Client) ---

// Heartbeat and Log Submission
app.post('/api/submit-log', async (req, res) => {
    const { hwid, status, details, instances } = req.body;
    
    // Ensure instances is a valid integer
    const clientInstances = parseInt(instances) || 0;
    const ip = getClientIp(req);

    console.log(`[DEBUG] Submission from HWID: ${hwid} | Clients detected: ${clientInstances}`);

    try {
        // 1. Update or Insert into Logs (Safe way)
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

        // 2. If there are details (like a detection), save to activity_logs and increment violations
        if (details) {
            await pool.query(
                'INSERT INTO activity_logs (hwid, action, details, timestamp) VALUES ($1, $2, $3, NOW())',
                [hwid, 'Detection', details]
            );

            // Increment violations count in logs table
            await pool.query(
                'UPDATE logs SET violations = violations + 1 WHERE hwid = $1',
                [hwid]
            );

            // 3. Special Case: If it's a Denied Hash, save to denied_hashes table
            if (details.includes("DENIED: Hash")) {
                // Extract the hash from the message
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
        await pool.query("UPDATE logs SET status = 'offline', instances = 0 WHERE last_online < NOW() - INTERVAL '1 minute'");
        
        const result = await pool.query('SELECT * FROM logs ORDER BY last_online DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Denied Hashes
app.get('/api/denied-hashes', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM denied_hashes ORDER BY timestamp DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Activity Logs for a specific HWID
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

// Stats
app.get('/api/stats', async (req, res) => {
    try {
        // Auto-set offline those who haven't sent heartbeat in 1 minute
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

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});

