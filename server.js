const express = require('express');
const { Pool } = require('pg');
const app = express();
app.use(express.json());

// Iyong Neon Connection String
const connectionString = "postgresql://neondb_owner:npg_kczdR6Ajyo7C@ep-odd-cake-aozdfekp-pooler.c-2.ap-southeast-1.aws.neon.tech/neondb?sslmode=require";

const pool = new Pool({
    connectionString: connectionString,
    ssl: { rejectUnauthorized: false }
});

// TEST ENDPOINT (Para malaman kung working ang API)
app.get('/', (req, res) => res.send('Anti-Cheat API is ONLINE'));

// [A] DETECTION LOGS
app.post('/api/log', async (req, res) => {
    const { hwid, ip, log } = req.body;
    try {
        await pool.query('INSERT INTO anti_cheat_logs (hwid, ip, log_message) VALUES ($1, $2, $3)', [hwid, ip, log]);
        res.json({ status: 'ok' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// [B] HEARTBEATS
app.post('/api/heartbeat', async (req, res) => {
    const { hwid, ip } = req.body;
    try {
        await pool.query(
            'INSERT INTO heartbeats (hwid, ip, last_seen) VALUES ($1, $2, CURRENT_TIMESTAMP) ON CONFLICT (hwid) DO UPDATE SET last_seen = EXCLUDED.last_seen, ip = EXCLUDED.ip',
            [hwid, ip]
        );
        res.json({ status: 'ok' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// [C] HASH AUTH
app.get('/api/hashes', async (req, res) => {
    try {
        const result = await pool.query('SELECT game_name, hash_value, status FROM game_hashes WHERE status = \'active\'');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// [D] DASHBOARD DATA
app.get('/api/admin/logs', async (req, res) => {
    try {
        const result = await pool.query('SELECT hwid, ip, log_message, date_recorded FROM anti_cheat_logs ORDER BY date_recorded DESC LIMIT 500');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API Live on ${PORT}`));
