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
    console.log(`[${new Date().toLocaleString()}] Admin Panel is fetching logs...`);
    try {
        // Ginawang mas simple ang DATE format para sa C++ Parser
        const query = `
            SELECT hwid, ip, log_message, 
            TO_CHAR(date_recorded, 'YYYY-MM-DD HH24:MI:SS') as date_recorded 
            FROM anti_cheat_logs 
            ORDER BY date_recorded DESC 
            LIMIT 500
        `;
        const result = await pool.query(query);
        console.log(`- Found ${result.rows.length} logs in database.`);
        res.json(result.rows);
    } catch (err) { 
        console.error("- Error fetching logs:", err.message);
        res.status(500).json({ error: err.message }); 
    }
});

// [E] HEARTBEAT DATA FOR DASHBOARD
app.get('/api/admin/heartbeats', async (req, res) => {
    try {
        const result = await pool.query('SELECT hwid, last_seen FROM heartbeats WHERE last_seen > CURRENT_TIMESTAMP - INTERVAL \'5 minutes\'');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API Live on ${PORT}`));
