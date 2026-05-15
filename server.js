const express = require('express');
const { Pool } = require('pg');
const app = express();
const cors = require('cors');
const fs = require('fs');

app.use(express.json());
app.use(cors());

// --- GLOBAL REQUEST LOGGER ---
app.use((req, res, next) => {
    const phTime = new Date().toLocaleString('en-US', { timeZone: 'Asia/Manila', hour12: true });
    console.log(`[${phTime}] ${req.method} ${req.url}`);
    next();
});

// Iyong Neon Connection String
const connectionString = "postgresql://neondb_owner:npg_kczdR6Ajyo7C@ep-odd-cake-aozdfekp-pooler.c-2.ap-southeast-1.aws.neon.tech/neondb?sslmode=require";

const pool = new Pool({
    connectionString: connectionString,
});

// Siguraduhin na lahat ng bagong connection sa pool ay naka-Asia/Manila timezone
pool.on('connect', (client) => {
    client.query("SET TIME ZONE 'Asia/Manila'");
});

// --- DATABASE INITIALIZATION ---
const initDb = async () => {
    try {
        await pool.query("SET TIME ZONE 'Asia/Manila'");
        await pool.query(`
            CREATE TABLE IF NOT EXISTS anti_cheat_logs (
                id SERIAL PRIMARY KEY,
                hwid TEXT,
                ip TEXT,
                log_message TEXT,
                date_recorded TIMESTAMPTZ DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS game_hashes (
                id SERIAL PRIMARY KEY,
                hash_value VARCHAR(64) UNIQUE NOT NULL,
                status VARCHAR(20) DEFAULT 'active',
                last_updated TIMESTAMPTZ DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS heartbeats (
                hwid TEXT PRIMARY KEY,
                ip TEXT,
                last_seen TIMESTAMPTZ DEFAULT NOW()
            );
        `);
        console.log(" - Database Tables Verified/Created with TIMESTAMPTZ.");
    } catch (err) {
        console.error(" - Database Init Error:", err.message);
    }
};
initDb();

// TEST ENDPOINT (Para malaman kung working ang API)
app.get('/', (req, res) => res.send('Anti-Cheat API is ONLINE'));

app.get('/api/test-log', (req, res) => {
    try {
        const phTime = new Date().toLocaleString('en-US', { timeZone: 'Asia/Manila', hour12: true });
        const debugPath = 'C:\\Users\\User\\Desktop\\Ran-AntiCheat-DB\\hash_checker_debug.txt';
        const debugMsg = `[${phTime}] TEST LOG FROM BROWSER\n`;
        fs.appendFileSync(debugPath, debugMsg);
        res.send('Test log recorded at ' + debugPath);
    } catch (err) {
        console.error(" - File Write Error:", err.message);
        res.status(500).send("Error writing file: " + err.message);
    }
});

// [A] DETECTION LOGS
app.post('/api/log', async (req, res) => {
    const { hwid, log } = req.body;
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '0.0.0.0').replace('::ffff:', '');
    
    // --- DEBUG FILE LOGGING ---
    try {
        const phTime = new Date().toLocaleString('en-US', { timeZone: 'Asia/Manila', hour12: true });
        const debugPath = 'C:\\Users\\User\\Desktop\\Ran-AntiCheat-DB\\hash_checker_debug.txt';
        const debugMsg = `[${phTime}] HWID: ${hwid} | IP: ${ip} | LOG: ${log}\n`;
        fs.appendFileSync(debugPath, debugMsg);
        console.log(" - Debug log written to file.");
    } catch (fErr) {
        console.error(" - File Log Error:", fErr.message);
    }

    try {
        await pool.query('INSERT INTO anti_cheat_logs (hwid, ip, log_message, date_recorded) VALUES ($1, $2, $3, NOW())', [hwid, ip, log]);
        res.json({ status: 'ok' });
    } catch (err) { 
        console.error(" - DB Log Error:", err.message);
        res.status(500).json({ error: err.message }); 
    }
});

// [B] HEARTBEATS
app.post('/api/heartbeat', async (req, res) => {
    const { hwid } = req.body;
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '0.0.0.0').replace('::ffff:', '');
    try {
        await pool.query(
            'INSERT INTO heartbeats (hwid, ip, last_seen) VALUES ($1, $2, NOW()) ON CONFLICT (hwid) DO UPDATE SET last_seen = EXCLUDED.last_seen, ip = EXCLUDED.ip',
            [hwid, ip]
        );
        res.json({ status: 'ok' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// [C] HASH AUTH
app.get('/api/hashes', async (req, res) => {
    try {
        const result = await pool.query('SELECT hash_value, status, last_updated FROM game_hashes WHERE status = \'active\'');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// [D] DASHBOARD DATA
app.get('/api/admin/logs', async (req, res) => {
    const phTime = new Date().toLocaleString('en-US', { timeZone: 'Asia/Manila', hour12: true });
    console.log(`[${phTime}] Admin Panel is fetching logs...`);
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

// [F] MANAGE HASHES
app.get('/api/admin/hashes', async (req, res) => {
    try {
        const result = await pool.query('SELECT hash_value, status, last_updated FROM game_hashes ORDER BY id DESC');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/hashes', async (req, res) => {
    const { hash_value, status } = req.body;
    console.log(`[ADMIN] Saving hash: ${hash_value}`);
    try {
        await pool.query(
            'INSERT INTO game_hashes (hash_value, status, last_updated) VALUES ($1, $2, NOW()) ON CONFLICT (hash_value) DO UPDATE SET status = EXCLUDED.status, last_updated = NOW()',
            [hash_value, status || 'active']
        );
        console.log(" - Hash saved successfully.");
        res.json({ status: 'ok' });
    } catch (err) { 
        console.error(" - Error saving hash:", err.message);
        res.status(500).json({ error: err.message }); 
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API Live on ${PORT}`));
