import pkg from 'sqlite3';
const { Database } = pkg;
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const dbPath = join(__dirname, '../../../db/idp.db');
const db = new Database(dbPath);

const execute = async (db, sql) => {
    return new Promise((resolve, reject) => {
        db.exec(sql, (err) => {
            if (err) reject(err);
            resolve();
        });
    });
};

const run = (db, sql, params = []) => {
    return new Promise((resolve, reject) => {
        db.run(sql, sanitize(params), function(err) {
            if (err) reject (err);
            else resolve(this);
        });
    });
};

const get = (db, sql, params = []) => {
    return new Promise((resolve, reject) => {
        db.get(sql, sanitize(params), (err, row) => {
            if(err) reject(err);
            else resolve(row);
        });
    });
};

const all = (db, sql, params = []) => {
    return new Promise((resolve, reject) => {
        db.all(sql, sanitize(params), (err, rows) => {
            if(err) reject(err);
            else resolve(rows);
        });
    });
};

function sanitize(params) {
    if (!Array.isArray(params)) return params;
    return params.map((value) => {
        if (value === undefined || value === null) return null;
        if (value instanceof Date) return value.toISOString();
        if (Buffer.isBuffer(value)) return value;
        if (typeof value === 'string') {
            const trimmed = value.trim();
            const cleaned = trimmed.replace(/[\u0000-\u001F\u007F]/g, '');
            return cleaned.length ? cleaned : null;
        } else if (typeof value === 'number') {
            if (!Number.isFinite(value)) console.warn(`Invalid number: ${value}`);
            return value; 
        } else if (typeof value === 'boolean') {
            return value ? 1 : 0;
        } else if (typeof value === 'object') {
            try { return JSON.stringify(value); } catch { return null; }
        }

        return value; 
    });
}

async function initialOperation() {
    db.exec(`PRAGMA foreign_keys = ON`);
    await createTables();
}

async function createTables() {
    await execute(db, 
        `CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
        )`
    );

    await execute(db, 
        `CREATE TABLE IF NOT EXISTS profiles (
        id INTEGER PRIMARY KEY,
        displayName TEXT,
        firstName TEXT,
        lastName TEXT,
        userType TEXT,
        role TEXT,
        email TEXT,
        internalId INTEGER,
        FOREIGN KEY (id) REFERENCES users(id) ON DELETE CASCADE
        )`
    );
}

export {
    db, 
    execute,
    initialOperation,
    run, 
    get, 
    all
};