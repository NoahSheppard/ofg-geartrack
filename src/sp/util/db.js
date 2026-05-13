import pkg from 'sqlite3';
const { Database } = pkg;
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const dbPath = join(__dirname, '../../../db/sp.db');
const db = new Database(dbPath);

const execute = async (db, sql) => {
    return new Promise((resolve, reject) => {
        db.exec(sql, (err) => {
            if (err) return reject(err);
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
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        display_name TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'student',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login DATETIME DEFAULT CURRENT_TIMESTAMP
        )`
    );

    await execute(db, 
        `CREATE TABLE IF NOT EXISTS gear_categories (
        category_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        description TEXT NULL
        )`
    );

    await execute(db, 
        `CREATE TABLE IF NOT EXISTS gear (
        gear_id INTEGER PRIMARY KEY AUTOINCREMENT, 
        category_id INTEGER,
        name TEXT NOT NULL,
        description TEXT NULL,
        quantity_total INTEGER NOT NULL DEFAULT 1,
        quantity_available INTEGER NOT NULL DEFAULT 1,
        condition TEXT DEFAULT 'Good',
        image_url TEXT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (category_id) REFERENCES gear_categories(category_id)
        )`
    );

    await execute(db, 
        `CREATE TABLE IF NOT EXISTS rentals (
        rental_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        gear_id INTEGER,
        quantity INTEGER NOT NULL DEFAULT 1, 
        rental_start DATE NOT NULL,
        return_due DATE NOT NULL,
        return_actual DATE NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        approved_by INTEGER NULL,
        rejection_reason TEXT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(user_id),
        FOREIGN KEY (gear_id) REFERENCES gear(gear_id),
        FOREIGN KEY (approved_by) REFERENCES users(user_id)
        )`
    );

    await execute(db, 
        `CREATE TABLE IF NOT EXISTS audit_log (
        log_id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor_user_id INTEGER,
        action TEXT NOT NULL,
        target_rental_id INTEGER NULL,
        target_gear_id INTEGER NULL,
        details TEXT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (actor_user_id) REFERENCES users(user_id),
        FOREIGN KEY (target_rental_id) REFERENCES rentals(rental_id),
        FOREIGN KEY (target_gear_id) REFERENCES gear(gear_id)
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