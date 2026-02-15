import * as dbU from './db.js';
import bcrypt from 'bcrypt';

async function createUser(db, data) {
    await dbU.run(db, 'BEGIN');
    console.log(`Adding usr: ${JSON.stringify(data)}`)

    try {
        const hash = await bcrypt.hash(data.password, 12);

        const userResult = await dbU.run(
            db,
            `INSERT INTO users (username, password)
            VALUES (?, ?)`,
            [data.username, hash]
        );

        const userId = userResult.lastID;

        await dbU.run(
            db,
            `INSERT INTO profiles
            (id, displayName, firstName, lastName, userType, role, email)
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                userId,
                data.profile.displayName,
                data.profile.firstName,
                data.profile.lastName,
                data.profile.userType,
                data.profile.role,
                data.profile.email
            ]
        );

        await dbU.run(db, `COMMIT`);
        return userId;
    } catch (e) {
        await dbU.run(db, 'ROLLBACK');
        throw (`Issue with creating user: ${e}`);
    }
}

async function deleteUserById(db, id) {
    return dbU.run(db, `DELETE FROM users WHERE id = ?`, [id]);
}

async function deleteUserByUsername(db, id) {
    return dbU.run(db, `DELETE FROM users WHERE username = ?`, [username]);
}

async function getUserByUsername(db, username) {
    const row = await dbU.get(
        db, 
        `SELECT u.id, u.username,
                p.displayName, p.firstName, p.lastName, p.userType, p.role, p.email
        FROM users u
        JOIN profiles p ON p.id = u.id
        WHERE u.username = ?`,
        [username]
    );

    if (!row) return null;

    return {
        id: row.id,
        username: row.username,
        profile: {
            displayName: row.displayName,
            firstName: row.firstName,
            lastName: row.lastName,
            userType: row.userType,
            role: row.role,
            email: row.email
        }
    };
}

async function verifyPassword(db, username, password) {
    const row = await dbU.get(
        db, 
        `SELECT password FROM users WHERE username = ?`,
        [username]
    );

    if (!row) return false;

    return bcrypt.compare(password, row.password);
}

export {
    createUser,
    deleteUserById,
    deleteUserByUsername,
    getUserByUsername,
    verifyPassword
}