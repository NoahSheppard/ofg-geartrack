import * as dbU from './db.js';

async function createUser(db, data) {
    await dbU.run(db, 'BEGIN');
    console.log(`Adding usr: ${JSON.stringify(data)}`)

    try {
        const createdAt = data.created_at ?? new Date();
        const lastLogin = createdAt;
        const role = data.role && data.role.trim() ? data.role : 'student';

        const userResult = await dbU.run(
            db,
            `INSERT INTO users
            (email, display_name, role, created_at, last_login)
            VALUES (?, ?, ?, ?, ?)`,
            [
                data.email,
                data.display_name,
                role,
                createdAt,
                lastLogin
            ]
        );

        const userId = userResult.lastID;

        await dbU.run(db, `COMMIT`);
        return userId;
    } catch (e) {
        await dbU.run(db, 'ROLLBACK');
        throw (`Issue with creating user: ${e}`);
    }
}

async function updateUserLastLogin(db, user_id) {
    return dbU.run(
        db,
        `UPDATE users SET last_login = ? WHERE user_id = ?`,
        [new Date(), user_id]
     );
}

async function deleteUserById(db, user_id) {
    return dbU.run(db, `DELETE FROM users WHERE user_id = ?`, [user_id]);
}

async function deleteUserByEmail(db, email) {
    return dbU.run(db, `DELETE FROM users WHERE email = ?`, [email]);
}

async function getUserByEmail(db, email) {
    const row = await dbU.get(
        db, 
        `SELECT user_id, email, display_name, role, created_at, last_login
        FROM users 
        WHERE email = ?`,
        [email]
    );

    if (!row) return null;

    return {
        user_id: row.user_id,
        email: row.email,
        displayName: row.display_name,
        role: row.role,
        createdAt: row.created_at,
        lastLogin: row.last_login
    };
}

export {
    createUser,
    updateUserLastLogin,
    deleteUserById,
    deleteUserByEmail,
    getUserByEmail
}