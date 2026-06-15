import * as dbU from './db.js';

async function getClassesForUser(db, userId, role) {
    const table = role === 'student' ? 'class_enrollments' : 'class_teachers';

    const rows = await dbU.all(
        db,
        `SELECT c.class_id AS id, c.name
        FROM classes c
        JOIN ${table} m ON m.class_id = c.class_id
        WHERE m.user_id = ?
        ORDER BY c.name`,
        [userId]
    );

    return rows;
}

async function isTeacherOfClass(db, userId, classId) {
    const row = await dbU.get(
        db,
        `SELECT 1 FROM class_teachers WHERE class_id = ? AND user_id = ?`,
        [classId, userId]
    );

    return !!row;
}

export {
    getClassesForUser,
    isTeacherOfClass
}
