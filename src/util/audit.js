import { run } from './db.js';

// Appends a row to the tamper-evident audit_log table.
// `details` is stored as a JSON string for context-specific data.
async function logAction(db, { actorUserId, action, targetRentalId = null, targetGearId = null, details = null }) {
    return run(db, `
        INSERT INTO audit_log (actor_user_id, action, target_rental_id, target_gear_id, details)
        VALUES (?, ?, ?, ?, ?)
    `, [actorUserId, action, targetRentalId, targetGearId, details ? JSON.stringify(details) : null]);
}

export { logAction };
