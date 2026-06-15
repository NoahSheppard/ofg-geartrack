import express from 'express';
import passport from 'passport';
import { Strategy as SamlStrategy } from 'passport-saml';
import bodyParser from 'body-parser';
import session from 'express-session';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import {
    db,
    initialOperation,
    run,
    get,
    all,
} from './util/db.js';
import {
    createUser,
    updateUserLastLogin,
    getUserByEmail,
} from './util/user.js';
import { logAction } from './util/audit.js';
import { getClassesForUser, isTeacherOfClass } from './util/classes.js';

// ─── Config ───────────────────────────────────────────────────────────────────

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

// Vite builds into /dist at the project root (one level above /src)
const DIST  = path.join(__dirname, 'web/dist');
const PORT  = process.env.PORT || 3001;
const DEBUG = process.env.NODE_ENV !== 'production';

// Locally-hosted images (gear photos uploaded via the admin UI), served at /uploads/*
const UPLOADS_DIR      = path.join(__dirname, 'uploads');
const GEAR_UPLOADS_DIR = path.join(UPLOADS_DIR, 'gear');
fs.mkdirSync(GEAR_UPLOADS_DIR, { recursive: true });

const idpCert    = fs.readFileSync(path.join(__dirname, '../certificates/idp-signing.cert'), 'utf-8');
const spCert     = fs.readFileSync(path.join(__dirname, '../certificates/sp-signing.cert'), 'utf-8');
const entryPoint = process.env.IDP_ENTRY_POINT || 'http://localhost:3000/sso';

// ─── App Setup ────────────────────────────────────────────────────────────────

const app = express();

initialOperation(); // run DB migrations / init

// Parse incoming request bodies. The JSON limit is raised from the 100kb
// default so the admin gear-image upload (a base64 data URL) fits.
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json({ limit: '10mb' }));

// Session (must come before passport)
app.use(session({
    secret: process.env.SESSION_SECRET || 'sp-secret-key-change-in-prod',
    resave: false,
    saveUninitialized: false,
    // Only mark the cookie Secure when actually served over HTTPS (set
    // COOKIE_SECURE=true behind TLS) — over plain http://localhost the
    // browser silently drops Secure cookies, breaking the session.
    cookie: { secure: process.env.COOKIE_SECURE === 'true', httpOnly: true },
}));

app.use(passport.initialize());
app.use(passport.session());

// Serve the Vite production build as static files.
// This handles JS bundles, CSS, images, and / → index.html automatically.
app.use(express.static(DIST));

// Serve locally-hosted gear images (uploaded via the admin UI, or fetched
// during catalogue setup) at /uploads/*.
app.use('/uploads', express.static(UPLOADS_DIR));

// ─── SAML / Passport ─────────────────────────────────────────────────────────

passport.use(new SamlStrategy(
    {
        path: '/login/callback',
        entryPoint,
        issuer: 'geartrack-sp',
        cert: idpCert,
        identifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:username',
        wantAuthnResponseSigned: false,
        wantAssertionsSigned: false,
        wantEncryptedAssertions: false,
        disableRequestedAuthnContext: true,
        acceptedClockSkewMs: 5000,
        disableRequestCompression: true,
    },
    (profile, done) => {
        const attributes  = profile?.attributes || {};
        const email       = profile?.email || attributes.email;
        const username    = attributes.username || profile?.nameID || profile?.uid;
        const displayName =
            profile?.displayName ||
            attributes.displayName ||
            [attributes.firstName, attributes.lastName].filter(Boolean).join(' ');

        const user = {
            ...profile,
            attributes,
            username,
            email,
            displayName,
            givenName: profile?.givenName || attributes.givenName || attributes.firstName,
            surname:   profile?.surname   || attributes.surname   || attributes.lastName,
            uid:       profile?.uid       || attributes.uid       || username,
            // Normalize casing — the IdP sends roles like "Admin", but
            // requireAdmin() and the stored user records expect lowercase
            // ('admin', 'teacher', 'student'). The IdP sends an empty role
            // attribute for students, so default to 'student' here too.
            role:      (profile?.role || attributes.role || 'student').toLowerCase(),
        };

        if (DEBUG) console.log('[SAML] Profile:', user);
        return done(null, user);
    }
));

passport.serializeUser((user, done)   => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// ─── Auth Middleware ──────────────────────────────────────────────────────────

// Protects all /api/* routes — returns 401 JSON instead of redirecting,
// so the React frontend can handle it gracefully.
function requireAuth(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.status(401).json({ error: 'Unauthorized' });
}

// Protects strictly admin-only routes (gear/category management, class
// management, stats).
function requireAdmin(req, res, next) {
    if (req.user?.role === 'admin') return next();
    res.status(403).json({ error: 'Forbidden' });
}

// Protects routes shared by admins and teachers (rental queues — each route
// applies its own per-request teacher scoping/ownership checks).
function requireStaff(req, res, next) {
    const role = req.user?.role;
    if (role === 'admin' || role === 'teacher') return next();
    res.status(403).json({ error: 'Forbidden' });
}

// ─── SAML Auth Routes ─────────────────────────────────────────────────────────

// Expose SP metadata so the IdP can register this app.
app.get('/sp/metadata', (req, res) => {
    const cert = spCert
        .replace(/-----BEGIN CERTIFICATE-----/g, '')
        .replace(/-----END CERTIFICATE-----/g,   '')
        .replace(/\n/g, '')
        .trim();

    res.type('application/xml').send(`<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="geartrack-sp">
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true"
                   protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>${cert}</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:username</NameIDFormat>
    <AssertionConsumerService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="http://localhost:${PORT}/login/callback"
      index="0" isDefault="true"/>
  </SPSSODescriptor>
</EntityDescriptor>`);
});

// Redirects to the IdP login page.
app.get('/login', passport.authenticate('saml'));

// IdP posts the SAML assertion back here after the user logs in.
app.post('/login/callback', (req, res, next) => {
    passport.authenticate('saml', { failureRedirect: '/login' }, async (err, user) => {
        if (err) {
            console.error('[SAML] Error:', err);
            return res.status(500).json({ error: 'SAML authentication failed', detail: err.message });
        }
        if (!user) {
            console.error('[SAML] Auth failed — no user returned');
            return res.redirect('/login');
        }

        req.logIn(user, async (loginErr) => {
            if (loginErr) return next(loginErr);

            // Upsert the user in our DB so we have a local record.
            try {
                const existing = await getUserByEmail(db, user.email);
                const userId   = existing
                    ? existing.user_id
                    : await createUser(db, {
                        email:        user.email,
                        display_name: user.displayName || user.username || 'User',
                        role:         user.role || 'student',
                    });

                await updateUserLastLogin(db, userId);
                if (DEBUG) console.log(`[Auth] Logged in user_id=${userId}`);
            } catch (dbErr) {
                // Non-fatal — user is still authenticated via session
                console.error('[Auth] DB upsert error:', dbErr);
            }

            res.redirect('/');
        });
    })(req, res, next);
});

app.get('/logout', (req, res) => {
    req.logout(() => res.redirect('/login'));
});

// ─── Dev / Emergency Bypass Login ─────────────────────────────────────────────

// Outside production, allow logging in as a fixed student or admin account
// without going through SAML. This doubles as the "local emergency admin
// bypass account" mitigation for risk R-01 (SAML SSO outage).
if (DEBUG) {
    app.post('/auth/dev-login', async (req, res) => {
        const role = ['admin', 'teacher'].includes(req.body?.role) ? req.body.role : 'student';
        const email = {
            admin:   '[dev]admin@ofg.nsw.edu.au',
            teacher: '[dev]teacher@ofg.nsw.edu.au',
            student: '[dev]student@ofgsstudents.com',
        }[role];
        const displayName = {
            admin:   'Dev Admin',
            teacher: 'Dev Teacher',
            student: 'Dev Student',
        }[role];

        try {
            const existing = await getUserByEmail(db, email);
            const userId = existing
                ? existing.user_id
                : await createUser(db, { email, display_name: displayName, role });

            await updateUserLastLogin(db, userId);

            const sessionUser = {
                email,
                displayName,
                givenName: displayName.split(' ')[0],
                surname:   displayName.split(' ')[1],
                role,
                uid: email,
            };

            req.logIn(sessionUser, (err) => {
                if (err) return res.status(500).json({ error: 'Login failed' });
                res.json({ message: 'Logged in', user: sessionUser });
            });
        } catch (err) {
            console.error('[POST /auth/dev-login]', err);
            res.status(500).json({ error: 'Dev login failed' });
        }
    });
}

// ─── API: Current User ────────────────────────────────────────────────────────

// GET /api/me
// Returns the session user's profile.
// The useCurrentUser() hook in the frontend calls this in production.
app.get('/api/me', requireAuth, (req, res) => {
    const { email, displayName, givenName, surname, role, uid } = req.user;
    res.json({ email, displayName, givenName, surname, role, uid });
});

// ─── API: Gear ────────────────────────────────────────────────────────────────

// GET /api/gear
// Returns the full gear catalogue (category, availability, condition) for the
// Rental page.
app.get('/api/gear', requireAuth, async (req, res) => {
    try {
        const gear = await all(db, `
            SELECT
                g.gear_id            AS id,
                g.name,
                g.description,
                gc.name              AS category,
                g.quantity_total     AS quantityTotal,
                g.quantity_available AS quantityAvailable,
                g.condition,
                g.image_url          AS imageUrl,
                g.manufacturer,
                g.model_no           AS modelNo,
                g.serial_no          AS serialNo,
                g.type
            FROM gear g
            LEFT JOIN gear_categories gc ON gc.category_id = g.category_id
            ORDER BY gc.name, g.name
        `);
        res.json(gear);
    } catch (err) {
        console.error('[GET /api/gear]', err);
        res.status(500).json({ error: 'Failed to fetch gear' });
    }
});

// ─── API: Classes ─────────────────────────────────────────────────────────────

// GET /api/classes/me
// Returns the classes the current user belongs to — as a student
// (class_enrollments) or as a teacher/admin (class_teachers). Used by the
// rental-request class picker and the teacher's "My Classes" tab.
app.get('/api/classes/me', requireAuth, async (req, res) => {
    try {
        const userRow = await getUserByEmail(db, req.user.email);
        if (!userRow) return res.json([]);

        const classes = await getClassesForUser(db, userRow.user_id, req.user.role);
        res.json(classes);
    } catch (err) {
        console.error('[GET /api/classes/me]', err);
        res.status(500).json({ error: 'Failed to fetch classes' });
    }
});

// GET /api/classes/:id
// Roster + the current user's own rentals for a class they belong to.
// Students see their teachers/classmates; teachers/admins are also members
// (via class_teachers) and can use this for their own classes. This is the
// student-facing counterpart to /api/admin/classes/:id, which additionally
// exposes every student's rentals and is restricted to staff.
app.get('/api/classes/:id', requireAuth, async (req, res) => {
    const classId = req.params.id;

    try {
        const userRow = await getUserByEmail(db, req.user.email);
        if (!userRow) return res.status(404).json({ error: 'Class not found' });

        const classRow = await get(db, `
            SELECT class_id AS id, name, description FROM classes WHERE class_id = ?
        `, [classId]);
        if (!classRow) return res.status(404).json({ error: 'Class not found' });

        if (req.user.role === 'teacher') {
            if (!(await isTeacherOfClass(db, userRow.user_id, classId))) {
                return res.status(403).json({ error: 'Forbidden' });
            }
        } else if (req.user.role !== 'admin') {
            const enrolled = await get(db, `
                SELECT 1 FROM class_enrollments WHERE class_id = ? AND user_id = ?
            `, [classId, userRow.user_id]);
            if (!enrolled) return res.status(403).json({ error: 'Forbidden' });
        }

        const teachers = await all(db, `
            SELECT u.user_id AS id, u.display_name AS displayName, u.email, u.role
            FROM class_teachers ct
            JOIN users u ON u.user_id = ct.user_id
            WHERE ct.class_id = ?
            ORDER BY u.display_name
        `, [classId]);

        const students = await all(db, `
            SELECT u.user_id AS id, u.display_name AS displayName, u.email, u.role
            FROM class_enrollments ce
            JOIN users u ON u.user_id = ce.user_id
            WHERE ce.class_id = ?
            ORDER BY u.display_name
        `, [classId]);

        const myRentals = await all(db, `
            SELECT
                r.rental_id    AS id,
                r.quantity,
                r.rental_start AS rentalStart,
                r.return_due   AS returnDue,
                r.status,
                g.name         AS gearName
            FROM rentals r
            JOIN gear g ON g.gear_id = r.gear_id
            WHERE r.class_id = ? AND r.user_id = ?
            ORDER BY r.created_at DESC
            LIMIT 50
        `, [classId, userRow.user_id]);

        res.json({ ...classRow, teachers, students, myRentals });
    } catch (err) {
        console.error(`[GET /api/classes/${req.params.id}]`, err);
        res.status(500).json({ error: 'Failed to fetch class' });
    }
});

// ─── API: Rentals ─────────────────────────────────────────────────────────────

// GET /api/rentals/me
// Returns the current user's full rental history (all statuses).
// 'overdue' is computed at query time for approved, unreturned rentals
// whose return_due date has passed. Used by ProfilePage.
app.get('/api/rentals/me', requireAuth, async (req, res) => {
    try {
        const userRow = await getUserByEmail(db, req.user.email);
        if (!userRow) return res.json([]);

        const rentals = await all(db, `
            SELECT
                r.rental_id       AS id,
                r.gear_id         AS gearId,
                r.quantity,
                r.rental_start    AS rentalStart,
                r.return_due      AS returnDue,
                r.return_actual   AS returnActual,
                r.rejection_reason AS rejectionReason,
                CASE
                    WHEN r.status = 'approved'
                     AND r.return_actual IS NULL
                     AND date(r.return_due) < date('now')
                    THEN 'overdue'
                    ELSE r.status
                END               AS status,
                g.name            AS gearName,
                g.image_url       AS gearImage,
                gc.name           AS gearCategory
            FROM rentals r
            JOIN gear g                  ON g.gear_id = r.gear_id
            LEFT JOIN gear_categories gc ON gc.category_id = g.category_id
            WHERE r.user_id = ?
            ORDER BY r.created_at DESC
        `, [userRow.user_id]);

        res.json(rentals);
    } catch (err) {
        console.error('[GET /api/rentals/me]', err);
        res.status(500).json({ error: 'Failed to fetch rentals' });
    }
});

// Attempts to decrement gear.quantity_available by `quantity`, guarded
// against overselling. Must be called inside an open transaction (BEGIN
// IMMEDIATE). Returns true if the decrement succeeded, false if there wasn't
// enough availability (caller should ROLLBACK).
async function tryDecrementGear(db, gearId, quantity) {
    const result = await run(db, `
        UPDATE gear SET quantity_available = quantity_available - ?
        WHERE gear_id = ? AND quantity_available >= ?
    `, [quantity, gearId, quantity]);
    return result.changes === 1;
}

// POST /api/rentals
// Submits a new rental request from the Rental page.
// - Students: creates a 'pending' rental tied to a class they're enrolled
//   in — availability is only adjusted on staff approval.
// - Teachers: auto-approved immediately, tied to a class they teach.
// - Admins: auto-approved immediately, with no class attached.
// Body: { gearId, quantity, rentalStart, returnDue, purpose?, classId? }
app.post('/api/rentals', requireAuth, async (req, res) => {
    const { gearId, quantity, rentalStart, returnDue, purpose } = req.body;
    const qty = Number(quantity);
    const role = req.user.role;

    if (!gearId || !Number.isInteger(qty) || qty < 1) {
        return res.status(400).json({ error: 'gearId and quantity (≥ 1) are required' });
    }
    if (!rentalStart || !returnDue || isNaN(Date.parse(rentalStart)) || isNaN(Date.parse(returnDue))) {
        return res.status(400).json({ error: 'rentalStart and returnDue must be valid dates' });
    }

    const today = new Date().toISOString().split('T')[0];
    if (rentalStart < today) {
        return res.status(400).json({ error: 'rentalStart cannot be in the past' });
    }
    if (returnDue <= rentalStart) {
        return res.status(400).json({ error: 'returnDue must be after rentalStart' });
    }

    let classId = null;
    if (role !== 'admin') {
        classId = Number(req.body.classId);
        if (!req.body.classId || !Number.isInteger(classId)) {
            return res.status(400).json({ error: 'classId is required' });
        }
    }

    try {
        const userRow = await getUserByEmail(db, req.user.email);
        if (!userRow) return res.status(404).json({ error: 'User not found' });

        const gear = await get(db, 'SELECT * FROM gear WHERE gear_id = ?', [gearId]);
        if (!gear) return res.status(404).json({ error: 'Gear not found' });

        if (role === 'student') {
            const enrolled = await get(db, `
                SELECT 1 FROM class_enrollments WHERE class_id = ? AND user_id = ?
            `, [classId, userRow.user_id]);
            if (!enrolled) return res.status(403).json({ error: 'You are not enrolled in that class' });

            if (gear.quantity_available < qty) {
                return res.status(409).json({ error: 'Insufficient availability' });
            }

            const result = await run(db, `
                INSERT INTO rentals (user_id, gear_id, quantity, rental_start, return_due, status, class_id)
                VALUES (?, ?, ?, ?, ?, 'pending', ?)
            `, [userRow.user_id, gearId, qty, rentalStart, returnDue, classId]);

            await logAction(db, {
                actorUserId: userRow.user_id,
                action: 'REQUEST',
                targetRentalId: result.lastID,
                targetGearId: gearId,
                details: { quantity: qty, rentalStart, returnDue, purpose: purpose || null, classId },
            });

            return res.status(201).json({ message: 'Rental request submitted', rentalId: result.lastID, status: 'pending' });
        }

        // teacher / admin — auto-approved
        if (role === 'teacher') {
            if (!(await isTeacherOfClass(db, userRow.user_id, classId))) {
                return res.status(403).json({ error: 'You do not teach that class' });
            }
        }

        const rentalClassId = role === 'admin' ? null : classId;

        await run(db, 'BEGIN IMMEDIATE');
        try {
            if (!(await tryDecrementGear(db, gearId, qty))) {
                await run(db, 'ROLLBACK');
                return res.status(409).json({ error: 'Insufficient availability' });
            }

            const result = await run(db, `
                INSERT INTO rentals (user_id, gear_id, quantity, rental_start, return_due, status, approved_by, class_id)
                VALUES (?, ?, ?, ?, ?, 'approved', ?, ?)
            `, [userRow.user_id, gearId, qty, rentalStart, returnDue, userRow.user_id, rentalClassId]);

            await logAction(db, {
                actorUserId: userRow.user_id,
                action: 'REQUEST',
                targetRentalId: result.lastID,
                targetGearId: gearId,
                details: { quantity: qty, rentalStart, returnDue, purpose: purpose || null, classId: rentalClassId },
            });

            await logAction(db, {
                actorUserId: userRow.user_id,
                action: 'APPROVE',
                targetRentalId: result.lastID,
                targetGearId: gearId,
                details: { classId: rentalClassId, autoApproved: true },
            });

            await run(db, 'COMMIT');
            res.status(201).json({ message: 'Rental approved', rentalId: result.lastID, status: 'approved' });
        } catch (err) {
            await run(db, 'ROLLBACK');
            throw err;
        }
    } catch (err) {
        console.error('[POST /api/rentals]', err);
        res.status(500).json({ error: 'Failed to create rental request' });
    }
});

// ─── API: Admin — Rental Requests ─────────────────────────────────────────────

// GET /api/admin/rentals/pending
// All pending requests for the admin approval queue.
app.get('/api/admin/rentals/pending', requireAuth, requireStaff, async (req, res) => {
    try {
        let teacherFilter = '';
        const params = [];
        if (req.user.role === 'teacher') {
            const userRow = await getUserByEmail(db, req.user.email);
            teacherFilter = `AND r.class_id IN (SELECT class_id FROM class_teachers WHERE user_id = ?)`;
            params.push(userRow.user_id);
        }

        const rentals = await all(db, `
            SELECT
                r.rental_id          AS id,
                r.quantity,
                r.rental_start       AS rentalStart,
                r.return_due         AS returnDue,
                r.created_at         AS createdAt,
                u.display_name       AS studentName,
                u.email              AS studentEmail,
                g.gear_id            AS gearId,
                g.name               AS gearName,
                g.quantity_available AS quantityAvailable,
                r.class_id           AS classId,
                c.name               AS className
            FROM rentals r
            JOIN users u ON u.user_id = r.user_id
            JOIN gear  g ON g.gear_id = r.gear_id
            LEFT JOIN classes c ON c.class_id = r.class_id
            WHERE r.status = 'pending'
            ${teacherFilter}
            ORDER BY r.created_at ASC
        `, params);
        res.json(rentals);
    } catch (err) {
        console.error('[GET /api/admin/rentals/pending]', err);
        res.status(500).json({ error: 'Failed to fetch pending requests' });
    }
});

// GET /api/admin/rentals/active
// Approved rentals that have not yet been returned, for the Active Rentals tab.
app.get('/api/admin/rentals/active', requireAuth, requireStaff, async (req, res) => {
    try {
        let teacherFilter = '';
        const params = [];
        if (req.user.role === 'teacher') {
            const userRow = await getUserByEmail(db, req.user.email);
            teacherFilter = `AND r.class_id IN (SELECT class_id FROM class_teachers WHERE user_id = ?)`;
            params.push(userRow.user_id);
        }

        const rentals = await all(db, `
            SELECT
                r.rental_id    AS id,
                r.quantity,
                r.rental_start AS rentalStart,
                r.return_due   AS returnDue,
                u.display_name AS studentName,
                u.email        AS studentEmail,
                g.gear_id      AS gearId,
                g.name         AS gearName,
                (date(r.return_due) < date('now')) AS isOverdue,
                r.class_id     AS classId,
                c.name         AS className
            FROM rentals r
            JOIN users u ON u.user_id = r.user_id
            JOIN gear  g ON g.gear_id = r.gear_id
            LEFT JOIN classes c ON c.class_id = r.class_id
            WHERE r.status = 'approved' AND r.return_actual IS NULL
            ${teacherFilter}
            ORDER BY r.return_due ASC
        `, params);
        res.json(rentals);
    } catch (err) {
        console.error('[GET /api/admin/rentals/active]', err);
        res.status(500).json({ error: 'Failed to fetch active rentals' });
    }
});

// PATCH /api/admin/rentals/:id/approve
// Approves a pending request: decrements gear.quantity_available (guarded
// against overselling via a conditional UPDATE inside a transaction) and
// records the approving admin.
app.patch('/api/admin/rentals/:id/approve', requireAuth, requireStaff, async (req, res) => {
    const rentalId = req.params.id;

    try {
        const rental = await get(db, 'SELECT * FROM rentals WHERE rental_id = ?', [rentalId]);
        if (!rental) return res.status(404).json({ error: 'Rental not found' });
        if (rental.status !== 'pending') {
            return res.status(409).json({ error: `Rental is already ${rental.status}` });
        }

        const adminRow = await getUserByEmail(db, req.user.email);

        if (req.user.role === 'teacher') {
            if (rental.class_id == null || !(await isTeacherOfClass(db, adminRow.user_id, rental.class_id))) {
                return res.status(403).json({ error: 'Forbidden' });
            }
        }

        await run(db, 'BEGIN IMMEDIATE');
        try {
            if (!(await tryDecrementGear(db, rental.gear_id, rental.quantity))) {
                await run(db, 'ROLLBACK');
                return res.status(409).json({ error: 'Insufficient availability to approve this request' });
            }

            await run(db, `
                UPDATE rentals SET status = 'approved', approved_by = ?, updated_at = CURRENT_TIMESTAMP
                WHERE rental_id = ?
            `, [adminRow.user_id, rentalId]);

            await logAction(db, {
                actorUserId: adminRow.user_id,
                action: 'APPROVE',
                targetRentalId: rentalId,
                targetGearId: rental.gear_id,
            });

            await run(db, 'COMMIT');
        } catch (err) {
            await run(db, 'ROLLBACK');
            throw err;
        }

        res.json({ message: 'Rental approved' });
    } catch (err) {
        console.error(`[PATCH /api/admin/rentals/${req.params.id}/approve]`, err);
        res.status(500).json({ error: 'Failed to approve rental' });
    }
});

// PATCH /api/admin/rentals/:id/reject
// Rejects a pending request with a mandatory reason. Availability is
// untouched, since approval never decremented it.
// Body: { reason }
app.patch('/api/admin/rentals/:id/reject', requireAuth, requireStaff, async (req, res) => {
    const rentalId = req.params.id;
    const reason = req.body?.reason?.trim();

    if (!reason) {
        return res.status(400).json({ error: 'A reason is required to reject a request' });
    }

    try {
        const rental = await get(db, 'SELECT * FROM rentals WHERE rental_id = ?', [rentalId]);
        if (!rental) return res.status(404).json({ error: 'Rental not found' });
        if (rental.status !== 'pending') {
            return res.status(409).json({ error: `Rental is already ${rental.status}` });
        }

        const adminRow = await getUserByEmail(db, req.user.email);

        if (req.user.role === 'teacher') {
            if (rental.class_id == null || !(await isTeacherOfClass(db, adminRow.user_id, rental.class_id))) {
                return res.status(403).json({ error: 'Forbidden' });
            }
        }

        await run(db, `
            UPDATE rentals SET status = 'rejected', rejection_reason = ?, approved_by = ?, updated_at = CURRENT_TIMESTAMP
            WHERE rental_id = ?
        `, [reason, adminRow.user_id, rentalId]);

        await logAction(db, {
            actorUserId: adminRow.user_id,
            action: 'REJECT',
            targetRentalId: rentalId,
            targetGearId: rental.gear_id,
            details: { reason },
        });

        res.json({ message: 'Rental rejected' });
    } catch (err) {
        console.error(`[PATCH /api/admin/rentals/${req.params.id}/reject]`, err);
        res.status(500).json({ error: 'Failed to reject rental' });
    }
});

// PATCH /api/admin/rentals/:id/return
// Marks an approved rental as returned, restoring gear.quantity_available.
app.patch('/api/admin/rentals/:id/return', requireAuth, requireStaff, async (req, res) => {
    const rentalId = req.params.id;

    try {
        const rental = await get(db, 'SELECT * FROM rentals WHERE rental_id = ?', [rentalId]);
        if (!rental) return res.status(404).json({ error: 'Rental not found' });
        if (rental.status !== 'approved' || rental.return_actual) {
            return res.status(409).json({ error: 'Only approved, unreturned rentals can be marked as returned' });
        }

        const adminRow = await getUserByEmail(db, req.user.email);

        if (req.user.role === 'teacher') {
            if (rental.class_id == null || !(await isTeacherOfClass(db, adminRow.user_id, rental.class_id))) {
                return res.status(403).json({ error: 'Forbidden' });
            }
        }

        await run(db, 'BEGIN IMMEDIATE');
        try {
            await run(db, `
                UPDATE gear SET quantity_available = quantity_available + ?
                WHERE gear_id = ?
            `, [rental.quantity, rental.gear_id]);

            await run(db, `
                UPDATE rentals SET status = 'returned', return_actual = date('now'), updated_at = CURRENT_TIMESTAMP
                WHERE rental_id = ?
            `, [rentalId]);

            await logAction(db, {
                actorUserId: adminRow.user_id,
                action: 'RETURN',
                targetRentalId: rentalId,
                targetGearId: rental.gear_id,
            });

            await run(db, 'COMMIT');
        } catch (err) {
            await run(db, 'ROLLBACK');
            throw err;
        }

        res.json({ message: 'Rental marked as returned' });
    } catch (err) {
        console.error(`[PATCH /api/admin/rentals/${req.params.id}/return]`, err);
        res.status(500).json({ error: 'Failed to mark rental as returned' });
    }
});

// ─── API: Admin — Gear ────────────────────────────────────────────────────────

// GET /api/admin/gear
// Gear inventory (with category, condition, availability) for the admin
// Inventory tab. CSV bulk-upload is out of scope for this assessment.
app.get('/api/admin/gear', requireAuth, requireAdmin, async (req, res) => {
    try {
        const gear = await all(db, `
            SELECT
                g.gear_id            AS id,
                g.name,
                g.description,
                gc.name              AS category,
                g.quantity_total     AS quantityTotal,
                g.quantity_available AS quantityAvailable,
                g.condition,
                g.image_url          AS imageUrl,
                g.manufacturer,
                g.model_no           AS modelNo,
                g.serial_no          AS serialNo,
                g.type
            FROM gear g
            LEFT JOIN gear_categories gc ON gc.category_id = g.category_id
            ORDER BY gc.name, g.name
        `);
        res.json(gear);
    } catch (err) {
        console.error('[GET /api/admin/gear]', err);
        res.status(500).json({ error: 'Failed to fetch gear inventory' });
    }
});

// GET /api/admin/categories
// Lists gear categories for the Add Gear form's category picker.
app.get('/api/admin/categories', requireAuth, requireAdmin, async (req, res) => {
    try {
        const categories = await all(db, `
            SELECT category_id AS id, name, description
            FROM gear_categories
            ORDER BY name
        `);
        res.json(categories);
    } catch (err) {
        console.error('[GET /api/admin/categories]', err);
        res.status(500).json({ error: 'Failed to fetch categories' });
    }
});

// POST /api/admin/categories
// Creates a new gear category. Body: { name, description? }
app.post('/api/admin/categories', requireAuth, requireAdmin, async (req, res) => {
    const name = (req.body.name || '').trim();
    const description = (req.body.description || '').trim() || null;

    if (!name) {
        return res.status(400).json({ error: 'Category name is required' });
    }

    try {
        const existing = await get(db, 'SELECT category_id FROM gear_categories WHERE name = ?', [name]);
        if (existing) {
            return res.status(409).json({ error: 'A category with that name already exists' });
        }

        const result = await run(db, `
            INSERT INTO gear_categories (name, description) VALUES (?, ?)
        `, [name, description]);

        res.status(201).json({ id: result.lastID, name, description });
    } catch (err) {
        console.error('[POST /api/admin/categories]', err);
        res.status(500).json({ error: 'Failed to create category' });
    }
});

// POST /api/admin/gear/upload-image
// Accepts a base64 data URL (from the admin gear image picker), writes it to
// /uploads/gear and returns its served path so it can be saved as a gear's
// imageUrl without bloating the database.
// Body: { dataUrl: "data:image/<png|jpeg|webp|gif>;base64,...." }
const IMAGE_DATA_URL_RE = /^data:image\/(png|jpeg|jpg|webp|gif);base64,([a-zA-Z0-9+/]+=*)$/;

app.post('/api/admin/gear/upload-image', requireAuth, requireAdmin, async (req, res) => {
    const match = IMAGE_DATA_URL_RE.exec(req.body?.dataUrl || '');
    if (!match) {
        return res.status(400).json({ error: 'Expected a base64 image data URL' });
    }

    try {
        const ext = match[1] === 'jpeg' ? 'jpg' : match[1];
        const filename = `${crypto.randomUUID()}.${ext}`;
        await fs.promises.writeFile(path.join(GEAR_UPLOADS_DIR, filename), Buffer.from(match[2], 'base64'));
        res.status(201).json({ url: `/uploads/gear/${filename}` });
    } catch (err) {
        console.error('[POST /api/admin/gear/upload-image]', err);
        res.status(500).json({ error: 'Failed to upload image' });
    }
});

// POST /api/admin/gear
// Adds a new gear item to the inventory.
// Body: { name, categoryId?, description?, manufacturer?, modelNo?, serialNo?,
//         type?, condition?, quantityTotal, imageUrl? }
app.post('/api/admin/gear', requireAuth, requireAdmin, async (req, res) => {
    const {
        name, categoryId, description, manufacturer, modelNo, serialNo,
        type, condition, quantityTotal, imageUrl,
    } = req.body;

    const trimmedName = (name || '').trim();
    const qty = Number(quantityTotal);

    if (!trimmedName) {
        return res.status(400).json({ error: 'Gear name is required' });
    }
    if (!Number.isInteger(qty) || qty < 0) {
        return res.status(400).json({ error: 'quantityTotal must be a non-negative integer' });
    }

    try {
        if (categoryId) {
            const category = await get(db, 'SELECT category_id FROM gear_categories WHERE category_id = ?', [categoryId]);
            if (!category) return res.status(404).json({ error: 'Category not found' });
        }

        const result = await run(db, `
            INSERT INTO gear (
                category_id, name, description, quantity_total, quantity_available,
                condition, image_url, manufacturer, model_no, serial_no, type
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            categoryId || null, trimmedName, description || null, qty, qty,
            condition || 'Good', imageUrl || null, manufacturer || null,
            modelNo || null, serialNo || null, type || null,
        ]);

        const userRow = await getUserByEmail(db, req.user.email);
        await logAction(db, {
            actorUserId: userRow?.user_id,
            action: 'CREATE_GEAR',
            targetGearId: result.lastID,
            details: { name: trimmedName, quantityTotal: qty },
        });

        const created = await get(db, `
            SELECT
                g.gear_id            AS id,
                g.name,
                g.description,
                gc.name              AS category,
                g.quantity_total     AS quantityTotal,
                g.quantity_available AS quantityAvailable,
                g.condition,
                g.image_url          AS imageUrl,
                g.manufacturer,
                g.model_no           AS modelNo,
                g.serial_no          AS serialNo,
                g.type
            FROM gear g
            LEFT JOIN gear_categories gc ON gc.category_id = g.category_id
            WHERE g.gear_id = ?
        `, [result.lastID]);

        res.status(201).json(created);
    } catch (err) {
        console.error('[POST /api/admin/gear]', err);
        res.status(500).json({ error: 'Failed to create gear' });
    }
});

// PATCH /api/admin/gear/:id
// Updates an existing gear item's details and inventory counts.
// Body: { name, categoryId?, description?, manufacturer?, modelNo?, serialNo?,
//         type?, condition?, quantityTotal, quantityAvailable, imageUrl? }
app.patch('/api/admin/gear/:id', requireAuth, requireAdmin, async (req, res) => {
    const gearId = req.params.id;
    const {
        name, categoryId, description, manufacturer, modelNo, serialNo,
        type, condition, quantityTotal, quantityAvailable, imageUrl,
    } = req.body;

    const trimmedName = (name || '').trim();
    const qtyTotal = Number(quantityTotal);
    const qtyAvailable = Number(quantityAvailable);

    if (!trimmedName) {
        return res.status(400).json({ error: 'Gear name is required' });
    }
    if (!Number.isInteger(qtyTotal) || qtyTotal < 0) {
        return res.status(400).json({ error: 'quantityTotal must be a non-negative integer' });
    }
    if (!Number.isInteger(qtyAvailable) || qtyAvailable < 0 || qtyAvailable > qtyTotal) {
        return res.status(400).json({ error: 'quantityAvailable must be between 0 and quantityTotal' });
    }

    try {
        const existing = await get(db, 'SELECT gear_id FROM gear WHERE gear_id = ?', [gearId]);
        if (!existing) return res.status(404).json({ error: 'Gear not found' });

        if (categoryId) {
            const category = await get(db, 'SELECT category_id FROM gear_categories WHERE category_id = ?', [categoryId]);
            if (!category) return res.status(404).json({ error: 'Category not found' });
        }

        await run(db, `
            UPDATE gear SET
                category_id = ?, name = ?, description = ?, quantity_total = ?,
                quantity_available = ?, condition = ?, image_url = ?,
                manufacturer = ?, model_no = ?, serial_no = ?, type = ?
            WHERE gear_id = ?
        `, [
            categoryId || null, trimmedName, description || null, qtyTotal,
            qtyAvailable, condition || 'Good', imageUrl || null, manufacturer || null,
            modelNo || null, serialNo || null, type || null, gearId,
        ]);

        const userRow = await getUserByEmail(db, req.user.email);
        await logAction(db, {
            actorUserId: userRow?.user_id,
            action: 'UPDATE_GEAR',
            targetGearId: gearId,
            details: { name: trimmedName, quantityTotal: qtyTotal, quantityAvailable: qtyAvailable },
        });

        const updated = await get(db, `
            SELECT
                g.gear_id            AS id,
                g.name,
                g.description,
                gc.name              AS category,
                g.quantity_total     AS quantityTotal,
                g.quantity_available AS quantityAvailable,
                g.condition,
                g.image_url          AS imageUrl,
                g.manufacturer,
                g.model_no           AS modelNo,
                g.serial_no          AS serialNo,
                g.type
            FROM gear g
            LEFT JOIN gear_categories gc ON gc.category_id = g.category_id
            WHERE g.gear_id = ?
        `, [gearId]);

        res.json(updated);
    } catch (err) {
        console.error(`[PATCH /api/admin/gear/${req.params.id}]`, err);
        res.status(500).json({ error: 'Failed to update gear' });
    }
});

// ─── API: Admin — Classes ─────────────────────────────────────────────────────

// GET /api/admin/classes
// All classes with teacher/student counts, for the admin Classes tab.
app.get('/api/admin/classes', requireAuth, requireAdmin, async (req, res) => {
    try {
        const classes = await all(db, `
            SELECT
                c.class_id AS id,
                c.name,
                c.description,
                (SELECT COUNT(*) FROM class_teachers ct WHERE ct.class_id = c.class_id) AS teacherCount,
                (SELECT COUNT(*) FROM class_enrollments ce WHERE ce.class_id = c.class_id) AS studentCount
            FROM classes c
            ORDER BY c.name
        `);
        res.json(classes);
    } catch (err) {
        console.error('[GET /api/admin/classes]', err);
        res.status(500).json({ error: 'Failed to fetch classes' });
    }
});

// POST /api/admin/classes
// Creates a new class. Body: { name, description? }
app.post('/api/admin/classes', requireAuth, requireAdmin, async (req, res) => {
    const name = (req.body.name || '').trim();
    const description = (req.body.description || '').trim() || null;

    if (!name) {
        return res.status(400).json({ error: 'Class name is required' });
    }

    try {
        const result = await run(db, `
            INSERT INTO classes (name, description) VALUES (?, ?)
        `, [name, description]);

        const userRow = await getUserByEmail(db, req.user.email);
        await logAction(db, {
            actorUserId: userRow?.user_id,
            action: 'CREATE_CLASS',
            details: { classId: result.lastID, name },
        });

        res.status(201).json({ id: result.lastID, name, description, teacherCount: 0, studentCount: 0 });
    } catch (err) {
        console.error('[POST /api/admin/classes]', err);
        res.status(500).json({ error: 'Failed to create class' });
    }
});

// GET /api/admin/classes/:id
// Full class detail (roster + recent rentals). Admins can view any class;
// teachers only their own — this is also used by the teacher's read-only
// "My Classes" roster view.
app.get('/api/admin/classes/:id', requireAuth, requireStaff, async (req, res) => {
    const classId = req.params.id;

    try {
        const classRow = await get(db, `
            SELECT class_id AS id, name, description FROM classes WHERE class_id = ?
        `, [classId]);
        if (!classRow) return res.status(404).json({ error: 'Class not found' });

        if (req.user.role === 'teacher') {
            const userRow = await getUserByEmail(db, req.user.email);
            if (!(await isTeacherOfClass(db, userRow.user_id, classId))) {
                return res.status(403).json({ error: 'Forbidden' });
            }
        }

        const teachers = await all(db, `
            SELECT u.user_id AS id, u.display_name AS displayName, u.email, u.role
            FROM class_teachers ct
            JOIN users u ON u.user_id = ct.user_id
            WHERE ct.class_id = ?
            ORDER BY u.display_name
        `, [classId]);

        const students = await all(db, `
            SELECT u.user_id AS id, u.display_name AS displayName, u.email, u.role
            FROM class_enrollments ce
            JOIN users u ON u.user_id = ce.user_id
            WHERE ce.class_id = ?
            ORDER BY u.display_name
        `, [classId]);

        const rentals = await all(db, `
            SELECT
                r.rental_id    AS id,
                r.quantity,
                r.rental_start AS rentalStart,
                r.return_due   AS returnDue,
                r.status,
                u.display_name AS studentName,
                g.name         AS gearName
            FROM rentals r
            JOIN users u ON u.user_id = r.user_id
            JOIN gear  g ON g.gear_id = r.gear_id
            WHERE r.class_id = ?
            ORDER BY r.created_at DESC
            LIMIT 50
        `, [classId]);

        res.json({ ...classRow, teachers, students, rentals });
    } catch (err) {
        console.error(`[GET /api/admin/classes/${req.params.id}]`, err);
        res.status(500).json({ error: 'Failed to fetch class' });
    }
});

// POST /api/admin/classes/:id/teachers
// Adds a teacher to a class. Body: { userId }
app.post('/api/admin/classes/:id/teachers', requireAuth, requireAdmin, async (req, res) => {
    const classId = req.params.id;
    const userId = req.body?.userId;

    if (!userId) return res.status(400).json({ error: 'userId is required' });

    try {
        const classRow = await get(db, 'SELECT class_id FROM classes WHERE class_id = ?', [classId]);
        if (!classRow) return res.status(404).json({ error: 'Class not found' });

        const targetUser = await get(db, 'SELECT user_id FROM users WHERE user_id = ?', [userId]);
        if (!targetUser) return res.status(404).json({ error: 'User not found' });

        await run(db, `INSERT OR IGNORE INTO class_teachers (class_id, user_id) VALUES (?, ?)`, [classId, userId]);

        const actorRow = await getUserByEmail(db, req.user.email);
        await logAction(db, {
            actorUserId: actorRow?.user_id,
            action: 'ADD_CLASS_TEACHER',
            details: { classId: Number(classId), userId: Number(userId) },
        });

        res.status(201).json({ message: 'Teacher added' });
    } catch (err) {
        console.error(`[POST /api/admin/classes/${req.params.id}/teachers]`, err);
        res.status(500).json({ error: 'Failed to add teacher' });
    }
});

// DELETE /api/admin/classes/:id/teachers/:userId
app.delete('/api/admin/classes/:id/teachers/:userId', requireAuth, requireAdmin, async (req, res) => {
    const { id: classId, userId } = req.params;

    try {
        await run(db, `DELETE FROM class_teachers WHERE class_id = ? AND user_id = ?`, [classId, userId]);

        const actorRow = await getUserByEmail(db, req.user.email);
        await logAction(db, {
            actorUserId: actorRow?.user_id,
            action: 'REMOVE_CLASS_TEACHER',
            details: { classId: Number(classId), userId: Number(userId) },
        });

        res.json({ message: 'Teacher removed' });
    } catch (err) {
        console.error(`[DELETE /api/admin/classes/${req.params.id}/teachers/${req.params.userId}]`, err);
        res.status(500).json({ error: 'Failed to remove teacher' });
    }
});

// POST /api/admin/classes/:id/students
// Enrolls a student in a class. Body: { userId }
app.post('/api/admin/classes/:id/students', requireAuth, requireAdmin, async (req, res) => {
    const classId = req.params.id;
    const userId = req.body?.userId;

    if (!userId) return res.status(400).json({ error: 'userId is required' });

    try {
        const classRow = await get(db, 'SELECT class_id FROM classes WHERE class_id = ?', [classId]);
        if (!classRow) return res.status(404).json({ error: 'Class not found' });

        const targetUser = await get(db, 'SELECT user_id FROM users WHERE user_id = ?', [userId]);
        if (!targetUser) return res.status(404).json({ error: 'User not found' });

        await run(db, `INSERT OR IGNORE INTO class_enrollments (class_id, user_id) VALUES (?, ?)`, [classId, userId]);

        const actorRow = await getUserByEmail(db, req.user.email);
        await logAction(db, {
            actorUserId: actorRow?.user_id,
            action: 'ADD_CLASS_STUDENT',
            details: { classId: Number(classId), userId: Number(userId) },
        });

        res.status(201).json({ message: 'Student added' });
    } catch (err) {
        console.error(`[POST /api/admin/classes/${req.params.id}/students]`, err);
        res.status(500).json({ error: 'Failed to add student' });
    }
});

// DELETE /api/admin/classes/:id/students/:userId
app.delete('/api/admin/classes/:id/students/:userId', requireAuth, requireAdmin, async (req, res) => {
    const { id: classId, userId } = req.params;

    try {
        await run(db, `DELETE FROM class_enrollments WHERE class_id = ? AND user_id = ?`, [classId, userId]);

        const actorRow = await getUserByEmail(db, req.user.email);
        await logAction(db, {
            actorUserId: actorRow?.user_id,
            action: 'REMOVE_CLASS_STUDENT',
            details: { classId: Number(classId), userId: Number(userId) },
        });

        res.json({ message: 'Student removed' });
    } catch (err) {
        console.error(`[DELETE /api/admin/classes/${req.params.id}/students/${req.params.userId}]`, err);
        res.status(500).json({ error: 'Failed to remove student' });
    }
});

// GET /api/admin/users?search=
// User lookup for the admin Classes UI's "add teacher/student" search.
app.get('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
    const search = `%${(req.query.search || '').trim()}%`;

    try {
        const users = await all(db, `
            SELECT user_id AS id, display_name AS displayName, email, role
            FROM users
            WHERE display_name LIKE ? OR email LIKE ?
            ORDER BY display_name
            LIMIT 20
        `, [search, search]);

        res.json(users);
    } catch (err) {
        console.error('[GET /api/admin/users]', err);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

// ─── API: Admin — Stats ───────────────────────────────────────────────────────

// GET /api/admin/stats
// Aggregated numbers for the four stat cards at the top of AdminPage.
app.get('/api/admin/stats', requireAuth, requireAdmin, async (req, res) => {
    try {
        const [pending]   = await all(db, `SELECT COUNT(*) AS n FROM rentals WHERE status = 'pending'`);
        const [active]    = await all(db, `
            SELECT COUNT(*) AS n FROM rentals WHERE status = 'approved' AND return_actual IS NULL
        `);
        const [overdue]   = await all(db, `
            SELECT COUNT(*) AS n FROM rentals
            WHERE status = 'approved' AND return_actual IS NULL AND date(return_due) < date('now')
        `);
        const [totalGear] = await all(db, 'SELECT COUNT(*) AS n FROM gear');

        res.json({
            pending:   pending.n,
            active:    active.n,
            overdue:   overdue.n,
            totalGear: totalGear.n,
        });
    } catch (err) {
        console.error('[GET /api/admin/stats]', err);
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

// ─── SPA Catch-all ────────────────────────────────────────────────────────────

// This MUST be the last route. For any URL that isn't an API route or a real
// static file, send back index.html so React Router can handle client-side
// navigation (e.g. /profile, /admin).
app.get('*', (req, res) => {
    res.sendFile(path.join(DIST, 'index.html'));
});

// ─── Start ────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
    console.log(`Server running → http://localhost:${PORT}`);
    console.log(`Serving Vite build from: ${DIST}`);
    console.log(`IdP entry point: ${entryPoint}`);
});