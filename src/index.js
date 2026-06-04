import express from 'express';
import passport from 'passport';
import { Strategy as SamlStrategy } from 'passport-saml';
import bodyParser from 'body-parser';
import session from 'express-session';
import fs from 'fs';
import path from 'path';
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

// ─── Config ───────────────────────────────────────────────────────────────────

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

// Vite builds into /dist at the project root (one level above /src)
const DIST  = path.join(__dirname, 'web/dist');
const PORT  = process.env.PORT || 3001;
const DEBUG = process.env.NODE_ENV !== 'production';

const idpCert    = fs.readFileSync(path.join(__dirname, '../certificates/idp-signing.cert'), 'utf-8');
const spCert     = fs.readFileSync(path.join(__dirname, '../certificates/sp-signing.cert'), 'utf-8');
const entryPoint = process.env.IDP_ENTRY_POINT || 'http://localhost:3000/sso';

// ─── App Setup ────────────────────────────────────────────────────────────────

const app = express();

initialOperation(); // run DB migrations / init

// Parse incoming request bodies
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Session (must come before passport)
app.use(session({
    secret: process.env.SESSION_SECRET || 'sp-secret-key-change-in-prod',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production', httpOnly: true },
}));

app.use(passport.initialize());
app.use(passport.session());

// Serve the Vite production build as static files.
// This handles JS bundles, CSS, images, and / → index.html automatically.
app.use(express.static(DIST));

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
            role:      profile?.role      || attributes.role,
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

// Protects admin-only routes.
function requireAdmin(req, res, next) {
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
// Returns the full gear catalogue for the Rental page.
app.get('/api/gear', requireAuth, async (req, res) => {
    try {
        const gear = await all(db, `
            SELECT
                id,
                name,
                category,
                description,
                photo,
                stock,
                max_rent_days AS maxRentDays
            FROM gear
            ORDER BY category, name
        `);
        res.json(gear);
    } catch (err) {
        console.error('[GET /api/gear]', err);
        res.status(500).json({ error: 'Failed to fetch gear' });
    }
});

// GET /api/gear/:id/units
// Returns every physical unit of one gear type, with live rental status.
// Used by the Admin gear detail modal.
app.get('/api/gear/:id/units', requireAuth, requireAdmin, async (req, res) => {
    try {
        const units = await all(db, `
            SELECT
                gu.id,
                gu.label,
                r.id          AS rentalId,
                r.status      AS rentalStatus,
                r.due_date    AS dueDate,
                u.display_name AS studentName,
                u.email        AS studentEmail
            FROM gear_units gu
            LEFT JOIN rentals r
                ON  r.unit_id = gu.id
                AND r.status IN ('Active', 'Overdue')
            LEFT JOIN users u
                ON  u.user_id = r.student_id
            WHERE gu.gear_id = ?
            ORDER BY gu.label
        `, [req.params.id]);
        res.json(units);
    } catch (err) {
        console.error(`[GET /api/gear/${req.params.id}/units]`, err);
        res.status(500).json({ error: 'Failed to fetch units' });
    }
});

// ─── API: Rentals ─────────────────────────────────────────────────────────────

// GET /api/rentals/me
// Returns the current user's active and overdue rentals.
// Used by ProfilePage.
app.get('/api/rentals/me', requireAuth, async (req, res) => {
    try {
        const userRow = await getUserByEmail(db, req.user.email);
        if (!userRow) return res.json([]);

        const rentals = await all(db, `
            SELECT
                r.id,
                r.gear_id        AS gearId,
                r.unit_id        AS unitId,
                r.status,
                r.due_date       AS dueDate,
                r.checkout_date  AS checkoutDate,
                g.name           AS gearName,
                g.photo          AS gearPhoto,
                g.category       AS gearCategory,
                gu.label         AS unitLabel
            FROM rentals r
            JOIN gear       g  ON g.id  = r.gear_id
            JOIN gear_units gu ON gu.id = r.unit_id
            WHERE r.student_id = ?
              AND r.status IN ('Active', 'Overdue')
            ORDER BY r.due_date ASC
        `, [userRow.user_id]);

        res.json(rentals);
    } catch (err) {
        console.error('[GET /api/rentals/me]', err);
        res.status(500).json({ error: 'Failed to fetch rentals' });
    }
});

// POST /api/rentals
// Submits a new rental request from the Rental page.
// Body: { gearId: string, durationDays: number }
app.post('/api/rentals', requireAuth, async (req, res) => {
    const { gearId, durationDays } = req.body;

    if (!gearId || !durationDays || durationDays < 1) {
        return res.status(400).json({ error: 'gearId and durationDays (≥ 1) are required' });
    }

    try {
        const userRow = await getUserByEmail(db, req.user.email);
        if (!userRow) return res.status(404).json({ error: 'User not found' });

        // Check the gear exists and has stock
        const gear = await get(db, 'SELECT * FROM gear WHERE id = ?', [gearId]);
        if (!gear)         return res.status(404).json({ error: 'Gear not found' });
        if (gear.stock <= 0) return res.status(409).json({ error: 'Out of stock' });
        if (durationDays > gear.max_rent_days) {
            return res.status(400).json({ error: `Maximum rental duration is ${gear.max_rent_days} days` });
        }

        // Find a free unit (not currently out on loan)
        const unit = await get(db, `
            SELECT gu.id FROM gear_units gu
            LEFT JOIN rentals r
                ON  r.unit_id = gu.id
                AND r.status IN ('Active', 'Overdue')
            WHERE gu.gear_id = ?
              AND r.id IS NULL
            LIMIT 1
        `, [gearId]);

        if (!unit) return res.status(409).json({ error: 'No units available' });

        const today        = new Date();
        const checkoutDate = today.toISOString().split('T')[0];
        const dueDate      = new Date(today.getTime() + durationDays * 86_400_000)
                                .toISOString().split('T')[0];

        await run(db, `
            INSERT INTO rentals (student_id, gear_id, unit_id, status, checkout_date, due_date)
            VALUES (?, ?, ?, 'Active', ?, ?)
        `, [userRow.user_id, gearId, unit.id, checkoutDate, dueDate]);

        // Decrement available stock
        await run(db, 'UPDATE gear SET stock = stock - 1 WHERE id = ?', [gearId]);

        res.status(201).json({ message: 'Rental created', dueDate });
    } catch (err) {
        console.error('[POST /api/rentals]', err);
        res.status(500).json({ error: 'Failed to create rental' });
    }
});

// ─── API: Classes ─────────────────────────────────────────────────────────────

// GET /api/classes/me
// Returns the classes the current user is enrolled in.
// Used by ProfilePage.
app.get('/api/classes/me', requireAuth, async (req, res) => {
    try {
        const userRow = await getUserByEmail(db, req.user.email);
        if (!userRow) return res.json([]);

        const classes = await all(db, `
            SELECT
                c.id,
                c.name,
                (SELECT COUNT(*) FROM class_enrollments WHERE class_id = c.id) AS studentCount
            FROM classes            c
            JOIN class_enrollments ce ON ce.class_id  = c.id
            WHERE ce.student_id = ?
            ORDER BY c.name
        `, [userRow.user_id]);

        res.json(classes);
    } catch (err) {
        console.error('[GET /api/classes/me]', err);
        res.status(500).json({ error: 'Failed to fetch classes' });
    }
});

// ─── API: Admin — Stats ───────────────────────────────────────────────────────

// GET /api/admin/stats
// Aggregated numbers for the four stat cards at the top of AdminPage.
app.get('/api/admin/stats', requireAuth, requireAdmin, async (req, res) => {
    try {
        const [totalUnits] = await all(db, 'SELECT COUNT(*) AS n FROM gear_units');
        const [outOnLoan]  = await all(db, `
            SELECT COUNT(*) AS n FROM rentals WHERE status IN ('Active', 'Overdue')
        `);
        const [overdue]    = await all(db, `
            SELECT COUNT(*) AS n FROM rentals WHERE status = 'Overdue'
        `);
        const [students]   = await all(db, `
            SELECT COUNT(*) AS n FROM users WHERE role = 'student'
        `);

        res.json({
            totalUnits: totalUnits.n,
            outOnLoan:  outOnLoan.n,
            overdue:    overdue.n,
            students:   students.n,
        });
    } catch (err) {
        console.error('[GET /api/admin/stats]', err);
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

// ─── API: Admin — Gear ────────────────────────────────────────────────────────

// GET /api/admin/gear
// Full gear list with per-item rental & overdue counts for the admin Inventory tab.
app.get('/api/admin/gear', requireAuth, requireAdmin, async (req, res) => {
    try {
        const gear = await all(db, `
            SELECT
                g.id,
                g.name,
                g.category,
                g.photo,
                g.stock,
                g.max_rent_days                                            AS maxRentDays,
                COUNT(gu.id)                                               AS totalUnits,
                SUM(CASE WHEN r.status IN ('Active','Overdue') THEN 1 ELSE 0 END) AS rentedCount,
                SUM(CASE WHEN r.status = 'Overdue'             THEN 1 ELSE 0 END) AS overdueCount
            FROM gear g
            LEFT JOIN gear_units gu ON gu.gear_id = g.id
            LEFT JOIN rentals    r  ON r.unit_id  = gu.id
                                   AND r.status IN ('Active', 'Overdue')
            GROUP BY g.id
            ORDER BY g.category, g.name
        `);

        // Attach per-unit status dots for the availability column
        const withUnits = await Promise.all(gear.map(async (item) => {
            const units = await all(db, `
                SELECT
                    gu.id,
                    gu.label,
                    COALESCE(r.status, 'Available') AS status
                FROM gear_units gu
                LEFT JOIN rentals r
                    ON  r.unit_id = gu.id
                    AND r.status IN ('Active', 'Overdue')
                WHERE gu.gear_id = ?
                ORDER BY gu.label
            `, [item.id]);
            return { ...item, units };
        }));

        res.json(withUnits);
    } catch (err) {
        console.error('[GET /api/admin/gear]', err);
        res.status(500).json({ error: 'Failed to fetch admin gear' });
    }
});

// ─── API: Admin — Students ────────────────────────────────────────────────────

// GET /api/admin/students
// All students with class counts and rental summary for the Students tab.
app.get('/api/admin/students', requireAuth, requireAdmin, async (req, res) => {
    try {
        const students = await all(db, `
            SELECT
                u.user_id                                                      AS id,
                u.display_name                                                 AS name,
                u.email,
                COUNT(DISTINCT ce.class_id)                                    AS classCount,
                SUM(CASE WHEN r.status IN ('Active','Overdue') THEN 1 ELSE 0 END) AS rentalCount,
                SUM(CASE WHEN r.status = 'Overdue'             THEN 1 ELSE 0 END) AS overdueCount
            FROM users u
            LEFT JOIN class_enrollments ce ON ce.student_id = u.user_id
            LEFT JOIN rentals            r  ON r.student_id = u.user_id
                                           AND r.status IN ('Active', 'Overdue')
            WHERE u.role = 'student'
            GROUP BY u.user_id
            ORDER BY u.display_name
        `);
        res.json(students);
    } catch (err) {
        console.error('[GET /api/admin/students]', err);
        res.status(500).json({ error: 'Failed to fetch students' });
    }
});

// GET /api/admin/students/:id
// Full profile for the student detail modal:
// their classes + their active rentals with gear info.
app.get('/api/admin/students/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const student = await get(db, `
            SELECT user_id AS id, display_name AS name, email
            FROM users WHERE user_id = ? AND role = 'student'
        `, [req.params.id]);

        if (!student) return res.status(404).json({ error: 'Student not found' });

        const classes = await all(db, `
            SELECT c.id, c.name
            FROM classes            c
            JOIN class_enrollments ce ON ce.class_id = c.id
            WHERE ce.student_id = ?
            ORDER BY c.name
        `, [req.params.id]);

        const rentals = await all(db, `
            SELECT
                r.id,
                r.status,
                r.due_date       AS dueDate,
                g.name           AS gearName,
                g.photo          AS gearPhoto,
                gu.label         AS unitLabel
            FROM rentals    r
            JOIN gear       g  ON g.id  = r.gear_id
            JOIN gear_units gu ON gu.id = r.unit_id
            WHERE r.student_id = ?
              AND r.status IN ('Active', 'Overdue')
            ORDER BY r.due_date ASC
        `, [req.params.id]);

        res.json({ ...student, classes, rentals });
    } catch (err) {
        console.error(`[GET /api/admin/students/${req.params.id}]`, err);
        res.status(500).json({ error: 'Failed to fetch student detail' });
    }
});

// ─── API: Admin — Classes ─────────────────────────────────────────────────────

// GET /api/admin/classes
// All classes with student counts and class-wide rental summary.
app.get('/api/admin/classes', requireAuth, requireAdmin, async (req, res) => {
    try {
        const classes = await all(db, `
            SELECT
                c.id,
                c.name,
                COUNT(DISTINCT ce.student_id)                                      AS studentCount,
                SUM(CASE WHEN r.status IN ('Active','Overdue') THEN 1 ELSE 0 END)  AS rentalCount,
                SUM(CASE WHEN r.status = 'Overdue'             THEN 1 ELSE 0 END)  AS overdueCount
            FROM classes            c
            LEFT JOIN class_enrollments ce ON ce.class_id   = c.id
            LEFT JOIN rentals            r  ON r.student_id = ce.student_id
                                           AND r.status IN ('Active', 'Overdue')
            GROUP BY c.id
            ORDER BY c.name
        `);
        res.json(classes);
    } catch (err) {
        console.error('[GET /api/admin/classes]', err);
        res.status(500).json({ error: 'Failed to fetch classes' });
    }
});

// GET /api/admin/classes/:id
// Full class info for the class detail modal:
// all enrolled students with their rental counts.
app.get('/api/admin/classes/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const cls = await get(db, 'SELECT id, name FROM classes WHERE id = ?', [req.params.id]);
        if (!cls) return res.status(404).json({ error: 'Class not found' });

        const students = await all(db, `
            SELECT
                u.user_id                                                      AS id,
                u.display_name                                                 AS name,
                u.email,
                SUM(CASE WHEN r.status IN ('Active','Overdue') THEN 1 ELSE 0 END) AS rentalCount,
                SUM(CASE WHEN r.status = 'Overdue'             THEN 1 ELSE 0 END) AS overdueCount
            FROM class_enrollments ce
            JOIN users   u ON u.user_id    = ce.student_id
            LEFT JOIN rentals r ON r.student_id = u.user_id
                               AND r.status IN ('Active', 'Overdue')
            WHERE ce.class_id = ?
            GROUP BY u.user_id
            ORDER BY u.display_name
        `, [req.params.id]);

        res.json({ ...cls, students });
    } catch (err) {
        console.error(`[GET /api/admin/classes/${req.params.id}]`, err);
        res.status(500).json({ error: 'Failed to fetch class detail' });
    }
});

// ─── API: Admin — Rental Management ──────────────────────────────────────────

// PATCH /api/admin/rentals/:id
// Mark a rental as Returned (or correct its status).
// Body: { status: 'Active' | 'Overdue' | 'Returned' }
app.patch('/api/admin/rentals/:id', requireAuth, requireAdmin, async (req, res) => {
    const { status } = req.body;
    const allowed = ['Active', 'Overdue', 'Returned'];

    if (!allowed.includes(status)) {
        return res.status(400).json({ error: `status must be one of: ${allowed.join(', ')}` });
    }

    try {
        const rental = await get(db, 'SELECT * FROM rentals WHERE id = ?', [req.params.id]);
        if (!rental) return res.status(404).json({ error: 'Rental not found' });

        await run(db, 'UPDATE rentals SET status = ? WHERE id = ?', [status, req.params.id]);

        // Give stock back when gear is returned
        if (status === 'Returned' && rental.status !== 'Returned') {
            await run(db, 'UPDATE gear SET stock = stock + 1 WHERE id = ?', [rental.gear_id]);
        }

        res.json({ message: 'Rental updated' });
    } catch (err) {
        console.error(`[PATCH /api/admin/rentals/${req.params.id}]`, err);
        res.status(500).json({ error: 'Failed to update rental' });
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