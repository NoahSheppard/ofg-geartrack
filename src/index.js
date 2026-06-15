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
import { logAction } from './util/audit.js';

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
            // ('admin', 'teacher', 'student').
            role:      (profile?.role || attributes.role || '').toLowerCase() || undefined,
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

// ─── Dev / Emergency Bypass Login ─────────────────────────────────────────────

// Outside production, allow logging in as a fixed student or admin account
// without going through SAML. This doubles as the "local emergency admin
// bypass account" mitigation for risk R-01 (SAML SSO outage).
if (DEBUG) {
    app.post('/auth/dev-login', async (req, res) => {
        const role = req.body?.role === 'admin' ? 'admin' : 'student';
        const email = role === 'admin' ? 'dev.admin@hs.edu' : 'dev.student@hs.edu';
        const displayName = role === 'admin' ? 'Dev Admin' : 'Dev Student';

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

// POST /api/rentals
// Submits a new rental request from the Rental page. Creates a 'pending'
// rental record — availability is only adjusted on admin approval.
// Body: { gearId, quantity, rentalStart, returnDue, purpose? }
app.post('/api/rentals', requireAuth, async (req, res) => {
    const { gearId, quantity, rentalStart, returnDue, purpose } = req.body;
    const qty = Number(quantity);

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

    try {
        const userRow = await getUserByEmail(db, req.user.email);
        if (!userRow) return res.status(404).json({ error: 'User not found' });

        const gear = await get(db, 'SELECT * FROM gear WHERE gear_id = ?', [gearId]);
        if (!gear) return res.status(404).json({ error: 'Gear not found' });
        if (gear.quantity_available < qty) {
            return res.status(409).json({ error: 'Insufficient availability' });
        }

        const result = await run(db, `
            INSERT INTO rentals (user_id, gear_id, quantity, rental_start, return_due, status)
            VALUES (?, ?, ?, ?, ?, 'pending')
        `, [userRow.user_id, gearId, qty, rentalStart, returnDue]);

        await logAction(db, {
            actorUserId: userRow.user_id,
            action: 'REQUEST',
            targetRentalId: result.lastID,
            targetGearId: gearId,
            details: { quantity: qty, rentalStart, returnDue, purpose: purpose || null },
        });

        res.status(201).json({ message: 'Rental request submitted', rentalId: result.lastID });
    } catch (err) {
        console.error('[POST /api/rentals]', err);
        res.status(500).json({ error: 'Failed to create rental request' });
    }
});

// ─── API: Admin — Rental Requests ─────────────────────────────────────────────

// GET /api/admin/rentals/pending
// All pending requests for the admin approval queue.
app.get('/api/admin/rentals/pending', requireAuth, requireAdmin, async (req, res) => {
    try {
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
                g.quantity_available AS quantityAvailable
            FROM rentals r
            JOIN users u ON u.user_id = r.user_id
            JOIN gear  g ON g.gear_id = r.gear_id
            WHERE r.status = 'pending'
            ORDER BY r.created_at ASC
        `);
        res.json(rentals);
    } catch (err) {
        console.error('[GET /api/admin/rentals/pending]', err);
        res.status(500).json({ error: 'Failed to fetch pending requests' });
    }
});

// GET /api/admin/rentals/active
// Approved rentals that have not yet been returned, for the Active Rentals tab.
app.get('/api/admin/rentals/active', requireAuth, requireAdmin, async (req, res) => {
    try {
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
                (date(r.return_due) < date('now')) AS isOverdue
            FROM rentals r
            JOIN users u ON u.user_id = r.user_id
            JOIN gear  g ON g.gear_id = r.gear_id
            WHERE r.status = 'approved' AND r.return_actual IS NULL
            ORDER BY r.return_due ASC
        `);
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
app.patch('/api/admin/rentals/:id/approve', requireAuth, requireAdmin, async (req, res) => {
    const rentalId = req.params.id;

    try {
        const rental = await get(db, 'SELECT * FROM rentals WHERE rental_id = ?', [rentalId]);
        if (!rental) return res.status(404).json({ error: 'Rental not found' });
        if (rental.status !== 'pending') {
            return res.status(409).json({ error: `Rental is already ${rental.status}` });
        }

        const adminRow = await getUserByEmail(db, req.user.email);

        await run(db, 'BEGIN IMMEDIATE');
        try {
            const result = await run(db, `
                UPDATE gear SET quantity_available = quantity_available - ?
                WHERE gear_id = ? AND quantity_available >= ?
            `, [rental.quantity, rental.gear_id, rental.quantity]);

            if (result.changes !== 1) {
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
app.patch('/api/admin/rentals/:id/reject', requireAuth, requireAdmin, async (req, res) => {
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
app.patch('/api/admin/rentals/:id/return', requireAuth, requireAdmin, async (req, res) => {
    const rentalId = req.params.id;

    try {
        const rental = await get(db, 'SELECT * FROM rentals WHERE rental_id = ?', [rentalId]);
        if (!rental) return res.status(404).json({ error: 'Rental not found' });
        if (rental.status !== 'approved' || rental.return_actual) {
            return res.status(409).json({ error: 'Only approved, unreturned rentals can be marked as returned' });
        }

        const adminRow = await getUserByEmail(db, req.user.email);

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