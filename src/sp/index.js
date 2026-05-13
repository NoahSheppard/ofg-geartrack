import express from 'express';
import passport from 'passport';
import { Strategy as SamlStrategy } from 'passport-saml';
import bodyParser from 'body-parser';
import session from 'express-session';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createEngine } from 'express-react-views';
import { 
    db, 
    execute, 
    initialOperation, 
    run, 
    get, 
    all 
} from './util/db.js';
import { 
    createUser,
    updateUserLastLogin,
    deleteUserById,
    deleteUserByEmail,
    getUserByEmail 
} from './util/user.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const spCert = fs.readFileSync(path.join(__dirname, '../../certificates/sp-signing.cert'), 'utf-8');
const spKey = fs.readFileSync(path.join(__dirname, '../../certificates/sp-signing.key'), 'utf-8');
const spEncryptCert = fs.readFileSync(path.join(__dirname, '../../certificates/sp-encrypt.cert'), 'utf-8');
const spEncryptKey = fs.readFileSync(path.join(__dirname, '../../certificates/sp-encrypt.key'), 'utf-8');
const idpCert = fs.readFileSync(path.join(__dirname, '../../certificates/idp-signing.cert'), 'utf-8');
const entryPoint = 'http://localhost:3000/sso'

const app = express(); 
const PORT = 3001;

const DEBUG = true; 

// Databasing 
initialOperation();

// JSX Parsing
app.set('views', __dirname + '/views');
app.set('view engine', 'jsx');
app.engine('jsx', createEngine());

// Middleware
app.use(bodyParser.urlencoded({extended: false}));
app.use(bodyParser.json());
app.use(session({
    secret: 'sp-secret-key', // for the love of god change this in prod 
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, httpOnly: true } 
}));

app.use(passport.initialize());
app.use(passport.session());

// Configure Passport for SAML authentication
passport.use(
    new SamlStrategy({
        path: '/login/callback',
        entryPoint: entryPoint,
        issuer: 'geartrack-sp',
        cert: idpCert,  // IDP's certificate to verify signed responses
        identifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:username',
        wantAuthnResponseSigned: true,
        wantAssertionsSigned: true,
        wantEncryptedAssertions: true,
        disableRequestedAuthnContext: true,
        acceptedClockSkewMs: 5000,
        disableRequestCompression: true
    },
    (profile, done) => {
        const attributes = profile?.attributes || {};
        const normalized = {
            ...profile,
            attributes,
            email: profile?.email || attributes.email,
            displayName: profile?.displayName || attributes.displayName,
            givenName: profile?.givenName || attributes.givenName || attributes.firstName,
            surname: profile?.surname || attributes.surname || attributes.lastName,
            uid: profile?.uid || attributes.uid || attributes.username,
            role: profile?.role || attributes.role,
            userType: profile?.userType || attributes.userType
        };

        if (DEBUG) console.log('SAML Profile:', normalized);
        return done(null, normalized);
    }
));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

app.get('/sp/metadata', (req, res) => {
    const cleanSigningCert = spCert
        .replace(/-----BEGIN CERTIFICATE-----/, '')
        .replace(/-----END CERTIFICATE-----/, '')
        .replace(/\n/g, '')
        .trim();
    
    const metadata = `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="geartrack-sp">
    <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <KeyDescriptor use="signing">
            <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data>
                    <X509Certificate>${cleanSigningCert}</X509Certificate>
                </X509Data>
            </KeyInfo>
        </KeyDescriptor>
        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:username</NameIDFormat>
        <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://localhost:${PORT}/login/callback" index="0" isDefault="true"/>
    </SPSSODescriptor>
</EntityDescriptor>`;
    res.type('application/xml').send(metadata);
});

app.get('/login', (req, res) => {
    passport.authenticate('saml')(req, res);
});

app.post('/login/callback', (req, res, next) => {
    passport.authenticate('saml', {failureRedirect: '/'}, (err, user, info) => {
        if (err) {
            console.error('SAML Error:', err);
            return res.status(500).send(`<h1>SAML Error</h1><pre>${err.message}</pre>`);
        }
        if (!user) {
            console.error('SAML Auth Failed:', info);
            return res.redirect('/');
        }
        req.logIn(user, (err) => {
            if (err) return next(err);
            res.redirect('/');
        });
    })(req, res, next);
});

app.get('/', (req, res) => {
    if (req.isAuthenticated()) {
        let username = req.user.username;
        let email = username + req.user.email;
        let role = req.user.role;
        let displayName = req.user.displayName;
        getUserByEmail(db, email).then(user => {
            if (!user) {
                if (DEBUG) console.log(`User with email ${email} not found in DB, creating new user.`);
                return createUser(db, {
                    email: email,
                    display_name: displayName,
                    role
                });
            } else {
                if (DEBUG) console.log(`User with email ${email} found in DB.`);
                return user.user_id;
            }
        }).then(userId => {
            if (DEBUG) console.log(`Authenticated user ID: ${userId}`);
            return updateUserLastLogin(db, userId);
        }).catch(err => {
            console.error('Error handling user after authentication:', err);
            res.send(`<h1>Error</h1><pre>${err}</pre>`);
        });

        res.render('dashboard', { user: req.user} );
        // code beyond this point will not execute
    } else {
        res.redirect('/login');
    }
});

app.get('/', (req, res) => {
    res.send(`<h1>SP is live, using ${entryPoint} as the IdP.</h1>`);
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}/`)
});