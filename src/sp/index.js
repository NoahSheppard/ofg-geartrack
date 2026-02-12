const express = require('express');
const passport = require('passport');
const SamlStrategy = require('passport-saml').Strategy;
const bodyParser = require('body-parser');
const session = require('express-session');

const fs = require('fs');
const path = require('path');

const spCert = fs.readFileSync(path.join(__dirname, '../../certificates/sp-signing.cert'), 'utf-8');
const spKey = fs.readFileSync(path.join(__dirname, '../../certificates/sp-signing.key'), 'utf-8');
const spEncryptCert = fs.readFileSync(path.join(__dirname, '../../certificates/sp-encrypt.cert'), 'utf-8');
const spEncryptKey = fs.readFileSync(path.join(__dirname, '../../certificates/sp-encrypt.key'), 'utf-8');
const idpCert = fs.readFileSync(path.join(__dirname, '../../certificates/idp-signing.cert'), 'utf-8');
const entryPoint = 'http://localhost:3000/sso'

const app = express(); 
const PORT = 3001;

// Middleware
app.use(bodyParser.urlencoded({extended: false}));
app.use(bodyParser.json());
app.use(session({
    secret: 'sp-secret-key',
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
        identifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        wantAssertionsSigned: true,
        wantEncryptedAssertions: false,
        disableRequestedAuthnContext: true,
        acceptedClockSkewMs: 5000,
        disableRequestCompression: true
    },
    (profile, done) => {
        console.log('SAML Profile:', profile);
        return done(null, profile);
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
        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
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
            res.redirect('/dashboard');
        });
    })(req, res, next);
});

app.get('/dashboard', (req, res) => {
    if (req.isAuthenticated()) {
        res.send(`<h1>Welcome, ${req.user.displayName || req.user.name || 'User'}</h1>`);
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