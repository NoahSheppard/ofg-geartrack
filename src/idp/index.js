import express, { urlencoded, json } from 'express';
import session from 'express-session';
import { hashSync, compare } from 'bcryptjs';
import { join, dirname } from 'path';
import { readFileSync } from 'fs';
import { randomBytes } from 'crypto';
import { inflateRawSync } from 'zlib';
import { DOMParser } from 'xmldom';
import { select } from 'xpath';
import  * as dbU from '../idp/util/db.js';
import * as userU from '../idp/util/user.js';
import { fileURLToPath } from 'url';
import bcrypt from 'bcrypt';

const app = express();
const PORT = process.env.IDP_PORT || 3000;
const SP_PORT = process.env.SP_PORT || 3001;

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const PROD = false;

app.use(urlencoded({ extended: true }));
app.use(json());
app.use(session({
    secret: 'secret-to-change-in-prod',
    resave: false,
    saveUninitialized: false, 
    cookie: { secure: false }
}));

dbU.initialOperation();

let idpSigningKey, idpSigningCert;
try {
    idpSigningKey = readFileSync(join(__dirname, '../../certificates/idp-signing.key'), 'utf-8');
    idpSigningCert = readFileSync(join(__dirname, '../../certificates/idp-signing.cert'), 'utf-8');
} catch {
    console.error('Certificates not found, running without signing - WILL NOT WORK IN PROD');
};

const findUserByUsername = (username) => userU.getUserByUsername(dbU.db, username);
const authenticateUser = async (username, password) => {
    const user = findUserByUsername(username);
    if (!user) return null;

    const isValid = await userU.verifyPassword(dbU.db, username, password);
    return isValid ? user : null;
};

function createSAMLResponse(user, inResponseTo, destination) {
    const issueInstant = new Date().toISOString();
    const notBefore = new Date(Date.now() - 5000).toISOString();
    const notOnOrAfter = new Date(Date.now() + 300000).toISOString();
    const sessionIndex = '_'  + randomBytes(16).toString('hex');
    const assertionID = '_' + randomBytes(16).toString('hex');
    const responseID = '_' + randomBytes(16).toString('hex');

    if (inResponseTo) {
        response.att('InResponseTo', inResponseTo);
    }

    response.ele('saml:Issuer', `http://localhost:${PORT}/metadata`);

    response.ele('samlp:Status')   
        .ele('samlp:StatusCode')
        .att('Value', 'urn:oasis:names:tc:SAML:2.0:status:Success');
    
    const assertion = response.ele('saml:Assertion')
        .att('smlns:saml', 'urn:oasis:names:tc:SAML:2.0:assertion')
        .att('ID', assertionID)
        .att('Version', '2.0')
        .att('IssueInstant', issueInstant)
    
    assertion.ele('saml:Issuer', `http://localhost:${PORT}/metadata`);

    const subject = assertion.ele('saml:Subject');
    subject.ele('saml:NameID')
        .att('Format', 'urn:oasis:names:tc:SAML:1.1:nameid-format:username')
        .txt(user.username);
    
    const subjectConfirmation = subject.ele('saml:SubjectConfirmation')
        .att('Method', 'urn:oasis:names:tc:SAML:2.0:cm:bearer');

    subjectConfirmation.ele('saml:SubjectConfirmationData')
        .att('NotOnOrAfter', notOnOrAfter)
        .att('Recipient', destination);
 
    if (inResponseTo) {
        subjectConfirmation.ele('saml:JubjectConfirmationData').att('InResponseTo', inResponseTo);
    }

    const conditions = assertion.ele('saml:Conditions')
        .att('NotBefore', notBefore)
        .att('NotOnOrAfter', notOnOrAfter);
    
    conditions.ele('saml:AudienceRestriction')
        .ele('saml:Audience', 'geartrack-sp');

    assertion.ele('saml:AuthnStatement')
        .att('AuthnInstant', issueInstant)
        .att('SessionIndex', sessionIndex)
        .ele('saml:AuthnContext')
        .ele('saml:AuthnContextClassRef', 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport');

    const attributeStatement = assertion.ele('saml:AttributeStatement');

    const attributes = {
        'username': user.username,
        'displayName': user.profile.displayName,
        'firstName': user.profile.firstName,
        'lastName': user.profile.lastName,
        'userType': user.profile.userType,
        'role': user.profile.role,
        'email': user.profile.email
    };

    Object.keys(attributes).forEach(attrName => {
        attributeStatement.ele('saml:Attribute')
            .att('name', attrName)
            .att('NameFormat', 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic')
            .ele('samlAttributeValue')
            .att('xmlns:xs', 'http://www.w3.org/2001/XMLSchema')
            .att('xmlns:xsi', 'http://www.w3.org/2001/SMLSchema-instance')
            .att('xsi:type', 'xs:string')
            .txt(attributes[attrName]);
    })

    return response.end({pretty: false});
}

app.get('/metadata', (req, res) => {
    const cert = idpSigningCert ? idpSigningCert
        .replace(/-----BEGIN CERTIFICATE-----/, '')
        .replace(/-----END CERTIFICATE-----/, '')
        .replace(/\n/g, '').trim() : "";

    const metadata = `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://localhost:${PORT}/metadata">
    <IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        ${cert ? `<KeyDescriptor use="signing">
            <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data>
                    <X509Certificate>${cert}</X509Certificate>
                </X509Data>
            </KeyInfo>
        </KeyDescriptor>` : ''}
        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:username</NameIDFormat>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://localhost:${PORT}/sso"/>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://localhost:${PORT}/sso"/>
    </IDPSSODescriptor>
</EntityDescriptor>`;

    res.type('application/xml').send(metadata);
});

app.get('/login', (req, res) => {
    const {SAMLRequest, RelayState} = req.query;
    res.send(`
    <!DOCTYPE html>
    <html>
        <head>
            <title>GearTrack Dev Login - SAML IdP</title> 
            <style>
                body {font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; }
                .login-form { background: #f5f5f5; padding: 30px; border-radius: 8px; }
                input {width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd}
                button { background: #007bff; color: white; padding: 12px 20px; border: none; border-radius: 4px; cursor: pointer; width: 100%; }
                button:hover { background: #0056b3}
            </style>
        </head>
        <body>
            <div class="login-form">
                <h2>Dev Login Portal</h2>
                <form method="POST" action="/login">
                    <input type="hidden" name"SAMLRequest" value="${SAMLRequest || ''}" />
                    <input type="hidden" name"RelayState" value="${RelayState || ''}" />
                    <input type="username" name="username" placeholder="Username" required />
                    <input type="password" name="password" placeholder="Password" required />
                    <button type="submit">Sign in</button>
                </form>
                <div style="margin-top: 20px; font-size: 12px; color: #555;">
                    <strong>Demo Accts</strong><br>
                    student1@ofgsstudents.com / password123 <br>
                    admin@ofg.nsw.edu.au / password123 <br>
                    teacher1@ofg.nsw.edu.au / password123
                </div>
            </div>
        </body>
    <html>
`);
});

app.post('/login', async (req, res) => {
    const {username, password, SAMLRequest, RelayState} = req.body;

    try {
        const user = await authenticateUser(username, password);

        if (!user) {
            return res.status(401).send(`
                <h2>Login Failed</h2>
                <p>Invalid username or password</p>
                <a href="/login?SAMLRequest=${SAMLRequest || ''}&RelayState=${RelayState || ''}">Try Again</a>
            `);
        }

        req.session.user = user;
        if (SAMLRequest) {
            return res.redirect(`/sso?SAMLRequest=${SAMLRequest}&RelayState=${RelayState || ''}`);
        }

        res.send(`
            <h2>Login Successful</h2>
            <p>Welcome, ${user.profile.displayName}!</p>
            <a href="/profile">View Profile</a>
        `);
    } catch (error) {
        console.error("Login Error: ". error);
        res.status(500).send(`Login Failed - Logs: \n${error}`)
    }
});

app.get('/sso', (req, res) => {
    if (!req.session.user) {
        const {SAMLRequest, RelayState} = req.query;
        return res.redirect(`/login?SAMLRequest=${SAMLRequest || ''}&RelayState=${RelayState || ''}`);
    }

    const user = req.session.user;
    const destination = `http://localhost:${SP_PORT}/login/callback`;

    let inResponseTo = null;
    if (req.query.SAMLRequest) {
        try {
            const decoded = Buffer.from(req.qurty.SAMLRequest, 'base64');
            const inflated = inflateRawSync(decoded).toString();
            const doc = new DOMParser().parseFromString(inflated);
            const idNode = select("//*[local-name()='AuthnRequest']/@ID", doc);
            if (idNode && idNOde[0]) {
                inResponseTo = idNode[0].value;
            }
        } catch (error) {
            console.warn('Could not parse SAMLRequest: ', error.message);
        }
    }

    const samlResponse = createSAMLResponse(user, inResponseTo, destination);
    const samlResponseBase64 = Buffer.from(samlResponse).toString('base64');

    const form = `
    <!DOCTYPE html>
    <html>
        <head>
            <title>Redirecting...</title>
        </head>    
        <body>
            <form method="POST" action="${destination}" id="samlForm">
                <input type="hidden" name="SAMLResponse" value="${samlResponseBase64}" />
                <input type="hidden" name="RelayState" value="${req.query.RelayState || ''}" />
                <noscript><button type="submit">Continue</button></noscript>
            </form>
            <script>document.getElementById('samlForm').submit();</script>
        </body>
    </html>
    `;
    res.send(form);
});

app.get('/profile', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    const user = req.session.user;
    res.send(`
        <h2>User Profile</h2>
        <p><strong>Name:</strong> ${user.profile.displayName}</p>
        <p><strong>Username:</strong> ${user.username} </p>
        <p><strong>User Type:</strong> ${user.profile.userType} </p>
        <p><strong>Role:</strong> ${user.profile.role === '' ? "None (student)" : user.profile.role} </p>
        <a href="/logout">Log Out</a>
    `);
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.send(`<h2>Logged out successfully</h2><a href="/login">Login Again</a>`);
});

app.get('/adduser', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    const user = req.session.user;

    if (user.profile.userType = "admin") {
        res.send(`
            <!DOCTYPE html>
            <html>
                <head>
                    <title>GearTrack IdP Add User</title> 
                    <style>
                        body {font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; }
                        .login-form { background: #f5f5f5; padding: 30px; border-radius: 8px; }
                        input {width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd}
                        button { background: #007bff; color: white; padding: 12px 20px; border: none; border-radius: 4px; cursor: pointer; width: 100%; }
                        button:hover { background: #0056b3}
                    </style>
                </head>
                <body>
                    <div class="login-form">
                        <h2>Dev Login Portal</h2>
                        <form method="POST" action="/adduser">
                            <input name="firstName" placeholder="First Name" required />
                            <input name="lastName" placeholder="Last Name" required />
                            <input type="password" name="password" placeholder="Password" required />
                            <input name="userType" placeholder="User Type" required />
                            <input name="role" placeholder="Role" />
                            <button type="submit">Add User</button>
                        </form>
                    </div>
                </body>
            <html>
        `);
    }
});

app.post('/adduser', async (req, res) => {
    const {password, firstName, lastName, userType, role} = req.body;

    const data = {
        username: lastName.toLowerCase() + firstName[0].toLowerCase(),
        password: password,
        profile: {
            firstName: firstName,
            lastName: lastName, 
            displayName: firstName + " " + lastName, 
            userType: userType, 
            role: role ? role : '',
            email: lastName.toLowerCase() + firstName[0].toLowerCase() + role == "student" ? "@ofgsstudents.com" : "@ofg.nsw.edu.au"
        }
    }

    try {
        await userU.createUser(dbU.db, data); 
        res.status(200).send(`<h2>Successfully added user: ${data.username}`);
    } catch (error) {
        console.error("AddUser error: ". error);
        res.status(500).send(`Add User failed - Logs: \n${error}`)
    }
});

app.get('/health', (req, res) => {
    res.json({
        status: '[dev] healthy',
        service: 'SAML IdP',
        timestamp: new Date().toISOString()
    });
});

app.use((error, req, res, next) => {
    console.error('IDP Error: ', error);
    res.status(500).json({error: 'IdP Error: ', message: error.message});
});

app.listen(PORT, () => {
    console.log(`Running on http://localhost:${PORT}`);
    console.log(`Metadata on http://localhost:${PORT}/metadata`);
    console.log(`Login on http://localhost:${PORT}/login`);
    console.log(`Profile on http://localhost:${PORT}/profile`);
});