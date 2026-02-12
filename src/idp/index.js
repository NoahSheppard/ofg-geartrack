const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const zlib = require('zlib');
const xmlbuilder = require('xmlbuilder');
const xmldom = require('xmldom');
const xpath = require('xpath')

const app = express();
const PORT = process.env.IDP_PORT || 3000;
const SP_PORT = process.env.SP_PORT || 3001;

const PROD = false;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
    secret: 'secret-to-change-in-prod',
    resave: false,
    saveUninitialized: false, 
    cookie: { secure: false } // FIXED: was 'cookies'
}));

// replace with db instance later
const users = [
    {
        id: 0, 
        email: 'student1@ofgsstudents.com',
        password: bcrypt.hashSync('password123', 10),
        profile: {
            displayName: 'Student One',
            firstName: 'Student',
            lastName: 'One',
            userType: 'student',
            role: ''
        }
    },
    {
        id: 1, 
        email: 'admin@ofg.nsw.edu.au',
        password: bcrypt.hashSync('password123', 10),
        profile: {
            displayName: 'Admin One',
            firstName: 'Admin',
            lastName: 'One',
            userType: 'admin',
            role: 'Systems Administrator'
        }
    },
    {
        id: 2, 
        email: 'teacher1@ofg.nsw.edu.au',
        password: bcrypt.hashSync('password123', 10),
        profile: {
            displayName: 'Teacher One',
            firstName: 'Teacher',
            lastName: 'One',
            userType: 'teacher',
            role: 'Music Teacher'
        }
    }
]

let idpSigningKey, idpSigningCert;
try {
    idpSigningKey = fs.readFileSync(path.join(__dirname, '../../certificates/idp-signing.key'), 'utf-8');
    idpSigningCert = fs.readFileSync(path.join(__dirname, '../../certificates/idp-signing.cert'), 'utf-8');
} catch {
    console.error('Certificates not found, running without signing - WILL NOT WORK IN PROD');
};

const findUserByEmail = (email) => users.find(u => u.email === email);
const authenticateUser = async (email, password) => {
    const user = findUserByEmail(email);
    if (!user) return null;

    const isValid = await bcrypt.compare(password, user.password);
    return isValid ? user : null;
};

function createSAMLResponse(user, inResponseTo, destination) {
    const issueInstant = new Date().toISOString();
    const notBefore = new Date(Date.now() - 5000).toISOString();
    const notOnOrAfter = new Date(Date.now() + 300000).toISOString();
    const sessionIndex = '_'  = crypto.randomBytes(16).toString('hex');
    const assertionID = '_' + crypto.randomBytes(16).toString('hex');
    const responseID = '_' + crypto.randomBytes(16).toString('hex');

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
        .att('Format', 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress')
        .txt(user.email);
    
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
        'email': user.email,
        'displayName': user.profile.displayName,
        'firstName': user.profile.firstName,
        'lastName': user.profile.lastName,
        'userType': user.profile.userType,
        'role': user.profile.role
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