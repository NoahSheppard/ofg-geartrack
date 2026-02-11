const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const SAMLHelper = require ('saml-sso-helper');

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
    secret: 'secret-to-change-in-prod',
    resave: false,
    saveUninitialized: false, 
    cookies: { secure: false } // change in prod
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

const samlHelper = new SAMLHelper({
    encryption: true, 
    entityID: 'https://geartrack.ofg.nsw.edu.au/idp/metadata',
    baseURL: 'https://geartrack.ofg.nsw.edu.au',
    partnerMetadataURL: 'https://geartrack.ofg.nsw.edu.au/sp/metadata',
    certificates: {
        signing: {
            key: path.join(__dirname, '../../certificates/idp-signing.key'),
            cert: path.join(__dirname, '../../certificates/idp-signing.cert')
        },
        encryption: {
            key: path.join(__dirname, '../../certificates/idp-encrypt.key'),
            cert: path.join(__dirname, '../../certificates/idp-encrypt.cert')
        }
    },
    attributes: [
        'email',
        'displayName',
        'firstName',
        'lastName',
        'userType',
        'role'
    ]
})

samlHelper.createIdentityProvider();
const middleware = samlHelper.getExpressMiddleware();

const findUserByEmail = (email) => users.find(u => u.email === email);
const authenticateUser = async (email, password) => {
    const user = findUserByEmail(email);
    if (!user) return null;

    const isValid = await bcrypt.compare(password, user.password);
    return isValid ? user : null;
};

app.get('/metadata', middleware.idp.metadata);

app.get('/login', (req, res) => {
    const {SAMLRequest, RelayState}  = req.query;

    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>GearTrack Test Login - SAML IdP</title>
            <style>
                body {font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto; padding: 20px;}
                .login-form { background: #f5f5f5; padding: 30px; border-radius: 8px; }
                input { width: 100%; padding: 10px; margin:  10px 0; border: 1px solid #ddd; }
                button { background: #007bff; color: white; padding: 12px 20px; border: none; border-radius: 4px; cursor: pointer; width: 100%; }
                button:hover { background: #0056b3; }
                .error { color: red; margin: 10px 0; }
            </style>
        </head>
        <body>
            <div class="login-form">
                <h2>Dev Login Portal</h2>
                <form method="POST" action="/login">
                    <input type="hidden" name="SAMLRequest" value="${SAMLRequest || ''}" />
                    <input type="hidden" name="RelayState" value="${RelayState || ''}" />

                    <input type="email" name="email" placeholder="Email Address" required />
                    <input type="password" name="password" placeholder="Password" required/>
                    
                    <button type="submit>Sign In</button> 
                </form>

                <div style="margin-top: 20px; font-size: 12px; color: #666;">
                    <strong>Demo Accounts:</strong><br>
                    student@ofgsstudents.com / password123 <br>
                    admin@ofg.nsw.edu.au / password123 <br>
                    teacher1@ofg.nsw.edu.au / password123
                </div>
            </div>
        </body>
        </html>
    `)
})

app.post('/login', async (req, res) => {
    const {email, password, SAMLRequest, RelayState } = req.body;

    try {
        const user = await authenticateUser(email, password);

        if (!user) {
            return res.status(401).send(`
                <h2>Login Failed</h2>
                <p>Invalid email or password.</p>
                <a href="/login?SAMLRequest=${SAMLRequest}&RelayState=${RelayState}">Try Again</a>
            `);
        }

        req.session.user = user;

        if (SAMLRequest) {
            req.query.SAMLRequest = SAMLRequest;
            req.query.RelayState = RelayState;
            return app._router.handle({...req, method: 'GET', url: '/sso'}, res);
        }

        res.send(`
            <h2>Login Successful</h2>
            <p>Welcome, ${user.profile.displayName}!</p>
            <a href="/profile">View Profile</a>
        `);
    } catch (error) {
        console.error("Login Error: ", error);
        res.status(500).send("Login Failed, server issues?");
    }
});

app.get('/sso', (req, res) => {
    if (!req.session.user) {
        const {SAMLRequest, RelayState } = req.query;
        return res.redirect(`/login?SAMLRequest=${SAMLRequest}&RelayState=${RelayState}`);
    }

    const user = req.session.user;
    req.userData = {
        email: user.email,
        displayName: user.profile.displayName,
        firstName: user.profile.firstName,
        lastName: user.profile.lastName,
        userType: user.profile.userType,
        role: user.profile.role
    };

    middleware.idp.sso(req, res);
});

app.get('/profile', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    const user = req.session.user;
    res.semd(`
        <h2>User Profile</h2>
        <p><strong>Name:</strong> ${user.profile.displayName}</p>
        <p><strong>Email:</strong> ${user.email}</p>
        <p><strong>User Type:</strong> ${user.profile.userType}</p>
        <p><strong>Role:</strong> ${user.profile.role === '' ? "None (Student)" : user.profile.role}</p>
        <a href="/logout">Log Out</a>
    `);
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.send('<h2>Logged out successfully!</h2><a href="/login">Login Again</a>');
});

app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        service: 'SAML Identity Provider',
        encryption: samlHelper.config.encryption,
        timestamp: new Date().toISOString()
    });
});

app.use((error, req, res, next) => {
    console.error("IdP Error: ", error);
    res.status(500).json({
        error: 'IdP Error',
        message: error.message
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Running on http://localhost:${PORT}`);
    console.log(`Metadata: http://localhost:${PORT}/metadata`);
    console.log(`Login: http://localhost:${PORT}/login`);
    console.log(`Profile: http://localhost:${PORT}/profile`);
});