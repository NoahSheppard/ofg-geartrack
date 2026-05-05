import React from 'react';

export default function DevProfile({ user }) {
    const profile = user?.profile || {};

    return (
        <html>
            <head>
                <style>{`
                    body {
                        font-family: Arial, sans-serif;
                        margin: 20px;
                        background-color: #f0f0f0;
                    }
                    h1 {
                        color: #333;
                    }
                    p {
                        font-size: 18px;
                        color: #555;
                    }
                    a {
                        display: inline-block;
                        margin-top: 20px;
                        padding: 10px 15px;
                        background-color: #007BFF;
                        color: white;
                        text-decoration: none;
                        border-radius: 5px;
                    }
                    a:hover {
                        background-color: #0056b3;
                    }
                `}</style>
                <title>IdP Profile Site</title>
            </head>
            <body>
                <h1>IdP User Profile</h1>
                <p><strong>Name:</strong> {profile.displayName || user?.name || 'Unknown'}</p>
                <p><strong>Email:</strong> {profile.email || user?.email || 'Unknown'}</p>
                <p><strong>Username:</strong> {user?.username || 'Unknown'}</p>
                <p><strong>Groups:</strong> {Array.isArray(user?.groups) ? user.groups.join(', ') : 'None'}</p>
                <p><strong>User Type:</strong> {profile.userType || user?.userType || 'Unknown'}</p>
                <p><strong>Role:</strong> {profile.role || user?.role || 'None'}</p>
                <a href="/logout">Log Out</a>
            </body>
        </html>
    );
}