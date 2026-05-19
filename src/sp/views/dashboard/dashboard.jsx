import React from 'react';

const KNOWN_FIELDS = [
    { key: 'issuer', label: 'Issuer' },
    { key: 'nameID', label: 'NameID' },
    { key: 'nameIDFormat', label: 'NameID Format' },
    { key: 'sessionIndex', label: 'Session Index' },
    { key: 'inResponseTo', label: 'In Response To' },
    { key: 'spNameQualifier', label: 'SP Name Qualifier' },
    { key: 'nameQualifier', label: 'Name Qualifier' },
    { key: 'email', label: 'Email' },
    { key: 'displayName', label: 'Display Name' },
    { key: 'givenName', label: 'Given Name' },
    { key: 'surname', label: 'Surname' },
    { key: 'uid', label: 'UID' },
    { key: 'role', label: 'Role' }
];
const css = `
`

function formatValue(value) {
    if (value === null || value === undefined || value === '') return 'Not provided';
    if (Array.isArray(value)) return value.join(', ');
    if (typeof value === 'object') {
        try {
            return JSON.stringify(value, null, 2);
        } catch (error) {
            return '[Unserializable object]';
        }
    }
    if (typeof value === 'function') return '[Function]';
    return String(value);
}

function safeStringify(value) {
    try {
        return JSON.stringify(value, (key, val) => (typeof val === 'function' ? '[Function]' : val), 2);
    } catch (error) {
        return '[Unserializable object]';
    }
}

function getObjectEntries(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return [];
    return Object.keys(value)
        .sort()
        .map((key) => ({ key, value: value[key] }));
}

export default function Dashboard({ user }) {
    const profile = user || {};
    const displayName = profile.displayName || profile.nameID || profile.name || 'User';
    const attributes = profile.attributes || profile.attribute || {};
    const attributeEntries = getObjectEntries(attributes);
    const allEntries = getObjectEntries(profile);

    return (
        <html>
            <head>
                <meta charSet="utf-8" />
                <title>SP Dashboard</title>
                
                <link rel="stylesheet" href="/dashboard/styles.css" />
            </head>
            <body>
                <div className="page">
                    <div className="hero">
                        <div>
                            <div className="badge">SAML Session Active</div>
                            <h1 className="title">Welcome back, {displayName}</h1>
                            <p className="subtitle">Every field we can detect from the SAML response is laid out below for quick inspection.</p>
                        </div>
                        <div className="card">
                            <h2>Session Snapshot</h2>
                            <div className="pill">Login succeeded</div>
                            <table className="table">
                                <tbody>
                                    <tr>
                                        <td className="label">Issuer</td>
                                        <td className="value">{formatValue(profile.issuer)}</td>
                                    </tr>
                                    <tr>
                                        <td className="label">NameID</td>
                                        <td className="value">{formatValue(profile.nameID)}</td>
                                    </tr>
                                    <tr>
                                        <td className="label">Session Index</td>
                                        <td className="value">{formatValue(profile.sessionIndex)}</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <div className="grid">
                        <div className="card">
                            <h2>Known Fields</h2>
                            <table className="table">
                                <tbody>
                                    {KNOWN_FIELDS.map((field) => (
                                        <tr key={field.key}>
                                            <td className="label">{field.label}</td>
                                            <td className="value">{formatValue(profile[field.key])}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>

                        <div className="card">
                            <h2>Attributes</h2>
                            {attributeEntries.length ? (
                                <table className="table">
                                    <tbody>
                                        {attributeEntries.map((entry) => (
                                            <tr key={entry.key}>
                                                <td className="label">{entry.key}</td>
                                                <td className="value">{formatValue(entry.value)}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            ) : (
                                <div className="empty">No attribute bundle detected in this response.</div>
                            )}
                        </div>

                        <div className="card">
                            <h2>All Fields</h2>
                            {allEntries.length ? (
                                <table className="table">
                                    <tbody>
                                        {allEntries.map((entry) => (
                                            <tr key={entry.key}>
                                                <td className="label">{entry.key}</td>
                                                <td className="value">{formatValue(entry.value)}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            ) : (
                                <div className="empty">No profile data was attached to this session.</div>
                            )}
                        </div>

                        <div className="card">
                            <h2>Raw JSON</h2>
                            <pre className="json">{safeStringify(profile)}</pre>
                        </div>
                    </div>
                </div>
            </body>
        </html>
    );
}