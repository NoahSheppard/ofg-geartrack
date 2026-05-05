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
                <style>{`
                    @import url('https://fonts.googleapis.com/css2?family=Libre+Baskerville:wght@400;700&family=Space+Grotesk:wght@400;600&display=swap');

                    :root {
                        --ink: #1b1b1b;
                        --muted: #6b6b6b;
                        --accent: #c56b2f;
                        --accent-2: #2d6f8e;
                        --bg: #f6f1e9;
                        --card: #fffaf2;
                        --line: #e6ddcf;
                        --shadow: 0 18px 40px rgba(36, 32, 28, 0.12);
                    }

                    * { box-sizing: border-box; }

                    body {
                        margin: 0;
                        font-family: "Space Grotesk", "Trebuchet MS", sans-serif;
                        color: var(--ink);
                        background: radial-gradient(circle at top left, #f3ddc8 0%, #f6f1e9 55%, #e3f2f2 100%);
                        min-height: 100vh;
                    }

                    .page {
                        max-width: 1120px;
                        margin: 0 auto;
                        padding: 48px 24px 80px;
                    }

                    .hero {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
                        gap: 24px;
                        align-items: center;
                        margin-bottom: 32px;
                    }

                    .title {
                        font-family: "Libre Baskerville", "Times New Roman", serif;
                        font-size: 40px;
                        line-height: 1.1;
                        margin: 0 0 12px;
                    }

                    .subtitle {
                        color: var(--muted);
                        margin: 0;
                        font-size: 16px;
                    }

                    .badge {
                        display: inline-flex;
                        align-items: center;
                        gap: 10px;
                        padding: 10px 16px;
                        background: #0f2f3a;
                        color: #f8f2e7;
                        border-radius: 999px;
                        font-size: 13px;
                        letter-spacing: 0.08em;
                        text-transform: uppercase;
                    }

                    .grid {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                        gap: 24px;
                    }

                    .card {
                        background: var(--card);
                        border: 1px solid var(--line);
                        border-radius: 20px;
                        padding: 24px;
                        box-shadow: var(--shadow);
                    }

                    .card h2 {
                        margin: 0 0 16px;
                        font-size: 18px;
                        text-transform: uppercase;
                        letter-spacing: 0.12em;
                        color: var(--accent-2);
                    }

                    .table {
                        width: 100%;
                        border-collapse: collapse;
                        font-size: 14px;
                    }

                    .table tr + tr td {
                        border-top: 1px solid var(--line);
                    }

                    .table td {
                        padding: 10px 0;
                        vertical-align: top;
                    }

                    .label {
                        color: var(--muted);
                        text-transform: uppercase;
                        letter-spacing: 0.08em;
                        font-size: 11px;
                        width: 38%;
                        padding-right: 12px;
                    }

                    .value {
                        color: var(--ink);
                        white-space: pre-wrap;
                        word-break: break-word;
                        font-family: "Space Grotesk", "Trebuchet MS", sans-serif;
                    }

                    .pill {
                        display: inline-flex;
                        align-items: center;
                        gap: 8px;
                        background: rgba(197, 107, 47, 0.12);
                        color: var(--accent);
                        padding: 6px 12px;
                        border-radius: 999px;
                        font-size: 12px;
                        font-weight: 600;
                    }

                    .json {
                        background: #11110f;
                        color: #f4efe8;
                        padding: 18px;
                        border-radius: 16px;
                        font-size: 12px;
                        overflow: auto;
                        max-height: 360px;
                    }

                    .empty {
                        color: var(--muted);
                        font-style: italic;
                    }

                    @media (max-width: 720px) {
                        .page { padding: 32px 18px 56px; }
                        .title { font-size: 32px; }
                    }
                `}</style>
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