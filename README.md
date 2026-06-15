# (OFG) GearTrack

## Project layout

- `src/` — Express service provider (SP) backend (port `3001`)
- `src/web/` — React/Vite frontend (`@figma/my-make-file`)
- `ofg-geartrack-idp/` — SAML identity provider (IdP) (port `3000`), git submodule
- `certificates/` — SAML signing/encryption certs (see `docs/GEN_CERTS.MD`)
- `db/` — SQLite databases (`sp.db`, `idp.db`)
- `scripts/` — `dev.sh`, `prod.sh`, `gen_certs.sh`, `seed.js`

## First-time setup

Install dependencies for both the backend and the frontend (they are separate
npm projects):

```bash
npm install
npm --prefix src/web install
```

Certificates and the SQLite databases are already checked into the repo. If
you ever need to regenerate certs, see `docs/GEN_CERTS.MD` or run
`sh scripts/gen_certs.sh`. To re-seed the database: `npm run seed`.

## Running it

### Development

```bash
npm run dev
```

Runs `scripts/dev.sh`, which starts:
- the backend in dev mode on http://localhost:3001
- the Vite dev server on http://localhost:5173

### Production-style

```bash
npm run prod
```

Runs `scripts/prod.sh`, which:
1. builds the frontend (`vite build` → `src/web/dist`)
2. starts the backend with `NODE_ENV=production` on http://localhost:3001
3. starts the SAML IdP on http://localhost:3000

Both scripts use `trap ... EXIT` to stop all background processes when you
press Ctrl+C.

## Running under WSL (Windows)

This repo lives on the Windows filesystem (`/mnt/c/...`), and the dev machine
has Node installed on **both** Windows and inside WSL. This causes two
gotchas:

1. **Shell scripts must have LF (Unix) line endings.** If a script was
   saved/edited from a Windows tool, it can pick up CRLF endings, which
   breaks the `#!/usr/bin/env bash` shebang with an error like:
   ```
   /usr/bin/env: 'bash\r': No such file or directory
   ```
   Fix with: `sed -i 's/\r$//' scripts/<script>.sh`

2. **`npm` and `node` can resolve to different installs.** In this
   environment, WSL's PATH includes the Windows Node install
   (`/mnt/c/Program Files/nodejs`), so `npm` may resolve to the Windows
   binary while `node` resolves to the Linux one (or vice versa). If a local
   dependency (e.g. `vite`) is missing, this mismatch can surface as a
   **Windows-style** error even inside WSL:
   ```
   'vite' is not recognized as an internal or external command, operable program or batch file.
   ```
   This almost always means `src/web/node_modules` is missing or out of
   date — re-run `npm --prefix src/web install` to fix it. It is *not* a
   real Windows/Linux compatibility issue.

   Note: `react-router@7` wants Node >= 20, but the WSL Node here is 18.x.
   Install still succeeds (with an `EBADENGINE` warning) and the build runs
   fine.
