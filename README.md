# Zeabur Monitor - Cloudflare Workers + D1

This folder contains a Cloudflare Workers version of the service with D1 storage.

## Files

- `src/worker.js`: Workers implementation (API + static assets)
- `public/`: frontend assets copied from the root `public` folder
- `schema.sql`: D1 schema
- `wrangler.toml`: Workers config

## Setup

1. Install Wrangler (if needed):
   ```bash
   npm install -g wrangler
   ```

2. Create a D1 database and update `wrangler.toml`:
   ```bash
   wrangler d1 create zeabur_monitor
   ```

   Replace `YOUR_D1_DATABASE_ID` in `wrangler.toml` with the returned id.

3. Apply schema:
   ```bash
   wrangler d1 execute zeabur_monitor --file schema.sql
   ```

4. Configure secrets:
   - `ACCOUNTS_SECRET`: 64 hex chars for AES-GCM token encryption (recommended)
   - `ACCOUNTS`: optional preset accounts: `name:token,name2:token2`

   Example:
   ```bash
   wrangler secret put ACCOUNTS_SECRET
   wrangler secret put ACCOUNTS
   ```

5. Run locally:
   ```bash
   wrangler dev
   ```

6. Deploy:
   ```bash
   wrangler deploy
   ```

## README Note

This Workers-only deployment guide lives in `workers_version/README.md`. The root `README.md` is unchanged by design.

## Notes

- Session data is stored in D1 (`sessions` table) with a 10-day TTL.
- Admin password is stored in D1 (`admin_password` table).
- Accounts are stored in D1 (`accounts` table) and encrypted when `ACCOUNTS_SECRET` is set.
