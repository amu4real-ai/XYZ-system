# XYZ Collection – Inventory & Sales (Node.js + SQLite)

Self-hosted version of the inventory/sales system with a real backend:
server-side login (scrypt-hashed passwords, httpOnly session cookie), role enforcement
(Manager vs Sales), stock checks done on the server, and all data in one SQLite file.

## Run
    npm install
    npm start            # http://localhost:3000

On first visit the page asks you to create the **Manager** account.
Then register salespeople under **Team**.

## Settings (environment variables)
| Variable | Default | Purpose |
|---|---|---|
| PORT | 3000 | HTTP port |
| DB_FILE | ./data.db | SQLite database file (back this up) |
| TZ_NAME | Africa/Dar_es_Salaam | Time zone for "today" and daily reports |
| COOKIE_SECURE | off | Set to 1 when served over HTTPS |

## Going live
- Put it behind HTTPS (Caddy or nginx reverse proxy to port 3000) and set COOKIE_SECURE=1.
- Keep it running with pm2 (`pm2 start server.js --name xyz`) or a systemd service.
- Back up `data.db` (and `data.db-wal`) regularly, e.g. a nightly copy.
- Requires Node 18+.

## Files
- `server.js` – API, authentication, business rules, static hosting
- `public/index.html` – the web app (mobile friendly)
- `package.json` – dependency: better-sqlite3

## What the server enforces
- Salespeople only receive For Sale items (no costs or suppliers) and their own sales.
- Sales are validated server-side: item must be For Sale with a price, units cannot exceed stock,
  no sales after the daily report is submitted; the price always comes from the item.
- Selling price can never be below production price.
- Edit requests, roll-backs, resubmissions, daily reports and manager actions go to the audit log.
