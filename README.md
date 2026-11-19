# DRAGON RAKIB URL Shortener

A deployable starter for a URL shortener using Cloudflare Workers + D1.

## Included
- Responsive landing page and user dashboard UI
- Short-link creation and redirect tracking
- Basic account registration/login using email + password
- Admin endpoints (role is stored in D1)
- Click analytics and configurable earning ledger
- D1 schema and setup guide

## Important
This is a starter, not a production-verified earning platform. Earnings are illustrative/configurable and should only be credited after you define and validate a real monetization model. Do not promise payouts until you have a funded revenue source, fraud controls, terms, and payment procedures. Add rate limiting, email verification, CAPTCHA, abuse reporting, and security review before public launch.

## Deploy free (Cloudflare)
1. Create a Cloudflare account: https://dash.cloudflare.com/
2. Install Node.js LTS and Wrangler:
   `npm install -g wrangler`
3. Login:
   `wrangler login`
4. Create a D1 database:
   `wrangler d1 create dragon-rakib-db`
5. Copy the returned database_id into `wrangler.toml`.
6. Initialize database:
   `wrangler d1 execute dragon-rakib-db --file=./schema.sql`
7. Set a strong secret:
   `wrangler secret put JWT_SECRET`
8. Deploy:
   `wrangler deploy`

Cloudflare's free limits and product terms can change. Check current limits before launch.

## Make yourself admin
After registering your account, run:
`wrangler d1 execute dragon-rakib-db --command "UPDATE users SET role='admin' WHERE email='YOUR_EMAIL';"`

## Local development
`npm install`
`npm run dev`

## Environment
Set `JWT_SECRET` as a Worker secret. Never put it in frontend code.
