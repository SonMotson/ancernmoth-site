# Ancernmoth Site (root)

This repository contains both:
- A marketing/static site (root)
- The AncernmothApp single-page application (AncernmothApp/)

Deployment (Netlify):
- Site (marketing/static): create a Netlify site with base directory set to the root (or a specific site folder) and publish directory pointing to the folder with index.html.
- App (SPA): create a second Netlify site (or a different site) with base directory: AncernmothApp, build command: `npm ci && npm run build`, publish directory: `build`.
- Add required environment variables in Netlify site settings (see AncernmothApp/README.md).

Database options included (examples):
- Supabase (recommended) — client integration prepared at src/lib/supabaseClient.js
- Firebase / Firestore — example at src/lib/firebaseClient.js
- Dexie (IndexedDB) — client-side offline DB at src/lib/localDb.js
- A minimal backend skeleton is included in backend/ for future Prisma/MongoDB work.

Next steps:
- Provide Supabase project credentials and add them to Netlify site env variables, or set up Firebase or other services as needed.