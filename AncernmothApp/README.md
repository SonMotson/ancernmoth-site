# AncernmothApp (React + CRA + Tailwind)

Quick local development:
1. cd AncernmothApp
2. npm install
3. npm start

Build:
- npm run build (creates build/ folder)

Netlify deployment (recommended):
- Create a new Netlify site, connect to this repo
- Base directory: AncernmothApp
- Build command: npm ci && npm run build
- Publish directory: build
- Add env vars in Netlify:
  - REACT_APP_SUPABASE_URL
  - REACT_APP_SUPABASE_ANON_KEY
  - (Optional) FIREBASE keys if using Firebase
Notes:
- Do NOT commit secrets. Use Netlify Site Settings -> Build & deploy -> Environment.
- The repo contains example clients for Supabase, Firebase, and Dexie (IndexedDB).