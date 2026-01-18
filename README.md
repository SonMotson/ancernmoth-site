# Ancernmoth Demo Branch

This branch (ancernmoth-netlify-demo) contains a self-contained demo HTML file (ancernmoth-demo.html) and Netlify configuration so you can preview the site on Netlify.

What I pushed
- ancernmoth-demo.html — self-contained demo (static HTML/CSS/JS)
- netlify.toml — Netlify headers and publish settings (publishes repo root)
- _redirects — SPA redirect so all routes serve the demo

How to get a Netlify preview
1. In Netlify: Sites → Add new site → Import from Git → connect your GitHub account and select this repository.
2. Choose the branch `ancernmoth-netlify-demo` when creating the site (build command left empty, publish directory set to `.`).
3. Netlify will create a draft deploy and provide a preview URL. TLS is provided automatically.

Note
- The demo uses placeholders for phone/email/payment. Replace them in ancernmoth-demo.html if needed.

