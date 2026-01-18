// Simple Express skeleton — extend with Prisma, Mongoose, or Netlify Functions later.
const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors());
app.use(express.json());

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

const port = process.env.PORT || 3001;
app.listen(port, () => console.log(`Backend listening on ${port}`));