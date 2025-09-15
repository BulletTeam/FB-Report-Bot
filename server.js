const express = require('express');
const { chromium } = require('playwright');

const app = express();
const PORT = process.env.PORT || 3000;

app.get('/', (req, res) => res.send('Playwright server running ✅'));

app.get('/test', async (req, res) => {
  const browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
  const context = await browser.newContext();
  const page = await context.newPage();

  await page.goto('https://example.com');
  const title = await page.title();

  await browser.close();
  res.send({ title });
});

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
