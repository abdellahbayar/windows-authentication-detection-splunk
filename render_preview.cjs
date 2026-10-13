const fs = require('fs');
const path = require('path');
const http = require('http');
const {chromium} = require('playwright');

(async () => {
  const root = __dirname;
  const template = fs.readFileSync(path.join(root, 'preview/template.html'), 'utf8');
  const payload = fs.readFileSync(path.join(root, 'preview/payload.json'), 'utf8');
  const index = path.join(root, 'preview/index.html');
  fs.writeFileSync(index, template.replace('__PAYLOAD__', payload));
  const server = http.createServer((req, res) => { res.setHeader('Content-Type','text/html; charset=utf-8'); res.end(fs.readFileSync(index)); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const url = 'http://127.0.0.1:' + server.address().port + '/';
  const browser = await chromium.launch({headless: true, executablePath: 'C:/Program Files/Google/Chrome/Application/chrome.exe'});
  const page = await browser.newPage({viewport: {width: 1600, height: 600}, deviceScaleFactor: 1, acceptDownloads: true});
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  for (const view of ['architecture','install','ingestion','events','detection','dashboard','validation','alert','triage']) {
    await page.goto(url + '?view=' + view);
    await page.screenshot({path: path.join(root, 'screenshots', view + '.png'), fullPage: true});
  }
  await page.goto(url + '?view=events');
  await page.locator('#filter').fill('UtenteInesistente');
  if (await page.locator('#event-table tbody tr').count() !== 5) throw new Error('Filter returned wrong count');
  const downloadWait = page.waitForEvent('download');
  await page.getByRole('button', {name: 'Download synthetic CSV'}).click();
  const download = await downloadWait;
  await download.saveAs(path.join(root, 'preview/export-check.csv'));
  await page.setViewportSize({width: 390, height: 844});
  await page.goto(url + '?view=dashboard');
  await page.screenshot({path: path.join(root, 'screenshots', 'dashboard-mobile.png'), fullPage: true});
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > innerWidth);
  if (errors.length) throw new Error(errors.join('\n'));
  await browser.close();
  await new Promise(resolve => server.close(resolve));
  fs.writeFileSync(path.join(root, 'preview/verification.json'), JSON.stringify({pageErrors:errors,filter:'PASS',csvDownload:'PASS',mobileOverflow:overflow,scope:'Local demonstrator, not Splunk'}, null, 2));
  console.log(JSON.stringify({screenshots:10,filter:'PASS',csvDownload:'PASS',mobileOverflow:overflow}));
})().catch(err => {console.error(err);process.exit(1);});
