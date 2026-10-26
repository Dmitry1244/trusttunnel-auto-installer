const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const {spawn} = require('node:child_process');
const path = require('node:path');
const assert = require('node:assert/strict');

(async () => {
  const root = path.resolve(__dirname, '..');
  const port = '18095';
  const preview = spawn(process.env.PYTHON || 'python', [path.join(__dirname, 'preview_panel.py')], {
    cwd: root, env: {...process.env, TT_PREVIEW_PORT: port}, stdio: ['ignore', 'ignore', 'pipe']
  });
  let stderr = '';
  preview.stderr.on('data', chunk => stderr += chunk.toString());
  let browser;
  try {
    browser = await chromium.launch({headless: true, channel: 'msedge'});
    const base = 'http://127.0.0.1:' + port;
    for (let i = 0; i < 60; i++) {
      try {if ((await fetch(base + '/health')).ok) break;} catch {}
      if (i === 59) throw Error('Preview failed: ' + stderr);
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    for (const width of [320, 390, 768, 1440]) {
      const page = await browser.newPage({viewport: {width, height: 1000}});
      const posts = [], errors = [];
      page.on('pageerror', e => errors.push(e.message));
      page.on('request', r => {if (r.method() === 'POST') posts.push(new URLSearchParams(r.postData()));});
      await page.goto(base + '/?view=clients');
      const row = page.locator('tr[data-client-row]').filter({has: page.locator('[data-client-online="client01"]')});
      await row.getByRole('button', {name: 'Управлять'}).click();
      const drawer = page.locator('aside.drawer.open');
      await drawer.waitFor();
      assert.equal(await drawer.locator('input[value="guard-restrict"]').count(), 0);
      const watch = drawer.locator('form').filter({has: page.locator('input[value="guard-watch-save"]')});
      await watch.locator('..').locator('summary').click();
      await page.waitForFunction(() => document.querySelector('[data-client-watch="client01"]').textContent.includes('5 сетей'));
      assert.match(await drawer.locator('[data-client-watch]').textContent(), /не одновременные IP/);
      await watch.locator('[name="threshold"]').fill('6');
      await watch.getByRole('button', {name:'Включить наблюдение сетей'}).click();
      await page.locator('#action-confirm[open]').waitFor();
      await page.locator('#confirm-cancel').click();
      assert.equal(posts.length,0);
      await watch.getByRole('button', {name:'Включить наблюдение сетей'}).click();
      await page.locator('#confirm-accept').click();
      await page.locator('#operation-result[open]').waitFor();
      assert.equal(posts.at(-1).get('action'),'guard-watch-save');
      assert.equal(posts.at(-1).get('threshold'),'6');
      assert.equal(posts.at(-1).getAll('_csrf').length,1);
      await page.locator('#result-close').click();
      await page.screenshot({path:path.join(__dirname, `access-watch-${width}.png`),fullPage:true});
      await drawer.locator('[data-drawer-close]').click();
      await row.getByRole('button', {name:'Управлять'}).click();
      const invite = drawer.locator('form').filter({has:page.locator('input[value="enrollment-issue"]')});
      await invite.locator('..').locator('summary').click();
      await invite.locator('[name="source_cidr"]').fill('192.0.2.7/32');
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth+1),false);
      await page.goto(base + '/?view=routing');
      const torrent = page.locator('#torrent-controls');
      await torrent.waitFor();
      assert.match(await torrent.textContent(), /MSE\/PE/);
      const filter = torrent.locator('form').filter({has:page.locator('input[value="torrent-save"]')});
      await filter.locator('[name="mode"]').selectOption('ports');
      await filter.locator('[name="limits_ack"]').check();
      await filter.getByRole('button',{name:'Применить ограничение'}).click();
      await page.locator('#action-confirm[open]').waitFor();
      await page.locator('#confirm-accept').click();
      await page.locator('#operation-result[open]').waitFor();
      assert.equal(posts.at(-1).get('action'),'torrent-save');
      assert.equal(posts.at(-1).get('confirm'),'CONFIRMED');
      assert.equal(posts.at(-1).get('limits_ack'),'1');
      await page.locator('#result-close').click();
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth+1),false);
      assert.deepEqual(errors,[]);
      await page.screenshot({path:path.join(__dirname,`torrent-controls-${width}.png`),fullPage:true});
      await page.close();
    }
    assert.equal(stderr,'');
    console.log('Synthetic access/torrent UI: watch report, no transport preset, source-CIDR, cancel/confirm, CSRF; 320/390/768/1440: PASS');
  } finally {
    await browser?.close();
    if (preview.exitCode === null && preview.signalCode === null) {
      const exit = new Promise(resolve => preview.once('exit',resolve));
      preview.kill(); await exit;
    }
  }
})().catch(error => {console.error(error); process.exitCode=1;});
