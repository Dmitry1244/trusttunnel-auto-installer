const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const {spawn} = require('node:child_process');
const path = require('node:path');
const assert = require('node:assert/strict');

(async () => {
  const port = '18093';
  const root = path.resolve(__dirname, '..');
  const preview = spawn(process.env.PYTHON || 'python', [path.join(__dirname, 'preview_panel.py')], {
    cwd: root, env: {...process.env, TT_PREVIEW_PORT: port}, stdio: ['ignore', 'ignore', 'pipe']
  });
  let serverErrors = '';
  preview.stderr.on('data', chunk => serverErrors += chunk.toString());
  const browser = await chromium.launch({headless: true, channel: 'msedge'});
  try {
    const base = 'http://127.0.0.1:' + port;
    for (let i = 0; i < 60; i++) {
      try { if ((await fetch(base + '/health')).ok) break; } catch {}
      await new Promise(resolve => setTimeout(resolve, 100));
      if (i === 59) throw Error('Preview failed: ' + serverErrors);
    }
    for (const width of [320, 390, 768, 1440]) {
      const page = await browser.newPage({viewport: {width, height: 1000}});
      const posts = [], errors = [];
      page.on('pageerror', e => errors.push(e.message));
      page.on('request', request => {if (request.method() === 'POST') posts.push(new URLSearchParams(request.postData()));});
      await page.goto(base + '/?view=security');
      assert.equal(await page.locator('#ufw-controls tbody tr').count(), 5);
      const form = page.locator('form').filter({has: page.locator('input[name="action"][value="ufw-rule"]')});
      await form.locator('..').locator('summary').first().click();
      await form.locator('[name="port"]').fill('9000:9010');
      await form.locator('[name="source"]').fill('192.0.2.0/24');
      await form.getByRole('button', {name: 'Применить правило', exact: true}).click();
      await page.locator('#action-confirm[open]').waitFor();
      await page.locator('#confirm-cancel').click();
      assert.equal(posts.length, 0);
      await form.getByRole('button', {name: 'Применить правило', exact: true}).click();
      await page.locator('#confirm-accept').click();
      await page.locator('#operation-result[open]').waitFor();
      assert.equal(posts.at(-1).get('action'), 'ufw-rule');
      assert.equal(posts.at(-1).get('confirm'), 'CONFIRMED');
      assert.equal(posts.at(-1).get('port'), '9000:9010');
      assert.equal(posts.at(-1).getAll('_csrf').length, 1);
      await page.locator('#result-close').click();
      const settings = page.locator('form').filter({has: page.locator('input[name="action"][value="f2b-settings"]')});
      await settings.locator('..').locator('summary').click();
      await settings.locator('[name="jail"]').selectOption('nginx-http-auth');
      await settings.locator('[name="retry"]').fill('7');
      await settings.getByRole('button', {name: 'Сохранить параметры'}).click();
      await page.locator('#action-confirm[open]').waitFor();
      await page.locator('#confirm-accept').click();
      await page.locator('#operation-result[open]').waitFor();
      assert.equal(posts.at(-1).get('jail'), 'nginx-http-auth');
      assert.equal(posts.at(-1).get('retry'), '7');
      await page.locator('#result-close').click();
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1), false);
      assert.deepEqual(errors, []);
      await page.screenshot({path: path.join(__dirname, `security-admin-${width}.png`), fullPage: true});
      await page.close();
    }
    assert.equal(serverErrors, '');
    console.log('Security UI: UFW form, cancel/confirm, CIDR/range, CSRF, jail selection and responsive 320/390/768/1440: PASS');
  } finally {
    await browser.close();
    preview.kill();
    await new Promise(resolve => preview.once('exit', resolve));
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
