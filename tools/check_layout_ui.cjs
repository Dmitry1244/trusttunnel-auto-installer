// Synthetic only. --css explicitly opts into a local, unpublished CSS suggestion.
// PLAYWRIGHT_MODULE, TT_UI_DEPS and PYTHON follow check_panel_ui.cjs.
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const {spawn} = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {createHash} = require('node:crypto');

const root = path.resolve(__dirname, '..');
const source = path.join(root, 'trusttunnel-panel.py');
const digest = () => createHash('sha256').update(fs.readFileSync(source)).digest('hex');
const widths = [320, 390, 560, 768, 1024, 1440];
const scenarios = widths.flatMap(width => [
  {width, height: 1000, name: `${width}-normal`, font: 1, zoom: 1},
  {width, height: 1000, name: `${width}-text150`, font: 1.5, zoom: 1}
]);
// Browser-zoom-equivalent reflow, not pinch zoom or a devicePixelRatio-only test.
for (const width of [768, 1024, 1440]) {
  for (const factor of [1.25, 2]) scenarios.push({width: Math.floor(width / factor), height: 800,
    name: `${width}-reflow${factor * 100}`, font: 1, zoom: 1});
}
const selectedScenario = process.argv.find(arg => arg.startsWith('--scenario='))?.slice('--scenario='.length);
if (selectedScenario) {
  const selected = scenarios.filter(item => item.name === selectedScenario);
  assert.equal(selected.length, 1, 'Unknown layout scenario');
  scenarios.splice(0, scenarios.length, ...selected);
}

const bootstrap = String.raw`
import http.server, json, os, pathlib, runpy, sys
sys.path.insert(0, os.path.dirname(sys.argv[1]))
from test_admin import panel
fixture = pathlib.Path(os.environ['TT_LAYOUT_FIXTURE_ROOT'])
for name, value in list(vars(panel).items()):
    if isinstance(value, pathlib.Path):
        setattr(panel, name, fixture / name)
panel.run = lambda *args, **kwargs: (0, 'synthetic preview: no commands')
panel.protection_state = lambda: {}
panel.torrent_state = lambda: {'enabled': False}
panel.release_snapshot = lambda: {'installed': 'fixture', 'stable': {'tag_name': 'fixture'}, 'beta': {}, 'update_available': False}
def no_network(*args, **kwargs):
    raise OSError('Outbound requests disabled in synthetic layout preview')
panel.urllib.request.urlopen = no_network
if os.environ.get('TT_LAYOUT_CSS'):
    panel.PANEL_STYLE += '\n' + pathlib.Path(os.environ['TT_LAYOUT_CSS']).read_text(encoding='utf-8')
    panel.ASSET_VERSION = panel.hashlib.sha256((panel.PANEL_STYLE + panel.CONSOLE_SCRIPT).encode()).hexdigest()[:12]
original_server = http.server.ThreadingHTTPServer
class OwnedServer(original_server):
    def serve_forever(self, *args, **kwargs):
        print('TT_LAYOUT_READY ' + json.dumps({'port': self.server_port, 'pid': os.getpid()}), flush=True)
        return super().serve_forever(*args, **kwargs)
http.server.ThreadingHTTPServer = OwnedServer
runpy.run_path(sys.argv[1], run_name='__main__')
`;

function startPreview(fixtureRoot, cssPath) {
  // Bind port zero in the child: never probe/reuse an existing preview process.
  const env = {...process.env, TT_PREVIEW_PORT: '0', PYTHONDONTWRITEBYTECODE: '1',
    TT_LAYOUT_FIXTURE_ROOT: fixtureRoot};
  delete env.TT_PANEL_SOURCE;
  delete env.TT_LAYOUT_CSS;
  if (cssPath) env.TT_LAYOUT_CSS = cssPath;
  const child = spawn(process.env.PYTHON || 'python',
    ['-B', '-u', '-c', bootstrap, path.join(__dirname, 'preview_panel.py')],
    {cwd: root, env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe']});
  let stderr = '', stdout = '';
  child.stderr.on('data', chunk => {stderr += chunk.toString();});
  const exited = new Promise(resolve => child.once('exit', (code, signal) => resolve({code, signal})));
  const ready = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(Error('Preview startup timed out: ' + stderr)), 15000);
    const fail = error => {clearTimeout(timer); reject(error);};
    child.once('error', fail);
    child.once('exit', code => fail(Error(`Preview exited (${code}): ${stderr}`)));
    child.stdout.on('data', chunk => {
      stdout += chunk.toString();
      const line = stdout.split(/\r?\n/).find(value => value.startsWith('TT_LAYOUT_READY '));
      if (!line) return;
      try {
        const info = JSON.parse(line.slice('TT_LAYOUT_READY '.length));
        assert.equal(info.pid, child.pid, 'Preview ownership');
        assert.ok(Number.isInteger(info.port) && info.port > 0, 'Bound preview port');
        clearTimeout(timer);
        resolve('http://127.0.0.1:' + info.port);
      } catch (error) {fail(error);}
    });
  });
  return {child, ready, exited, stderr: () => stderr};
}

async function stopPreview(preview) {
  if (preview.child.exitCode !== null || preview.child.signalCode !== null) return;
  if (!preview.child.pid) return;
  preview.child.kill();
  let timer;
  try {
    await Promise.race([preview.exited, new Promise((_, reject) => {
      timer = setTimeout(() => reject(Error('Owned preview did not exit')), 10000);
    })]);
  } finally {clearTimeout(timer);}
}

async function stylePage(page, scenario) {
  await page.evaluate(scenario => {
    document.documentElement.style.zoom = String(scenario.zoom);
    // Snapshot before changing parents, including hidden help and closed details.
    const sizes = [...document.querySelectorAll('.drawer-card, .drawer-card *, dialog, dialog *')]
      .filter(element => !element.dataset.layoutFont && !(element instanceof SVGElement) &&
        !element.matches('.help-button,.icon-button,[data-drawer-close]'))
      .map(element => {
        const style = getComputedStyle(element);
        return [element, parseFloat(style.fontSize), parseFloat(style.lineHeight)];
      });
    if (scenario.font !== 1) for (const [element, font, line] of sizes) {
      element.style.fontSize = font * scenario.font + 'px';
      if (Number.isFinite(line)) element.style.lineHeight = line * scenario.font + 'px';
      element.dataset.layoutFont = 'true';
    }
  }, scenario);
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
}

async function layoutIssues(locator, options = {}) {
  return locator.evaluate((scope, options) => {
    const issues = [], tolerance = 2;
    const visible = element => element.getClientRects().length && getComputedStyle(element).visibility !== 'hidden';
    const rect = element => element.getBoundingClientRect();
    const describe = element => element.id || element.getAttribute('name') || element.getAttribute('aria-label') ||
      element.querySelector('input[name="action"]')?.value || element.textContent.trim().slice(0, 45) || element.tagName;
    const fail = (element, reason) => issues.push(`${describe(element)}: ${reason}`);
    const inside = (a, b) => a.left >= b.left - tolerance && a.right <= b.right + tolerance &&
      a.top >= b.top - tolerance && a.bottom <= b.bottom + tolerance;
    const overlap = (a, b) => Math.min(a.right, b.right) - Math.max(a.left, b.left) > tolerance &&
      Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top) > tolerance;
    const scale = element => rect(element).width / (element.offsetWidth || rect(element).width);
    const textRects = element => [...element.childNodes].filter(node => node.nodeType === Node.TEXT_NODE && node.textContent.trim())
      .flatMap(node => {const range = document.createRange(); range.selectNodeContents(node); return [...range.getClientRects()];});
    if (document.documentElement.scrollWidth > innerWidth + tolerance) fail(scope, 'document horizontal overflow');
    if (scope.scrollWidth > scope.clientWidth + tolerance) fail(scope, 'internal horizontal overflow');
    const boundary = rect(scope);
    if (boundary.left < -tolerance || boundary.right > innerWidth + tolerance) fail(scope, 'outside viewport horizontally');
    if (options.drawer && boundary.width > 550 * options.zoom + tolerance) fail(scope, 'drawer wider than 550 CSS px');
    const forms = [...scope.querySelectorAll('form')].filter(visible);
    for (const form of forms) {
      const formRect = rect(form);
      if (formRect.left < boundary.left - tolerance || formRect.right > boundary.right + tolerance) fail(form, 'outside drawer/dialog');
      if (form.scrollWidth > form.clientWidth + tolerance) fail(form, 'form horizontal overflow');
      const siblings = [...form.children].filter(element => visible(element) && element.matches('label,button,fieldset,.inline-actions,.action-control'));
      for (let i = 0; i < siblings.length; i++) {
        const element = siblings[i];
        if (!inside(rect(element), formRect)) fail(element, 'outside own form');
        for (const other of siblings.slice(i + 1)) {
          if (overlap(rect(element), rect(other))) fail(element, 'overlaps sibling ' + describe(other));
        }
      }
      for (const label of [...form.querySelectorAll('label')].filter(visible)) {
        const labelRect = rect(label);
        const controls = [...label.querySelectorAll('input,select,textarea,button')].filter(visible);
        for (const control of controls) {
          if (!inside(rect(control), labelRect)) fail(control, 'outside own label');
          for (const text of textRects(label)) if (overlap(rect(control), text)) fail(control, 'overlaps label text');
        }
        for (let i = 0; i < controls.length; i++) for (const other of controls.slice(i + 1)) {
          if (overlap(rect(controls[i]), rect(other))) fail(controls[i], 'overlaps control ' + describe(other));
        }
        for (const text of textRects(label)) if (!inside(text, labelRect)) fail(label, 'label text escapes bounds');
        if (label.matches('.check')) {
          if (Math.abs(labelRect.left - formRect.left) > tolerance || Math.abs(labelRect.right - formRect.right) > tolerance) {
            fail(label, 'checkbox does not occupy a whole form row');
          }
          const input = label.querySelector('input[type="checkbox"]');
          if (input && Math.abs(rect(input).width - 17 * scale(input)) > tolerance) fail(input, 'checkbox stretched or compressed');
        }
      }
      for (const input of [...form.querySelectorAll('input[type="number"],input[type="datetime-local"]')].filter(visible)) {
        const style = getComputedStyle(input), zoom = scale(input);
        const available = formRect.width;
        let minimum;
        if (input.type === 'datetime-local') {
          // Native date/time editor's intrinsic width, measured in this exact font.
          const clone = input.cloneNode();
          clone.removeAttribute('id'); clone.removeAttribute('name');
          clone.style.cssText += ';position:fixed;left:-10000px;width:max-content!important;min-width:max-content!important;max-width:none!important;';
          input.parentElement.append(clone);
          minimum = Math.min(available, rect(clone).width);
          clone.remove();
        } else {
          const canvas = document.createElement('canvas'), context = canvas.getContext('2d');
          context.font = style.font;
          minimum = Math.min(available, (Math.max(120, context.measureText('999999.999').width +
            parseFloat(style.paddingLeft) + parseFloat(style.paddingRight) + 26)) * zoom);
        }
        if (rect(input).width + tolerance < minimum) fail(input, `compressed field (${rect(input).width.toFixed(1)} < ${minimum.toFixed(1)})`);
      }
    }
    const buttons = [...scope.querySelectorAll('button')].filter(visible);
    for (const button of buttons) for (const text of textRects(button)) {
      if (!inside(text, rect(button))) fail(button, 'button text escapes bounds');
    }
    // Non-form dialog actions and search toolbar need the same sibling checks.
    for (const group of [...scope.querySelectorAll('.inline-actions')].filter(visible)) {
      const children = [...group.children].filter(element => visible(element) && !element.matches('.sr-only'));
      for (let i = 0; i < children.length; i++) for (const other of children.slice(i + 1)) {
        if (overlap(rect(children[i]), rect(other))) fail(children[i], 'dialog actions overlap ' + describe(other));
      }
    }
    return [...new Set(issues)];
  }, options);
}

async function clickCheckboxText(page, label) {
  await label.scrollIntoViewIfNeeded();
  const point = await label.evaluate(element => {
    const text = [...element.childNodes].find(node => node.nodeType === Node.TEXT_NODE && node.textContent.trim());
    if (!text) throw Error('Checkbox label has no text');
    const range = document.createRange(); range.selectNodeContents(text);
    const box = range.getClientRects()[0];
    return {x: box.left + Math.min(12, box.width / 2), y: box.top + box.height / 2};
  });
  await page.mouse.click(point.x, point.y);
}

(async () => {
  const args = process.argv.slice(2).filter(arg => !arg.startsWith('--scenario='));
  assert.ok(args.length === 0 || (args.length === 2 && args[0] === '--css'), 'Usage: node tools/check_layout_ui.cjs [--css path] [--scenario=name]');
  const cssPath = args[1] ? path.resolve(args[1]) : null;
  const css = cssPath ? fs.readFileSync(cssPath, 'utf8') : '';
  const artifacts = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-layout-20261112-'));
  const fixtureRoot = path.join(artifacts, 'empty-fixture');
  fs.mkdirSync(fixtureRoot);
  const sourceHash = digest();
  const preview = startPreview(fixtureRoot, cssPath);
  const failures = [], results = [];
  let browser, base, browserVersion, sourceEndHash;
  console.log(`Synthetic layout; CSS: ${cssPath || 'none (current source)'}; artifacts: ${artifacts}`);
  try {
    base = await preview.ready;
    const health = await fetch(base + '/health', {signal: AbortSignal.timeout(5000)});
    assert.ok(health.ok, 'Owned synthetic preview health');
    browser = await chromium.launch({headless: true, channel: 'msedge'});
    browserVersion = browser.version();
    for (const scenario of scenarios) {
      const context = await browser.newContext({viewport: {width: scenario.width, height: scenario.height},
        reducedMotion: 'reduce', locale: 'ru-RU', serviceWorkers: 'block'});
      const page = await context.newPage();
      page.setDefaultTimeout(7000);
      const errors = [], posts = [], violations = [], unexpected = [];
      page.on('pageerror', error => errors.push(error.message));
      page.on('response', response => {if (response.status() >= 400) errors.push(`HTTP ${response.status()} ${response.url()}`);});
      page.on('request', request => {if (request.method() === 'POST') posts.push(new URLSearchParams(request.postData()));});
      await context.route('**/*', route => {
        if (new URL(route.request().url()).origin === base) return route.continue();
        unexpected.push(route.request().url());
        return route.abort('blockedbyclient');
      });
      await page.addInitScript(() => {
        window.__layoutCsp = [];
        document.addEventListener('securitypolicyviolation', event => window.__layoutCsp.push(event.violatedDirective));
      });
      const found = [];
      const check = async (name, locator, options) => {
        const issues = await layoutIssues(locator, options);
        found.push(...issues.map(issue => `${name}: ${issue}`));
      };
      const screenshot = name => page.screenshot({path: path.join(artifacts, `${scenario.name}-${name}.png`)});
      const visit = async view => {
        violations.push(...await page.evaluate(() => window.__layoutCsp || []));
        await page.goto(base + view);
        await stylePage(page, scenario);
      };
      try {
        await visit('/login');
        await page.locator('#login-user').fill('preview');
        await page.locator('#login-password').fill('synthetic-preview-password');
        await page.locator('#login-eye').click();
        assert.equal(await page.locator('#login-password').getAttribute('type'), 'text', 'Login password visibility');
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1), false, 'Login overflow');
        await visit('/?view=clients');
        await page.waitForFunction(() => document.querySelector('[data-client-seen]')?.textContent.includes('\u0441\u0435\u0439\u0447\u0430\u0441'));
        assert.match(await page.locator('[data-client-seen]').first().innerText(), /\u0441\u0435\u0439\u0447\u0430\u0441/, 'Last-online display');
        const menu = page.locator('#mobile-menu');
        if (await menu.isVisible()) {
          await menu.click();
          assert.equal(await menu.getAttribute('aria-expanded'), 'true', 'Sidebar opens');
          await page.waitForFunction(() => document.querySelector('.sidebar').getBoundingClientRect().left >= -1);
          await check('sidebar', page.locator('.sidebar'));
          await page.keyboard.press('Escape');
          assert.equal(await menu.getAttribute('aria-expanded'), 'false', 'Sidebar closes on Escape');
          assert.equal(await page.locator('body').evaluate(body => body.classList.contains('nav-open')), false);
        }
        await page.locator('[data-drawer="identity-0"]').click();
        const drawer = page.locator('#identity-0.open');
        const card = drawer.locator('.drawer-card');
        await drawer.waitFor();
        assert.equal(await page.locator('body').evaluate(body => body.classList.contains('dialog-open')), true, 'Drawer scroll lock');
        assert.equal(await drawer.evaluate(element => element.contains(document.activeElement)), true, 'Drawer focus');
        await drawer.locator('details').evaluateAll(details => details.forEach(element => {element.open = true;}));
        const quota = drawer.locator('form').filter({has: page.locator('input[value="guard-save"]')});
        assert.equal(await quota.locator('input[type="checkbox"]').count(), 2, 'Both quota acknowledgements exist');
        await quota.locator('[name="quota_gib"]').fill('999998.999');
        await quota.locator('[name="expires"]').fill('2030-12-31T23:59');
        await check('drawer/forms', card, {drawer: true, zoom: scenario.zoom});
        await quota.scrollIntoViewIfNeeded();
        await screenshot('quota');
        for (const name of ['auto_suspend', 'disconnect_ack']) {
          const input = quota.locator(`[name="${name}"]`), label = input.locator('..');
          const before = await input.isChecked();
          await clickCheckboxText(page, label);
          assert.equal(await input.isChecked(), !before, `${name}: text toggles checkbox`);
          await clickCheckboxText(page, label);
          assert.equal(await input.isChecked(), before, `${name}: text toggles back`);
        }
        // Every help state, including the long checkbox help, participates in flow.
        await drawer.locator('label .help-button').evaluateAll(buttons => buttons.forEach(button => button.click()));
        await check('expanded help', card, {drawer: true, zoom: scenario.zoom});
        await quota.scrollIntoViewIfNeeded();
        await screenshot('help');
        await drawer.locator('label .help-button').evaluateAll(buttons => buttons.forEach(button => button.click()));
        await quota.locator('[name="auto_suspend"]').check();
        await quota.locator('[name="disconnect_ack"]').check();
        const save = quota.locator('button:not([type="button"])');
        await save.click();
        const confirm = page.locator('#action-confirm[open]');
        await confirm.waitFor();
        await check('confirmation', confirm);
        await screenshot('confirm');
        if (process.env.TT_LAYOUT_TRACE === '1') {
          const box = await page.locator('#confirm-cancel').boundingBox();
          await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
          const motion = await page.locator('#confirm-cancel').evaluate(async button => {
            const frames=[];
            for(let i=0;i<40;i++){
              await new Promise(resolve=>requestAnimationFrame(resolve));
              const rect=button.getBoundingClientRect(),parent=button.closest('dialog').getBoundingClientRect();
              frames.push([rect.x,rect.y,rect.width,rect.height,getComputedStyle(button).transform,parent.x,parent.y,innerWidth,innerHeight]);
            }
            return [...new Set(frames.map(frame=>JSON.stringify(frame)))];
          });
          console.log('Cancel geometry:',JSON.stringify(motion));
        }
        await page.locator('#confirm-cancel').click();
        assert.equal(posts.length, 0, 'Cancelled operation must not POST');
        assert.equal(await page.locator('#operation-result[open]').count(), 0, 'No result after cancel');
        await save.click();
        await page.locator('#confirm-accept').click();
        const result = page.locator('#operation-result[open]');
        await result.waitFor();
        assert.equal(posts.length, 1, 'Exactly one synthetic submission');
        assert.equal(posts[0].get('action'), 'guard-save');
        assert.equal(posts[0].get('quota_gib'), '999998.999');
        assert.equal(posts[0].get('expires'), '2030-12-31T23:59');
        assert.equal(posts[0].get('auto_suspend'), '1');
        assert.equal(posts[0].get('disconnect_ack'), '1');
        assert.equal(posts[0].getAll('_csrf').length, 1, 'Single CSRF value');
        await check('result dialog', result);
        await screenshot('result');
        await page.locator('#result-close').click();
        assert.equal(await page.locator('dialog[open]').count(), 0, 'Dialogs close');
        await page.keyboard.press('Escape');
        await drawer.waitFor({state: 'hidden'});
        assert.equal(await page.locator('body').evaluate(body => body.classList.contains('dialog-open')), false, 'Drawer unlocks');
        await page.locator('[data-drawer="add-client"]').click();
        const add = page.locator('#add-client.open');
        await add.waitFor();
        await check('add-client', add.locator('.drawer-card'), {drawer: true, zoom: scenario.zoom});
        await screenshot('add');
        await page.keyboard.press('Escape');
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1), false, 'Client page overflow');
        violations.push(...await page.evaluate(() => window.__layoutCsp));
        assert.deepEqual(errors, [], 'Browser errors');
        assert.deepEqual(violations, [], 'CSP violations');
        assert.deepEqual(unexpected, [], 'Only the owned loopback preview may be requested');
      } catch (error) {
        found.push(error.stack || error.message);
        await screenshot('failure').catch(() => {});
      } finally {await context.close();}
      const unique = [...new Set(found)];
      results.push({scenario, issues: unique});
      failures.push(...unique.map(issue => `${scenario.name}: ${issue}`));
      console.log(`${unique.length ? 'FAIL' : 'PASS'} ${scenario.name}: ${unique.length} issue(s)`);
      for (const issue of unique.slice(0, 4)) console.log('  ' + issue);
    }
    sourceEndHash = digest();
    assert.equal(sourceEndHash, sourceHash, 'Panel source changed during run; rerun against a stable snapshot');
    assert.equal(preview.stderr(), '', 'Synthetic preview stderr');
  } catch (error) {
    failures.push('Harness: ' + (error.stack || error.message));
    console.error(error);
  } finally {
    try {await browser?.close();} finally {
      await stopPreview(preview);
      assert.equal(path.dirname(fixtureRoot), artifacts, 'Temporary fixture cleanup boundary');
      fs.rmSync(fixtureRoot, {recursive: true, force: true});
    }
  }
  fs.writeFileSync(path.join(artifacts, 'results.json'), JSON.stringify({
    synthetic: true, sourceHash, sourceEndHash, cssPath, cssHash: css ? createHash('sha256').update(css).digest('hex') : null,
    browserChannel: 'msedge', browserVersion, results, failures, previewStopped: true
  }, null, 2));
  console.log(`${failures.length ? 'FAIL' : 'PASS'}: ${results.filter(result => !result.issues.length).length}/${scenarios.length} scenarios; ${failures.length} issues. Preview stopped. Results: ${artifacts}`);
  if (failures.length) process.exitCode = 1;
})().catch(error => {console.error(error); process.exitCode = 1;});
