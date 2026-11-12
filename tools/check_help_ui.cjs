// Browser QA only. No production writes, commands, credentials or external requests.
// Runtime overrides match check_panel_ui.cjs: PLAYWRIGHT_MODULE, TT_UI_DEPS, PYTHON.
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const {spawn} = require('node:child_process');
const {createHash} = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const port = 18096;
const base = `http://127.0.0.1:${port}`;
const sourceHash = () => createHash('sha256').update(fs.readFileSync(path.join(root, 'trusttunnel-panel.py'))).digest('hex');
const views = ['security', 'dashboard', 'clients', 'endpoint', 'warp', 'routing', 'dns', 'logs', 'certificates', 'system', 'panel'];

const bootstrap = String.raw`
import http.server, json, os, pathlib, runpy, socket, sys
sys.path.insert(0, os.path.dirname(sys.argv[1]))
from test_admin import panel
fixture = pathlib.Path(os.environ['TT_HELP_FIXTURE_ROOT'])
for name, value in list(vars(panel).items()):
    if isinstance(value, pathlib.Path):
        setattr(panel, name, fixture / name)
panel.read_text = lambda path: ''
panel.run = lambda *args, **kwargs: (0, 'synthetic preview: no commands')
panel.protection_state = lambda: {}
panel.torrent_state = lambda: {'enabled': False, 'mode': 'signatures', 'ports': []}
panel.release_snapshot = lambda: {'installed': 'fixture', 'stable': {'tag_name': 'fixture'}, 'beta': {}, 'update_available': False}
def no_network(*args, **kwargs):
    raise OSError('Outbound requests disabled in synthetic help preview')
panel.urllib.request.urlopen = no_network
original_server = http.server.ThreadingHTTPServer
class OwnedServer(original_server):
    allow_reuse_address = False
    def server_bind(self):
        if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()
    def serve_forever(self, *args, **kwargs):
        print('TT_HELP_READY ' + json.dumps({'port': self.server_port, 'pid': os.getpid()}), flush=True)
        return super().serve_forever(*args, **kwargs)
http.server.ThreadingHTTPServer = OwnedServer
runpy.run_path(sys.argv[1], run_name='__main__')
`;

function startPreview(fixtureRoot) {
  const env = {...process.env, TT_PREVIEW_PORT: String(port), TT_HELP_FIXTURE_ROOT: fixtureRoot,
    PYTHONDONTWRITEBYTECODE: '1'};
  delete env.TT_PANEL_SOURCE;
  delete env.TT_LAYOUT_CSS;
  const child = spawn(process.env.PYTHON || 'python',
    ['-B', '-u', '-c', bootstrap, path.join(__dirname, 'preview_panel.py')],
    {cwd: root, env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe']});
  let stderr = '', stdout = '';
  child.stderr.on('data', chunk => {stderr += chunk.toString();});
  const exited = new Promise(resolve => child.once('exit', resolve));
  const ready = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(Error('Owned preview startup timed out: ' + stderr)), 15000);
    const fail = error => {clearTimeout(timer); reject(error);};
    child.once('error', fail);
    child.once('exit', code => fail(Error(`Owned preview exited (${code}): ${stderr}`)));
    child.stdout.on('data', chunk => {
      stdout += chunk.toString();
      const line = stdout.split(/\r?\n/).find(value => value.startsWith('TT_HELP_READY '));
      if (!line) return;
      try {
        const info = JSON.parse(line.slice('TT_HELP_READY '.length));
        assert.equal(info.pid, child.pid, 'Preview ownership');
        assert.equal(info.port, port, 'Requested preview port');
        clearTimeout(timer);
        resolve();
      } catch (error) {fail(error);}
    });
  });
  // Readiness comes from our child after bind, never from an unknown HTTP listener.
  return {child, ready, exited, stderr: () => stderr};
}

async function stopPreview(preview) {
  if (!preview.child.pid || preview.child.exitCode !== null || preview.child.signalCode !== null) return;
  preview.child.kill();
  let timer;
  try {
    await Promise.race([preview.exited, new Promise((_, reject) => {
      timer = setTimeout(() => reject(Error('Owned preview did not exit')), 10000);
    })]);
  } finally {clearTimeout(timer);}
}

async function assertNoOverflow(page, selector = 'html') {
  const issues = await page.locator(selector).evaluate(element => {
    const box = element.getBoundingClientRect(), issues = [];
    if (document.documentElement.scrollWidth > innerWidth + 1) issues.push('document horizontal overflow');
    if (element.scrollWidth > element.clientWidth + 1) issues.push('internal horizontal overflow');
    if (box.left < -1 || box.right > innerWidth + 1) issues.push('outside viewport horizontally');
    return issues;
  });
  assert.deepEqual(issues, [], `Bounds: ${selector}`);
}

async function auditTitles(page) {
  return page.locator('main form').evaluateAll(forms => {
    const visible = element => element.getClientRects().length &&
      getComputedStyle(element).visibility !== 'hidden';
    const checked = [], missing = [];
    let hiddenSubmits = 0;
    for (const form of forms) {
      const action = form.querySelector('input[name="action"]')?.value || form.getAttribute('action');
      for (const button of form.querySelectorAll('button,input[type="submit"]')) {
        if (button.type !== 'submit') continue;
        if (!visible(button)) {hiddenSubmits++; continue;}
        const key = `${action}${button.name ? ':' + button.name + '=' + button.value : ''}`;
        checked.push(key);
        if (!button.title.trim()) missing.push(key);
      }
    }
    return {checked, missing, hiddenSubmits};
  });
}

async function checkHelp(page, trigger, expectedTitle, expectedText, screenshot, incoming = false) {
  assert.equal(await trigger.getAttribute('type'), 'button', 'Help must not be a submit button');
  assert.equal(await trigger.evaluate(element => !element.parentElement.closest('button')), true, 'No nested buttons');
  await trigger.hover();
  assert.equal(await trigger.evaluate(element => element.matches(':hover')), true, 'Help receives pointer hover');
  assert.equal((await trigger.getAttribute('title')).trim(), expectedText, 'Rich hover title');
  assert.ok(expectedText.length > 40, 'Help should explain the action, not repeat a short label');
  await trigger.click();
  const dialog = page.locator('#feature-help[open]');
  await dialog.waitFor();
  assert.equal(await dialog.evaluate(element => element.matches(':modal')), true, 'Native modal help');
  assert.equal(await dialog.locator('h3#feature-help-title').innerText(), expectedTitle, 'Help heading');
  const description = (await dialog.locator('p').innerText()).trim();
  assert.equal(description, expectedText, 'Modal retains the full hover explanation');
  if (incoming) {
    assert.match(description, /\bdeny\b/i, 'Explains default deny');
    assert.match(description, /incoming|\u0432\u0445\u043e\u0434\u044f\u0449/i, 'Explains incoming direction');
    assert.match(description, /default|\u0443\u043c\u043e\u043b\u0447\u0430\u043d/i, 'Explains default policy');
    assert.match(description, /\bSSH\b/i, 'Explains preserved SSH access');
    assert.match(description, /\ballow\b|\u0440\u0430\u0437\u0440\u0435\u0448|\u044f\u0432\u043d\u043e \u043e\u0442\u043a\u0440\u044b\u0442/i,
      'Explains explicit allow rules, including SSH');
  }
  assert.equal(await dialog.evaluate(element => element.contains(document.activeElement)), true, 'Focus moves into help');
  await assertNoOverflow(page, '#feature-help');
  assert.equal(await page.locator('#action-confirm[open],#operation-result[open]').count(), 0, 'Help is not an operation');
  await screenshot();
  await page.keyboard.press('Escape');
  await dialog.waitFor({state: 'hidden'});
  assert.equal(await trigger.evaluate(element => document.activeElement === element), true, 'Escape returns focus');
  // Keyboard activation and the explicit close control follow the same safe path.
  await page.keyboard.press('Enter');
  await dialog.waitFor();
  await dialog.locator('button[type="button"]').click();
  await dialog.waitFor({state: 'hidden'});
  assert.equal(await trigger.evaluate(element => document.activeElement === element), true, 'Close returns focus');
  await page.waitForTimeout(100);
  assert.equal(await page.locator('#action-confirm[open],#operation-result[open]').count(), 0, 'No operation after help closes');
  assert.deepEqual(await page.evaluate(() => window.__helpSubmits), [], 'Help must not dispatch form submit');
}

(async () => {
  const artifacts = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-help-ui-'));
  const fixtureRoot = path.join(artifacts, 'empty-fixture');
  fs.mkdirSync(fixtureRoot);
  const hashBefore = sourceHash();
  const preview = startPreview(fixtureRoot);
  const results = [], failures = [];
  let browser, browserVersion, hashAfter, previewStopped = false;
  console.log(`Synthetic help QA: ${base}; artifacts: ${artifacts}`);
  try {
    await preview.ready;
    assert.ok((await fetch(base + '/health', {signal: AbortSignal.timeout(5000)})).ok, 'Owned preview health');
    browser = await chromium.launch({headless: true, channel: 'msedge'});
    browserVersion = browser.version();
    for (const width of [320, 390, 768, 1440]) {
      const context = await browser.newContext({viewport: {width, height: 1000},
        reducedMotion: 'reduce', locale: 'ru-RU', serviceWorkers: 'block'});
      const page = await context.newPage();
      page.setDefaultTimeout(5000);
      const issues = [], posts = [], errors = [], external = [], violations = [], titleAudits = [];
      page.on('pageerror', error => errors.push(error.message));
      page.on('request', request => {if (request.method() === 'POST') posts.push(request.url());});
      await context.route('**/*', route => {
        const request = route.request();
        if (new URL(request.url()).origin !== base) {
          external.push(request.url());
          return route.abort('blockedbyclient');
        }
        if (!['GET', 'HEAD'].includes(request.method())) {
          if (request.method() !== 'POST') posts.push(`${request.method()} ${request.url()}`);
          return route.abort('blockedbyclient');
        }
        return route.continue();
      });
      await page.addInitScript(() => {
        window.__helpSubmits = [];
        window.__helpCsp = [];
        document.addEventListener('submit', event => {
          window.__helpSubmits.push(event.target.getAttribute('action'));
          event.preventDefault();
        }, true);
        document.addEventListener('securitypolicyviolation', event => window.__helpCsp.push(event.violatedDirective));
      });
      const screenshot = name => page.screenshot({path: path.join(artifacts, `${width}-${name}.png`)});
      const step = async (name, work) => {
        try {await work();} catch (error) {
          issues.push(`${name}: ${error.stack || error.message}`);
          await screenshot(name + '-failure').catch(() => {});
          await page.locator('#feature-help[open]').evaluateAll(dialogs => dialogs.forEach(dialog => dialog.close())).catch(() => {});
        }
      };
      const audit = async view => {
        const titles = await auditTitles(page);
        titleAudits.push({view, ...titles});
        assert.ok(titles.checked.length, `${view}: visible submit coverage must not be empty`);
        assert.deepEqual(titles.missing, [], `${view}: visible submit buttons need titles (backend actions)`);
        await assertNoOverflow(page);
      };
      try {
        for (const view of views) {
          await step(view, async () => {
            violations.push(...await page.evaluate(() => window.__helpCsp || []));
            await page.goto(`${base}/?view=${view}`);
            assert.equal(await page.locator('body').getAttribute('data-view'), view, 'Expected admin view');
            await page.locator('#feature-help').waitFor({state: 'attached'});
            await audit(view);
          });
          if (view !== 'security') continue;
          await step('incoming-card', async () => {
            const heading = page.locator('.security-check h3').filter({hasText: /incoming|\u0432\u0445\u043e\u0434\u044f\u0449/i});
            assert.equal(await heading.count(), 1, 'Preview must include one incoming-policy fixture card');
            const title = await heading.evaluate(element => [...element.childNodes]
              .filter(node => node.nodeType === Node.TEXT_NODE).map(node => node.textContent).join('').trim());
            await heading.hover();
            assert.equal(await heading.evaluate(element => element.matches(':hover')), true, 'Incoming card receives hover');
            const explanation = (await heading.getAttribute('title') || '').trim();
            assert.ok(explanation, 'Incoming card heading has a hover explanation');
            const help = heading.locator('button.action-help');
            assert.equal(await help.count(), 1, 'Incoming card has a separate info button');
            await checkHelp(page, help, title, explanation, () => screenshot('incoming-help'), true);
          });
          await step('ufw-action-help', async () => {
            const form = page.locator('main form').filter({has: page.locator('input[name="action"][value="ufw-default"]')});
            assert.equal(await form.count(), 1, 'Find UFW policy by backend action, not its button text');
            await form.evaluate(element => {
              for (let parent = element.parentElement; parent; parent = parent.parentElement) {
                if (parent.tagName === 'DETAILS') parent.open = true;
              }
            });
            const control = form.locator('.action-control');
            assert.equal(await control.count(), 1, 'UFW action uses its own wrapper');
            const submit = control.locator('button:not([type="button"])');
            assert.equal(await submit.count(), 1, 'Distinct UFW submit button');
            const title = (await submit.innerText()).trim();
            const explanation = (await submit.getAttribute('title') || '').trim();
            const help = control.locator('button.action-help');
            assert.equal(await help.count(), 1, 'UFW action has separate help');
            await checkHelp(page, help, title, explanation, () => screenshot('ufw-action-help'));
            await audit('security-policy-expanded');
          });
        }
        violations.push(...await page.evaluate(() => window.__helpCsp || []));
        await step('no-side-effects', async () => {
          assert.deepEqual(posts, [], 'No POST or other mutation request; requests are blocked defensively');
          assert.deepEqual(external, [], 'No external browser requests');
          assert.deepEqual(errors, [], 'No browser exceptions');
          assert.deepEqual(violations, [], 'No CSP violations');
        });
      } finally {await context.close();}
      results.push({width, issues, titleAudits, posts, errors, external, violations});
      failures.push(...issues.map(issue => `${width}: ${issue}`));
      console.log(`${issues.length ? 'FAIL' : 'PASS'} ${width}: ${titleAudits.reduce((sum, audit) => sum + audit.checked.length, 0)} visible submit checks; ${issues.length} issue(s)`);
      for (const issue of issues) console.log('  ' + issue);
    }
    hashAfter = sourceHash();
    assert.equal(hashAfter, hashBefore, 'Panel source changed during QA; results require a stable-source rerun');
    assert.equal(preview.stderr(), '', 'Synthetic preview stderr');
  } catch (error) {
    failures.push('Harness: ' + (error.stack || error.message));
    console.error(error);
  } finally {
    try {await browser?.close();} finally {
      await stopPreview(preview);
      previewStopped = true;
      assert.equal(path.dirname(fixtureRoot), artifacts, 'Fixture cleanup stays inside our Temp directory');
      fs.rmSync(fixtureRoot, {recursive: true, force: true});
    }
  }
  fs.writeFileSync(path.join(artifacts, 'results.json'), JSON.stringify({synthetic: true,
    base, previewPid: preview.child.pid, previewStopped, sourceHash: hashBefore, sourceEndHash: hashAfter,
    browserChannel: 'msedge', browserVersion, results, failures}, null, 2));
  console.log(`${failures.length ? 'FAIL' : 'PASS'}: ${results.filter(result => !result.issues.length).length}/4 widths; owned preview stopped. Report: ${artifacts}`);
  if (failures.length) process.exitCode = 1;
})().catch(error => {console.error(error); process.exitCode = 1;});
