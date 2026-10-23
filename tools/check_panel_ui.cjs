const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const path = require('path');
(async () => {
  const browser = await chromium.launch({headless:true,channel:process.env.BROWSER_CHANNEL || 'msedge'});
  const errors=[];
  try {
    for(const viewport of [{width:1440,height:1000},{width:390,height:844},{width:320,height:740},{width:768,height:1024}]) {
      const page=await browser.newPage({viewport});
      page.on('pageerror',e=>errors.push(e.message));
      await page.addInitScript(()=>{window.__securityViolations=[];document.addEventListener('securitypolicyviolation',e=>window.__securityViolations.push(e.violatedDirective));});
      for(const theme of ['light','dark']){
        await page.goto('http://127.0.0.1:18089/login');
        await page.evaluate(theme=>{localStorage.setItem('tt-theme',theme);document.documentElement.dataset.theme=theme;},theme);
        await page.locator('#login-user').fill('preview');
        await page.locator('#login-password').fill('synthetic-preview-password');
        await page.locator('#login-eye').click();
        if(await page.locator('#login-password').getAttribute('type')!=='text')throw Error('Login password visibility');
        if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1))throw Error('Login overflow');
        await page.screenshot({path:path.join(__dirname,`login-${theme}-${viewport.width}.png`),fullPage:true});
        if((await page.evaluate(()=>window.__securityViolations)).length)throw Error('Login CSP');
      }
      await page.goto('http://127.0.0.1:18089/?view=clients');
      await page.waitForFunction(()=>document.querySelector('[data-client-metrics]')?.textContent.includes('всего'));
      if(!(await page.locator('[data-client-seen]').first().innerText()).includes('сейчас'))throw Error('Last-online display');
      if(viewport.width<=800){
        await page.locator('#mobile-menu').click();
        await page.locator('.sidebar .nav-item.active').waitFor({state:'visible'});
        if(await page.locator('#mobile-menu').getAttribute('aria-expanded')!=='true')throw Error('Mobile navigation failed');
        await page.keyboard.press('Escape');
      }
      await page.locator('[data-drawer="identity-0"]').click();
      await page.locator('#identity-0.open').waitFor({state:'visible'});
      await page.locator('#identity-0 [data-reveal]').click();
      if(await page.locator('#secret-0').getAttribute('type') !== 'text') throw Error('Password reveal failed');
      await page.locator('#identity-0 [data-load-link]').click();
      await page.locator('#lazy-link-0').waitFor();
      if(!(await page.locator('#lazy-link-0').inputValue()).startsWith('tt://'))throw Error('Lazy link failed');
      await page.locator('#identity-0 .share-qr').waitFor({state:'visible'});
      await page.waitForFunction(()=>{const img=document.querySelector('#identity-0 .share-qr');return img?.complete&&img.naturalWidth>100;});
      await page.evaluate(()=>window.__qaPersistent='same-document');
      await page.locator('#identity-0 input[name="note"]').fill('Проверено QA');
      await page.locator('#identity-0 form').filter({has:page.locator('input[name="note"]')}).getByRole('button',{name:'Сохранить',exact:true}).click();
      await page.locator('#operation-result[open]').waitFor();
      await page.locator('#result-close').click();
      await page.locator('main[data-refreshed]').waitFor();
      await page.locator('[data-drawer="identity-0"]').click();
      await page.locator('#identity-0.open').waitFor();
      if(await page.locator('#identity-0 input[name="note"]').inputValue()!=='Проверено QA')throw Error('Soft content refresh failed');
      if(await page.evaluate(()=>window.__qaPersistent)!=='same-document')throw Error('Full document reload after action');
      await page.locator('#identity-0 form').filter({has:page.locator('input[name="password"]')}).getByRole('button',{name:'Сменить пароль',exact:true}).click();
      await page.locator('#action-confirm[open]').waitFor();
      await page.locator('#confirm-cancel').click();
      if(await page.locator('#operation-result[open]').count())throw Error('Cancelled operation was submitted');
      await page.locator('#identity-0 form').filter({has:page.locator('input[name="password"]')}).getByRole('button',{name:'Сменить пароль',exact:true}).click();
      await page.locator('#action-confirm[open]').waitFor();
      await page.locator('#confirm-accept').click();
      await page.locator('#operation-result[open]').waitFor();
      const previousRefresh=await page.locator('main').getAttribute('data-refreshed');
      await page.locator('#result-close').click();
      await page.waitForFunction(previous=>document.querySelector('main')?.dataset.refreshed!==previous,previousRefresh);
      await page.keyboard.press('Escape');
      await page.locator('#client-search').fill('client27');
      if(await page.locator('[data-client-row]:visible').count()!==1) throw Error('Client search failed');
      await page.locator('#client-search').fill('');
      await page.locator('#page-next').click();
      if(await page.locator('#page-label').innerText()!=='2 / 3') throw Error('Pagination failed');
      await page.locator('#theme-toggle').click();
      await page.waitForTimeout(220);
      await page.evaluate(()=>scrollTo(0,0));
      await page.screenshot({path:path.join(__dirname,`clients-${viewport.width}.png`),fullPage:true});
      for(const view of ['dashboard','security','routing','dns','logs','endpoint','warp','certificates','system','panel']) {
        await page.goto('http://127.0.0.1:18089/?view='+view);
        if(view==='dashboard') {
          await page.locator('#interface-select option').first().waitFor({state:'attached'});
          await page.waitForTimeout(350);
          await page.locator('#monitor-refresh').click();
          await page.waitForFunction(()=>document.querySelector('#network-rate').textContent.includes('/с'));
          const pixels=await page.locator('#traffic-chart').evaluate(canvas=>{const data=canvas.getContext('2d').getImageData(0,0,canvas.width,canvas.height).data;let count=0;for(let i=0;i<data.length;i+=4)if(data[i+3]>0)count++;return count;});
          if(pixels<100)throw Error('Traffic canvas is blank');
          await page.locator('#refresh-interval').selectOption('0');
        }
        const overflowing=await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1);
        if(overflowing) throw Error(`Page overflow ${view} ${viewport.width}`);
        if(view==='security'){
          await page.getByRole('button',{name:'Полный отчёт',exact:true}).click();
          await page.locator('#operation-result[open]').waitFor();
          if(!(await page.locator('#result-output').innerText()).includes('Тестовый отчёт'))throw Error('Shared action result failed');
          await page.locator('#result-close').click();
        }
        if(view==='routing'){
          if(await page.locator('.route-picker input:checked').inputValue()!=='interface')throw Error('Current route is not preselected');
          await page.locator('.route-picker input[value="socks5"]').check();
          await page.locator('[data-cascade-address] input').fill('proxy.example.test:1080');
          await page.getByRole('button',{name:'Применить выбранный маршрут',exact:true}).click();
          await page.locator('#action-confirm[open]').waitFor();
          await page.locator('#confirm-cancel').click();
          await page.locator('.route-picker input[value="interface"]').check();
          if(await page.locator('[data-cascade-address]').isVisible())throw Error('Irrelevant cascade input still visible');
        }
        await page.screenshot({path:path.join(__dirname,`${view}-${viewport.width}.png`),fullPage:true});
        if((await page.evaluate(()=>window.__securityViolations)).length)throw Error('CSP violation on '+view);
      }
      await page.goto('http://127.0.0.1:18089/?view=dashboard');
      await page.locator('#theme-toggle').click();
      await page.waitForTimeout(350);
      await page.locator('#monitor-refresh').click();
      await page.waitForFunction(()=>document.querySelector('#network-rate').textContent.includes('/с'));
      await page.screenshot({path:path.join(__dirname,`dashboard-light-${viewport.width}.png`),fullPage:true});
      const missingSubmit=await page.locator('form').evaluateAll(forms=>forms.filter(f=>!f.querySelector('button,input[type=submit]')).length);
      if(missingSubmit)throw Error('Form without submit action');
      await page.close();
    }
    if(errors.length) throw Error(errors.join('\n'));
    console.log('Desktop/mobile: login, drawers, lazy QR, confirmations, soft refresh, search, pagination, themes, chart and eleven views passed.');
  } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exit(1);});
