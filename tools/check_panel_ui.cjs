const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const path = require('path');
(async () => {
  const browser = await chromium.launch({headless:true,channel:process.env.BROWSER_CHANNEL || 'msedge'});
  const errors=[];
  try {
    for(const viewport of [{width:1440,height:1000},{width:390,height:844},{width:320,height:740},{width:768,height:1024}]) {
      const page=await browser.newPage({viewport});
      page.on('pageerror',e=>errors.push(e.message));
      await page.goto('http://127.0.0.1:18089/?view=clients');
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
      await page.keyboard.press('Escape');
      await page.locator('#client-search').fill('client27');
      if(await page.locator('[data-client-row]:visible').count()!==1) throw Error('Client search failed');
      await page.locator('#client-search').fill('');
      await page.locator('#page-next').click();
      if(await page.locator('#page-label').innerText()!=='2 / 3') throw Error('Pagination failed');
      await page.locator('#theme-toggle').click();
      await page.evaluate(()=>scrollTo(0,0));
      await page.screenshot({path:path.join(__dirname,`clients-${viewport.width}.png`),fullPage:true});
      for(const view of ['dashboard','security','routing','dns','logs','endpoint','warp','certificates','system','panel']) {
        await page.goto('http://127.0.0.1:18089/?view='+view);
        if(view==='dashboard') {
          await page.locator('#interface-select option').first().waitFor({state:'attached'});
          await page.waitForTimeout(100);
          await page.locator('#monitor-refresh').click();
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
        await page.screenshot({path:path.join(__dirname,`${view}-${viewport.width}.png`),fullPage:true});
      }
      await page.goto('http://127.0.0.1:18089/?view=dashboard');
      await page.locator('#theme-toggle').click();
      await page.waitForTimeout(220);
      await page.screenshot({path:path.join(__dirname,`dashboard-light-${viewport.width}.png`),fullPage:true});
      const missingSubmit=await page.locator('form').evaluateAll(forms=>forms.filter(f=>!f.querySelector('button,input[type=submit]')).length);
      if(missingSubmit)throw Error('Form without submit action');
      await page.close();
    }
    if(errors.length) throw Error(errors.join('\n'));
    console.log('Desktop/mobile: drawers, password reveal, search, pagination, theme, chart polling and five views passed.');
  } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exit(1);});
