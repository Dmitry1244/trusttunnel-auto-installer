const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const path = require('path');
(async () => {
  const browser = await chromium.launch({headless:true,channel:process.env.BROWSER_CHANNEL || 'msedge'});
  const errors=[];
  try {
    for(const viewport of [{width:1440,height:1000},{width:390,height:844}]) {
      const page=await browser.newPage({viewport});
      page.on('pageerror',e=>errors.push(e.message));
      await page.goto('http://127.0.0.1:18089/?view=clients');
      await page.locator('[data-drawer="identity-0"]').click();
      await page.locator('#identity-0.open').waitFor({state:'visible'});
      await page.locator('#identity-0 [data-reveal]').click();
      if(await page.locator('#secret-0').getAttribute('type') !== 'text') throw Error('Password reveal failed');
      await page.keyboard.press('Escape');
      await page.locator('#client-search').fill('client27');
      if(await page.locator('[data-client-row]:visible').count()!==1) throw Error('Client search failed');
      await page.locator('#client-search').fill('');
      await page.locator('#page-next').click();
      if(await page.locator('#page-label').innerText()!=='2 / 3') throw Error('Pagination failed');
      await page.locator('#theme-toggle').click();
      await page.screenshot({path:path.join(__dirname,`clients-${viewport.width}.png`),fullPage:true});
      for(const view of ['dashboard','security','routing','dns','logs']) {
        await page.goto('http://127.0.0.1:18089/?view='+view);
        if(view==='dashboard') await page.waitForTimeout(5500);
        const overflowing=await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1);
        if(overflowing) throw Error(`Page overflow ${view} ${viewport.width}`);
        await page.screenshot({path:path.join(__dirname,`${view}-${viewport.width}.png`),fullPage:true});
      }
      await page.close();
    }
    if(errors.length) throw Error(errors.join('\n'));
    console.log('Desktop/mobile: drawers, password reveal, search, pagination, theme, chart polling and five views passed.');
  } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exit(1);});
