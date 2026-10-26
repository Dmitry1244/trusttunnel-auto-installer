const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const path = require('path');
(async()=>{
  const url=process.env.PANEL_QA_URL;
  if(!url||!process.env.PANEL_QA_USER||!process.env.PANEL_QA_PASSWORD)throw Error('QA_CONFIG_MISSING');
  const browser=await chromium.launch({headless:true,channel:'msedge'});
  try{
    for(const width of [1440,390]){
      const page=await browser.newPage({viewport:{width,height:900}});
      const errors=[];page.on('pageerror',()=>errors.push(true));
      await page.goto(url+'/login');
      await page.locator('#login-user').waitFor();
      await page.locator('#login-user').fill(process.env.PANEL_QA_USER);
      await page.locator('#login-password').fill(process.env.PANEL_QA_PASSWORD);
      await page.locator('.login-submit').click();
      await page.waitForURL(url+'/');
      await page.locator('#traffic-chart').waitFor();
      await page.locator('#interface-select option').first().waitFor({state:'attached'});
      await page.locator('#monitor-refresh').click();
      if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1))throw Error('LIVE_LAYOUT_OVERFLOW');
      await page.screenshot({path:path.join(__dirname,`live-dashboard-${width}.png`),fullPage:true});
      await page.goto(url+'/?view=security');
      await page.getByRole('button',{name:'Проверить сервер и получить рекомендации',exact:true}).waitFor();
      if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1))throw Error('LIVE_SECURITY_OVERFLOW');
      await page.goto(url+'/?view=clients');
      await page.locator('[data-drawer^="identity-"]').first().click();
      const drawer=page.locator('aside.drawer.open');
      if(await drawer.locator('input[value="guard-restrict"]').count())throw Error('LEGACY_TRANSPORT_PRESET');
      if(await drawer.locator('input[value="guard-watch-save"]').count()!==1)throw Error('WATCH_CONTROLS_MISSING');
      if(await drawer.locator('input[name="source_cidr"]').count()!==1)throw Error('INVITE_SCOPE_MISSING');
      await page.goto(url+'/?view=routing');
      await page.locator('#torrent-controls').waitFor();
      if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1))throw Error('LIVE_ROUTING_OVERFLOW');
      await page.locator('form[action="/logout"] button').click();
      await page.waitForURL(url+'/login');
      if(errors.length)throw Error('LIVE_PAGE_ERROR');
      await page.close();
    }
    console.log('Live trusted HTTPS, real login, dashboard, security, watch/invite and torrent controls; responsive layout and logout: PASS');
  }finally{await browser.close();}
})().catch(()=>{console.error('Live browser verification failed. No credentials or page content logged.');process.exit(1);});
