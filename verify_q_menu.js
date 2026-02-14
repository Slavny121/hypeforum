const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.goto('http://localhost:5500/index.html');
  
  // Wait for intro or bypass it
  await page.evaluate(() => {
    // Manually trigger what's needed to see the UI
    document.getElementById('auth-overlay').classList.remove('active');
    document.getElementById('auth-overlay').style.display = 'none';
    state.isLoaded = true;
  });

  // Open Q menu
  await page.keyboard.press('q');
  await page.waitForTimeout(1000); // wait for animation
  
  await page.screenshot({ path: 'q_menu_redesign.png', fullPage: true });
  
  await browser.close();
})();
