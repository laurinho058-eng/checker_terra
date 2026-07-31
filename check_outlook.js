const puppeteer = require('puppeteer');
const fs = require('fs');

(async () => {
    const email = process.argv[2];
    const password = process.argv[3];
    
    const browser = await puppeteer.launch({
        headless: 'new',
        args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    
    try {
        const page = await browser.newPage();
        await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36');
        
        await page.goto('https://login.live.com/', {waitUntil: 'networkidle2'});
        
        await page.waitForSelector('input[type="email"]', {timeout: 5000});
        await page.type('input[type="email"]', email);
        await page.keyboard.press('Enter');
        
        await new Promise(r => setTimeout(r, 4000));
        
        await page.screenshot({path: 'screenshot.png'});
        
        const pageContent = await page.content();
        fs.writeFileSync('page.html', pageContent);

    } catch (err) {
        console.log(err);
    } finally {
        await browser.close();
    }
})();
