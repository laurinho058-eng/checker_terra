const puppeteer = require('puppeteer');

(async () => {
    const email = 'marciorubens065@outlook.com';
    const password = 'wrongpassword123';
    
    let puppeteerArgs = ['--no-sandbox', '--disable-setuid-sandbox', '--disable-blink-features=AutomationControlled'];

    const browser = await puppeteer.launch({
        headless: 'new',
        args: puppeteerArgs
    });
    
    try {
        const page = await browser.newPage();
        await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36');
        
        await page.goto('https://login.live.com/', {waitUntil: 'networkidle2'});
        await page.waitForSelector('input[type="email"]', {timeout: 5000});
        await page.type('input[type="email"]', email);
        await page.keyboard.press('Enter');
        
        await new Promise(r => setTimeout(r, 4000));
        
        // Search in all frames
        let clicked = false;
        for (const frame of page.frames()) {
            try {
                const elements = await frame.$$('a, span, div[role="button"], button');
                for (const el of elements) {
                    const text = await frame.evaluate(e => e.innerText, el);
                    if (text) {
                        const lowerText = text.trim().toLowerCase();
                        if (lowerText === 'use sua senha' || lowerText === 'usar senha em vez disso' || lowerText === 'use password instead' || lowerText.includes('senha em vez disso') || lowerText.includes('use sua senha')) {
                            await el.click();
                            console.log("Clicked in frame: " + frame.name());
                            clicked = true;
                            break;
                        }
                    }
                }
                if (clicked) break;
            } catch (e) {}
        }
        
        await new Promise(r => setTimeout(r, 4000));
        
        let hasPassword = false;
        for (const frame of page.frames()) {
            try {
                let el = await frame.$('input[type="password"]');
                if (el) {
                    hasPassword = true;
                    await frame.type('input[type="password"]', password);
                    await frame.evaluate(() => {
                        let btn = document.querySelector('input[type="submit"], button[type="submit"]');
                        if (btn) btn.click();
                    });
                    break;
                }
            } catch (e) {}
        }
        
        if (!hasPassword) {
            console.log("No password field, quitting test.");
            await browser.close();
            return;
        }
        
        await new Promise(r => setTimeout(r, 4000));
        
        // check pwdError
        let pwdError = '';
        for (const frame of page.frames()) {
            try {
                const err = await frame.evaluate(() => {
                    const el = document.querySelector('#passwordError');
                    if (el && el.innerText) return el.innerText;
                    const alert = document.querySelector('div[role="alert"]');
                    if (alert) return alert.innerText;
                    return '';
                });
                if (err) {
                    pwdError = err;
                    break;
                }
            } catch (e) {}
        }
        
        console.log("PWD Error: " + pwdError);

    } catch (err) {
        console.log("Error: " + err.message);
    } finally {
        await browser.close();
    }
})();
