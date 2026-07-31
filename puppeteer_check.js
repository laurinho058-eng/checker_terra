const puppeteer = require('puppeteer');

(async () => {
    const email = process.argv[2];
    const password = process.argv[3];
    const proxyStr = process.argv[4] || '';
    
    if (!email || !password) {
        console.log(JSON.stringify({status: 'die', reason: 'Missing credentials'}));
        process.exit(1);
    }

    let puppeteerArgs = ['--no-sandbox', '--disable-setuid-sandbox', '--disable-blink-features=AutomationControlled'];
    let proxyHost = '', proxyPort = '', proxyUser = '', proxyPass = '';
    
    if (proxyStr) {
        // Parse proxy: user:pass@host:port or host:port
        const proxyUrl = proxyStr.replace('http://', '').replace('https://', '');
        if (proxyUrl.includes('@')) {
            const parts = proxyUrl.split('@');
            const auth = parts[0].split(':');
            const hostPort = parts[1].split(':');
            proxyUser = auth[0];
            proxyPass = auth[1];
            proxyHost = hostPort[0];
            proxyPort = hostPort[1];
            puppeteerArgs.push(`--proxy-server=http://${proxyHost}:${proxyPort}`);
        } else {
            puppeteerArgs.push(`--proxy-server=http://${proxyUrl}`);
        }
    }

    let launchOptions = {
        headless: 'new',
        args: puppeteerArgs
    };
    
    // Check if system chromium exists (Linux/Docker/Render)
    const fs = require('fs');
    if (fs.existsSync('/usr/bin/chromium')) {
        launchOptions.executablePath = '/usr/bin/chromium';
    }

    const browser = await puppeteer.launch(launchOptions);
    
    try {
        const page = await browser.newPage();
        
        if (proxyUser && proxyPass) {
            await page.authenticate({ username: proxyUser, password: proxyPass });
        }
        
        await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36');
        
        await page.goto('https://login.live.com/', {waitUntil: 'networkidle2'});
        
        await page.waitForSelector('input[type="email"]', {timeout: 5000});
        await page.type('input[type="email"]', email);
        await page.keyboard.press('Enter');
        
        await new Promise(r => setTimeout(r, 4000));
        
        const userError = await page.evaluate(() => {
            const el = document.querySelector('#usernameError');
            return el ? el.innerText : '';
        });
        if (userError) {
            console.log(JSON.stringify({status: 'die', reason: 'Does Not Exist'}));
            process.exit(0);
        }
        
        const passwordInputSelector = 'input[type="password"]';
        let hasPassword = await page.$(passwordInputSelector).catch(() => null);
        
        if (!hasPassword) {
            await page.evaluate(() => {
                let switchBtn = document.querySelector('#idA_PWD_SwitchToPassword');
                if (switchBtn) { switchBtn.click(); }
                
                let links = document.querySelectorAll('a, span, div[role="button"], button, div');
                for (let link of links) {
                    if (!link.innerText) continue;
                    let text = link.innerText.trim().toLowerCase();
                    if (text === 'outras maneiras de entrar' || text === 'other ways to sign in' || text === 'usar senha em vez disso' || text === 'use password instead' || text.includes('senha em vez disso') || text.includes('password instead') || text.includes('use sua senha') || text.includes('use your password') || text === 'use sua senha') {
                        link.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, cancelable: true, view: window }));
                        link.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, cancelable: true, view: window }));
                        link.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, view: window }));
                        link.click();
                    }
                }
            });
            
            await new Promise(r => setTimeout(r, 3000));
            
            let hasPwd2 = await page.$(passwordInputSelector).catch(() => null);
            if (!hasPwd2) {
                await page.evaluate(() => {
                    let tiles = document.querySelectorAll('div[data-testid="tile"], div[role="button"]'); 
                    for (let tile of tiles) {
                        let text = tile.innerText.toLowerCase();
                        if (text.includes('senha') || text.includes('password')) {
                            tile.click();
                            return;
                        }
                    }
                });
                await new Promise(r => setTimeout(r, 4000));
            }
        }
        
        await page.type(passwordInputSelector, password);
        await page.keyboard.press('Enter');
        
        await new Promise(r => setTimeout(r, 4000));
        
        const pwdError = await page.evaluate(() => {
            // Check legacy
            const el = document.querySelector('#passwordError');
            if (el && el.innerText) return el.innerText;
            const alert = document.querySelector('div[role="alert"]');
            if (alert) return alert.innerText;
            const iError = document.querySelector('#i0118Error');
            if (iError && iError.innerText) return iError.innerText;
            const anyError = document.querySelector('.alert, .error, .text-danger');
            if (anyError && anyError.innerText) return anyError.innerText;
            return '';
        });
        
        if (pwdError) {
            let reasonStr = (pwdError.includes('Rate Limited') || pwdError.includes('várias vezes') || pwdError.includes('too many')) ? 'Rate Limited' : 'Wrong Password';
            console.log(JSON.stringify({status: 'die', reason: reasonStr}));
            process.exit(0);
        }
        
        // Final check: if password field is still visible, it didn't login!
        const isStillOnLogin = await page.evaluate(() => {
            return !!document.querySelector('input[type="password"]');
        });
        
        if (isStillOnLogin) {
            console.log(JSON.stringify({status: 'die', reason: 'Wrong Password / Login failed silently'}));
            process.exit(0);
        }
        
        // If we reached here, no errors were found and we advanced past the password screen
        console.log(JSON.stringify({status: 'live'}));

    } catch (err) {
        console.log(JSON.stringify({status: 'die', reason: 'Fallback timeout / ' + err.message}));
    } finally {
        await browser.close();
    }
})();
