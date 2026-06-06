import crypto from 'crypto';

// Переменные окружения (задайте в Vercel)
const BOT_TOKEN = process.env.BOT_TOKEN;
const SESSION_SECRET = process.env.SESSION_SECRET || 'very_secret_key_change_me';
const ADMIN_ID = parseInt(process.env.ADMIN_ID || '287265398');

// Хранилище сессий в памяти (при перезапуске сбрасывается)
const sessions = new Map(); // key: sessionToken, value: { userId, isAdmin, firstName, exp }

// Вспомогательная функция для подписи данных сессии
function signSession(payload) {
    const payloadStr = JSON.stringify(payload);
    const signature = crypto.createHmac('sha256', SESSION_SECRET).update(payloadStr).digest('hex');
    return Buffer.from(payloadStr + '|' + signature).toString('base64');
}

function verifySession(token) {
    try {
        const decoded = Buffer.from(token, 'base64').toString();
        const [payloadStr, signature] = decoded.split('|');
        const expectedSig = crypto.createHmac('sha256', SESSION_SECRET).update(payloadStr).digest('hex');
        if (signature !== expectedSig) return null;
        const payload = JSON.parse(payloadStr);
        if (payload.exp && Date.now() > payload.exp) return null;
        return payload;
    } catch (e) { return null; }
}

// Проверка hash от Telegram Login Widget
function checkTelegramAuth(authData) {
    const { hash, ...data } = authData;
    const checkString = Object.keys(data)
        .sort()
        .map(key => `${key}=${data[key]}`)
        .join('\n');
    const secret = crypto.createHmac('sha256', BOT_TOKEN).update('WebAppData').digest();
    const computedHash = crypto.createHmac('sha256', secret).update(checkString).digest('hex');
    return computedHash === hash;
}

export default async function handler(req, res) {
    // CORS для удобства (можно ужесточить)
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
    if (req.method === 'OPTIONS') return res.status(200).end();

    // GET: проверка текущей сессии по cookie
    if (req.method === 'GET') {
        const sessionToken = req.cookies?.session;
        if (!sessionToken) return res.json({ authenticated: false });
        const payload = verifySession(sessionToken);
        if (!payload) {
            res.setHeader('Set-Cookie', 'session=; Max-Age=0; HttpOnly; Secure; SameSite=Strict; Path=/');
            return res.json({ authenticated: false });
        }
        return res.json({
            authenticated: true,
            userId: payload.userId,
            first_name: payload.firstName,
            isAdmin: payload.isAdmin
        });
    }
    
    // POST: вход (Telegram виджет + капча)
    if (req.method === 'POST') {
        const { tgData, captchaAnswer, captchaExpression } = req.body;
        if (!tgData || !captchaAnswer || !captchaExpression) {
            return res.status(400).json({ error: 'Не все поля' });
        }
        // Простая капча "a + b"
        const match = captchaExpression.match(/(\d+)\s*\+\s*(\d+)/);
        if (!match) return res.status(400).json({ error: 'Неверный формат капчи' });
        const expected = parseInt(match[1]) + parseInt(match[2]);
        if (parseInt(captchaAnswer) !== expected) {
            return res.status(400).json({ error: 'Капча неверна' });
        }
        // Проверка подписи Telegram
        if (!checkTelegramAuth(tgData)) {
            return res.status(401).json({ error: 'Неверная подпись Telegram' });
        }
        const userId = tgData.id.toString();
        const firstName = tgData.first_name || 'User';
        const isAdmin = (parseInt(userId) === ADMIN_ID);
        
        // Создаём сессию (срок 7 дней)
        const exp = Date.now() + 7*24*3600*1000;
        const payload = { userId, firstName, isAdmin, exp };
        const sessionToken = signSession(payload);
        res.setHeader('Set-Cookie', `session=${sessionToken}; HttpOnly; Secure; SameSite=Strict; Max-Age=${7*24*3600}; Path=/`);
        return res.json({ success: true, isAdmin });
    }
    
    // DELETE: выход
    if (req.method === 'DELETE') {
        res.setHeader('Set-Cookie', 'session=; Max-Age=0; HttpOnly; Secure; SameSite=Strict; Path=/');
        return res.json({ success: true });
    }
    
    res.status(405).json({ error: 'Method not allowed' });
}