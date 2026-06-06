import crypto from 'crypto';

const SESSION_SECRET = process.env.SESSION_SECRET || 'very_secret_key_change_me';
const BOT_TOKEN = process.env.BOT_TOKEN;
const ADMIN_ID = parseInt(process.env.ADMIN_ID || '287265398');

// Хранилище заявок в памяти (при перезапуске теряется)
let requests = []; // каждый элемент: { id, userId, userName, text, status, createdAt }

function verifySession(token) {
    if (!token) return null;
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

// Отправка уведомления админу в Telegram
async function notifyAdmin(request) {
    if (!BOT_TOKEN) return;
    const text = `📬 Новая заявка от ${request.userName || request.userId}:\n${request.text}\nID: ${request.id}`;
    const url = `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`;
    await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: ADMIN_ID, text })
    }).catch(e => console.error('Не удалось отправить уведомление', e));
}

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,OPTIONS');
    if (req.method === 'OPTIONS') return res.status(200).end();

    const sessionToken = req.cookies?.session;
    const session = verifySession(sessionToken);
    if (!session) return res.status(401).json({ error: 'Не авторизован' });
    
    const { userId, isAdmin, firstName } = session;
    
    // GET: получение списка заявок
    if (req.method === 'GET') {
        const { my, admin } = req.query;
        if (my === 'true') {
            const userRequests = requests.filter(r => r.userId === userId);
            return res.json({ requests: userRequests });
        }
        if (admin === 'true' && isAdmin) {
            return res.json({ requests });
        }
        return res.status(403).json({ error: 'Доступ запрещён' });
    }
    
    // POST: создание новой заявки
    if (req.method === 'POST') {
        if (isAdmin) return res.status(403).json({ error: 'Администраторы не могут создавать заявки' });
        const { text } = req.body;
        if (!text || text.trim().length < 5) return res.status(400).json({ error: 'Текст слишком короткий' });
        const newRequest = {
            id: Date.now().toString() + Math.random().toString(36).substr(2, 6),
            userId,
            userName: firstName,
            text: text.trim(),
            status: 'pending',
            createdAt: new Date().toISOString()
        };
        requests.unshift(newRequest);
        await notifyAdmin(newRequest);
        return res.json({ success: true, requestId: newRequest.id });
    }
    
    // PUT: выполнить заявку (только админ)
    if (req.method === 'PUT') {
        if (!isAdmin) return res.status(403).json({ error: 'Только админ' });
        const { requestId, action } = req.body;
        if (action !== 'complete') return res.status(400).json({ error: 'Неизвестное действие' });
        const reqIndex = requests.findIndex(r => r.id === requestId);
        if (reqIndex === -1) return res.status(404).json({ error: 'Заявка не найдена' });
        requests[reqIndex].status = 'completed';
        return res.json({ success: true });
    }
    
    res.status(405).json({ error: 'Method not allowed' });
}