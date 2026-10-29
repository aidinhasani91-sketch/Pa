import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT || 3000);
const API_VERSION = (process.env.META_API_VERSION || 'v26.0').replace(/^v?/, 'v');
const DATA_DIR = path.join(__dirname, 'data');
const ACCOUNT_FILE = path.join(DATA_DIR, 'instagram-account.json');
fs.mkdirSync(DATA_DIR, { recursive: true });

if (process.env.NODE_ENV === 'production') app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null
    }
  }
}));
app.use(session({
  name: 'instasmart.sid',
  secret: process.env.SESSION_SECRET || 'local-development-only-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 10 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: 'draft-7', legacyHeaders: false });
app.use(['/auth/instagram', '/auth/instagram/callback'], authLimiter);

function requiredEnv(...names) {
  return names.filter((name) => !process.env[name] || process.env[name].startsWith('put-your-') || process.env[name].startsWith('replace-with-'));
}
function baseUrl() { return (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, ''); }
function redirectUri() { return `${baseUrl()}/auth/instagram/callback`; }
function keyBytes() {
  const value = process.env.TOKEN_ENCRYPTION_KEY || '';
  if (!/^[a-fA-F0-9]{64}$/.test(value)) throw new Error('TOKEN_ENCRYPTION_KEY باید دقیقاً ۶۴ رقم هگزادسیمال باشد.');
  return Buffer.from(value, 'hex');
}
function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', keyBytes(), iv);
  const ciphertext = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return { iv: iv.toString('hex'), tag: cipher.getAuthTag().toString('hex'), data: ciphertext.toString('hex') };
}
function decrypt(obj) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', keyBytes(), Buffer.from(obj.iv, 'hex'));
  decipher.setAuthTag(Buffer.from(obj.tag, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(obj.data, 'hex')), decipher.final()]).toString('utf8');
}
function readAccount() {
  try {
    const raw = JSON.parse(fs.readFileSync(ACCOUNT_FILE, 'utf8'));
    return { ...raw.public, accessToken: decrypt(raw.secret) };
  } catch { return null; }
}
function writeAccount(account) {
  const { accessToken, ...publicData } = account;
  const saved = { public: publicData, secret: encrypt(accessToken) };
  const temp = `${ACCOUNT_FILE}.tmp`;
  fs.writeFileSync(temp, JSON.stringify(saved, null, 2), { mode: 0o600 });
  fs.renameSync(temp, ACCOUNT_FILE);
  try { fs.chmodSync(ACCOUNT_FILE, 0o600); } catch {}
}
async function fetchJson(url, options = {}) {
  const response = await fetch(url, { ...options, signal: AbortSignal.timeout(15000) });
  const body = await response.json().catch(() => ({}));
  if (!response.ok || body.error) {
    const message = body?.error?.message || body?.error_description || `Meta API returned HTTP ${response.status}`;
    throw new Error(message);
  }
  return body;
}
async function subscribeToMessages(account) {
  const url = new URL(`https://graph.instagram.com/${API_VERSION}/${encodeURIComponent(account.userId)}/subscribed_apps`);
  url.searchParams.set('subscribed_fields', 'messages');
  url.searchParams.set('access_token', account.accessToken);
  return fetchJson(url, { method: 'POST' });
}
function safeEqual(a, b) {
  const aa = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

app.get('/health', (_req, res) => res.json({ ok: true, service: 'instasmart' }));
app.get('/api/status', (_req, res) => {
  const account = readAccount();
  res.set('Cache-Control', 'no-store');
  res.json({ connected: Boolean(account), username: account?.username || null, webhookSubscribed: account?.webhookSubscribed ?? false });
});

app.get('/auth/instagram', (req, res) => {
  const missing = requiredEnv('META_APP_ID', 'META_APP_SECRET', 'BASE_URL', 'SESSION_SECRET', 'TOKEN_ENCRYPTION_KEY');
  if (missing.length) return res.status(503).type('text').send(`اتصال هنوز تنظیم نشده است. متغیرهای زیر را در فایل .env تکمیل کنید: ${missing.join(', ')}`);
  if (!baseUrl().startsWith('https://') && process.env.NODE_ENV === 'production') return res.status(400).send('BASE_URL باید HTTPS باشد.');
  const state = crypto.randomBytes(32).toString('hex');
  req.session.oauthState = state;
  req.session.oauthStartedAt = Date.now();
  req.session.save((err) => {
    if (err) return res.status(500).send('ذخیره وضعیت ورود ناموفق بود.');
    const url = new URL('https://www.instagram.com/oauth/authorize');
    url.searchParams.set('client_id', process.env.META_APP_ID);
    url.searchParams.set('redirect_uri', redirectUri());
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', 'instagram_business_basic,instagram_business_manage_messages');
    url.searchParams.set('state', state);
    url.searchParams.set('enable_fb_login', '0');
    url.searchParams.set('force_authentication', '1');
    res.redirect(url.toString());
  });
});

app.get('/auth/instagram/callback', async (req, res) => {
  const { code, state, error, error_description: errorDescription } = req.query;
  if (error) return res.status(400).type('text').send(`ورود توسط کاربر لغو یا رد شد: ${String(errorDescription || error).slice(0, 300)}`);
  if (!code || !state || !req.session.oauthState || !safeEqual(state, req.session.oauthState) || Date.now() - (req.session.oauthStartedAt || 0) > 10 * 60 * 1000) {
    return res.status(400).type('text').send('درخواست ورود معتبر نیست یا منقضی شده است. از سایت دوباره اتصال را آغاز کنید.');
  }
  delete req.session.oauthState;
  delete req.session.oauthStartedAt;
  try {
    const form = new URLSearchParams({
      client_id: process.env.META_APP_ID,
      client_secret: process.env.META_APP_SECRET,
      grant_type: 'authorization_code',
      redirect_uri: redirectUri(),
      code: String(code)
    });
    const short = await fetchJson('https://api.instagram.com/oauth/access_token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form.toString()
    });
    if (!short.access_token) throw new Error('Meta توکن دسترسی برنگرداند.');
    let token = short.access_token;
    let expiresIn = Number(short.expires_in || 3600);
    try {
      const longUrl = new URL('https://graph.instagram.com/access_token');
      longUrl.searchParams.set('grant_type', 'ig_exchange_token');
      longUrl.searchParams.set('client_secret', process.env.META_APP_SECRET);
      longUrl.searchParams.set('access_token', token);
      const long = await fetchJson(longUrl.toString());
      if (long.access_token) token = long.access_token;
      expiresIn = Number(long.expires_in || expiresIn);
    } catch (e) {
      console.error('Long-lived token exchange failed:', e.message);
      throw new Error('تبدیل توکن به توکن بلندمدت ناموفق بود؛ تنظیمات اپ متا را بررسی کنید.');
    }
    const profileUrl = new URL(`https://graph.instagram.com/${API_VERSION}/me`);
    profileUrl.searchParams.set('fields', 'user_id,username');
    profileUrl.searchParams.set('access_token', token);
    const profile = await fetchJson(profileUrl.toString());
    const account = {
      userId: String(profile.user_id || profile.id || short.user_id || ''),
      username: String(profile.username || 'Instagram'),
      accessToken: token,
      connectedAt: new Date().toISOString(),
      tokenExpiresAt: new Date(Date.now() + expiresIn * 1000).toISOString(),
      webhookSubscribed: false
    };
    if (!account.userId) throw new Error('شناسه حساب اینستاگرام از متا دریافت نشد.');
    try {
      await subscribeToMessages(account);
      account.webhookSubscribed = true;
    } catch (e) {
      console.error('Meta webhook subscription failed:', e.message);
    }
    writeAccount(account);
    res.redirect('/?instagram=connected');
  } catch (e) {
    console.error('Instagram OAuth callback failed:', e.message);
    res.status(500).type('text').send('اتصال کامل نشد. تنظیمات App ID، App Secret، Redirect URI و مجوزهای متا را بررسی کنید. جزئیات حساس در مرورگر نمایش داده نمی‌شوند.');
  }
});

// Instagram verifies the callback URL with this GET request.
app.get('/webhooks/instagram', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];
  if (mode === 'subscribe' && safeEqual(token, process.env.WEBHOOK_VERIFY_TOKEN)) return res.status(200).send(String(challenge || ''));
  return res.sendStatus(403);
});

// Must keep the raw body to validate Meta's X-Hub-Signature-256 header.
app.post('/webhooks/instagram', express.raw({ type: 'application/json', limit: '1mb' }), (req, res) => {
  const appSecret = process.env.META_APP_SECRET;
  if (!appSecret || !Buffer.isBuffer(req.body)) return res.sendStatus(401);
  const signature = req.get('x-hub-signature-256') || '';
  const expected = `sha256=${crypto.createHmac('sha256', appSecret).update(req.body).digest('hex')}`;
  if (!safeEqual(signature, expected)) return res.sendStatus(401);
  let payload;
  try { payload = JSON.parse(req.body.toString('utf8')); } catch { return res.sendStatus(400); }
  // Acknowledge quickly; process the webhook after returning 200 to Meta.
  res.sendStatus(200);
  void processWebhook(payload).catch((e) => console.error('Webhook processing error:', e.message));
});

const seenMessageIds = new Map();
async function processWebhook(payload) {
  if (payload.object !== 'instagram' || !Array.isArray(payload.entry)) return;
  const account = readAccount();
  if (!account) return;
  for (const entry of payload.entry) {
    for (const event of (entry.messaging || [])) {
      const message = event.message;
      const senderId = event.sender?.id;
      const recipientId = event.recipient?.id;
      if (!message?.text || !senderId || message.is_echo || String(senderId) === String(account.userId)) continue;
      if (recipientId && String(recipientId) !== String(account.userId) && String(entry.id) !== String(account.userId)) continue;
      if (message.mid && seenMessageIds.has(message.mid)) continue;
      if (message.mid) {
        seenMessageIds.set(message.mid, Date.now());
        if (seenMessageIds.size > 5000) {
          for (const [id, when] of seenMessageIds) if (Date.now() - when > 24 * 60 * 60 * 1000) seenMessageIds.delete(id);
        }
      }
      const reply = await makeReply(message.text);
      if (reply) await sendInstagramMessage(account, String(senderId), reply);
    }
  }
}
async function makeReply(incomingText) {
  const businessName = process.env.BUSINESS_NAME || 'کسب‌وکار';
  const knowledge = process.env.BUSINESS_KNOWLEDGE || 'اطلاعات تأییدشده کسب‌وکار هنوز تنظیم نشده است.';
  if (process.env.OPENAI_API_KEY) {
    try {
      const response = await fetchJson('https://api.openai.com/v1/responses', {
        method: 'POST',
        headers: { Authorization: `Bearer ${process.env.OPENAI_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: process.env.OPENAI_MODEL || 'gpt-4.1-mini',
          instructions: `تو دستیار دایرکت اینستاگرام ${businessName} هستی. به زبان پیام و با لحنی کوتاه و دوستانه پاسخ بده. از اطلاعات زیر استفاده کن و هرگز قیمت، موجودی، ضمانت یا قولی را جعل نکن. اگر پاسخ در اطلاعات نیست، سؤال روشن‌کننده بپرس یا بگو اپراتور انسانی پیگیری می‌کند. شفاف باش که پاسخ خودکار است. از ارسال تبلیغ ناخواسته یا درخواست اطلاعات حساس خودداری کن.\nاطلاعات تأییدشده کسب‌وکار:\n${knowledge}`,
          input: String(incomingText).slice(0, 4000),
          max_output_tokens: 250
        })
      });
      const text = (response.output || []).flatMap((item) => item.content || []).filter((item) => item.type === 'output_text').map((item) => item.text).join('\n').trim();
      if (text) return text.slice(0, 1000);
    } catch (e) { console.error('AI reply generation failed; using fallback:', e.message); }
  }
  const text = String(incomingText).toLowerCase();
  if (/قیمت|چنده|هزینه|price|cost/.test(text)) return `سلام! من دستیار خودکار ${businessName} هستم 🌷 برای اعلام قیمت دقیق، لطفاً نام یا لینک محصول را بفرستید تا تیم ما بررسی کند.`;
  if (/سفارش|پیگیری|ارسال|order|tracking|shipping/.test(text)) return `سلام! من دستیار خودکار ${businessName} هستم 🌷 برای پیگیری سفارش، لطفاً فقط شماره سفارش را ارسال کنید؛ اطلاعات بانکی یا رمز عبور نفرستید.`;
  if (/ساعت|باز|آدرس|ساعات کاری|opening|hours|address/.test(text)) return `سلام! من دستیار خودکار ${businessName} هستم. اطلاعات ساعات کاری و آدرس باید در تنظیمات کسب‌وکار ثبت شود؛ در صورت نیاز همکاران ما پیگیری می‌کنند.`;
  return `سلام! من دستیار خودکار ${businessName} هستم 🌷 ممنون از پیامتان. لطفاً کمی دقیق‌تر بفرمایید چه اطلاعاتی نیاز دارید تا راهنمایی‌تان کنیم.`;
}
async function sendInstagramMessage(account, recipientId, text) {
  const url = new URL(`https://graph.instagram.com/${API_VERSION}/${encodeURIComponent(account.userId)}/messages`);
  url.searchParams.set('access_token', account.accessToken);
  return fetchJson(url.toString(), {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ recipient: { id: recipientId }, message: { text } })
  });
}

app.use((err, _req, res, _next) => {
  console.error('Server error:', err?.message || 'unknown error');
  res.status(500).json({ error: 'خطای داخلی سرور رخ داد.' });
});

app.listen(PORT, () => {
  console.log(`InstaSmart running on port ${PORT}`);
  console.log(`Local URL: http://localhost:${PORT}`);
  if (process.env.NODE_ENV === 'production' && requiredEnv('META_APP_ID', 'META_APP_SECRET', 'BASE_URL', 'SESSION_SECRET', 'TOKEN_ENCRYPTION_KEY', 'WEBHOOK_VERIFY_TOKEN').length) {
    console.warn('WARNING: Configure all required Meta and encryption environment variables before enabling connection.');
  }
});
