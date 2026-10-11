'use strict';
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const { createClient } = require('@libsql/client');

const required = ['TURSO_DATABASE_URL','TURSO_AUTH_TOKEN','ADMIN_USERNAME','ADMIN_PASSWORD','SESSION_SECRET'];
const missing = required.filter(k => !process.env[k]);
if (missing.length) { console.error('Missing required environment variables:', missing.join(', ')); process.exit(1); }
if (process.env.SESSION_SECRET.length < 32) { console.error('SESSION_SECRET must be at least 32 characters.'); process.exit(1); }
const db = createClient({ url: process.env.TURSO_DATABASE_URL, authToken: process.env.TURSO_AUTH_TOKEN });
const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '30kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(session({ name:'portal.sid', secret:process.env.SESSION_SECRET, resave:false, saveUninitialized:false, cookie:{httpOnly:true, secure:process.env.NODE_ENV==='production', sameSite:'lax', maxAge:8*60*60*1000} }));
app.use('/api/login', rateLimit({windowMs:15*60*1000, limit:20, standardHeaders:true, legacyHeaders:false}));
app.use('/api/signup', rateLimit({windowMs:60*60*1000, limit:10, standardHeaders:true, legacyHeaders:false}));

async function init(){
 const statements = [
 `CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, name TEXT NOT NULL, mobile TEXT NOT NULL, email TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, last_login TEXT)`,
 `CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
 `CREATE TABLE IF NOT EXISTS user_links (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, token_hash TEXT NOT NULL UNIQUE, label TEXT NOT NULL DEFAULT 'Personal link', target_url TEXT NOT NULL, expires_at TEXT, revoked INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
 `CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, event TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`
 ];
 for (const sql of statements) await db.execute(sql);
 for (const [key,value] of [['maintenance_mode','off'],['redirect_url','https://example.com'],['broadcast_message','']]) await db.execute({sql:'INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)',args:[key,value]});
}
const sha = v => crypto.createHash('sha256').update(v).digest('hex');
const validUrl = s => { try { const u = new URL(s); return ['https:','http:'].includes(u.protocol); } catch { return false; } };
async function setting(key, fallback=''){ const r=await db.execute({sql:'SELECT value FROM settings WHERE key=?',args:[key]}); return r.rows[0]?.value ?? fallback; }
async function setSetting(key,value){ await db.execute({sql:'INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',args:[key,String(value)]}); }
function adminOnly(req,res,next){ if(!req.session?.isAdmin) return res.status(401).json({success:false,message:'Admin login required'}); next(); }
function userOnly(req,res,next){ if(!req.session?.userId) return res.status(401).json({success:false,message:'Please login first'}); next(); }
async function telegramSignup(name,mobile,username){
 const token=process.env.TELEGRAM_BOT_TOKEN, chat=process.env.TELEGRAM_CHAT_ID; if(!token||!chat) return;
 const text=`New registration\nName: ${name}\nMobile: ${mobile}\nUsername: ${username}`;
 try { await fetch(`https://api.telegram.org/bot${token}/sendMessage`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({chat_id:chat,text})}); } catch(e){ console.error('Telegram notification failed:',e.message); }
}
app.get('/healthz',(req,res)=>res.json({ok:true}));
app.get('/api/get-maintenance',async(req,res)=>res.json({maintenance:(await setting('maintenance_mode','off'))==='on'}));
app.get('/api/get-link',async(req,res)=>res.json({url:await setting('redirect_url','https://example.com'),broadcast:await setting('broadcast_message','')}));
app.post('/api/signup',async(req,res)=>{
 try {
  const name=String(req.body.name||'').trim(), mobile=String(req.body.mobile||'').trim(), username=String(req.body.username||'').trim(), password=String(req.body.password||'');
  if(!name||!mobile||!username||password.length<10) return res.status(400).json({success:false,status:'missing',message:'Name, mobile, username भरें; password कम से कम 10 characters का हो।'});
  if(!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) return res.status(400).json({success:false,status:'invalid',message:'Username 3–32 characters; letters, numbers, _ . - only.'});
  const hash=await bcrypt.hash(password,12);
  await db.execute({sql:'INSERT INTO users(username,password_hash,name,mobile,email,status) VALUES(?,?,?,?,?,?)',args:[username,hash,name,mobile,String(req.body.email||'').trim(),'pending']});
  await telegramSignup(name,mobile,username); return res.json({success:true,status:'pending',message:'Registration successful. Admin approval pending.'});
 } catch(e){ if(String(e.message).includes('UNIQUE')) return res.status(409).json({success:false,status:'exists',message:'Username already exists.'}); console.error(e); return res.status(500).json({success:false,message:'Registration failed.'}); }
});
app.post('/api/login',async(req,res)=>{
 try {
  if(await setting('maintenance_mode','off')==='on') return res.status(503).json({success:false,status:'maintenance',message:'Maintenance mode is on.'});
  const username=String(req.body.username||'').trim(), password=String(req.body.password||'');
  const r=await db.execute({sql:'SELECT id,username,password_hash,status,name FROM users WHERE username=?',args:[username]}); const u=r.rows[0];
  if(!u || !(await bcrypt.compare(password,u.password_hash))) return res.status(401).json({success:false,status:'invalid',message:'Invalid username or password.'});
  if(u.status==='pending') return res.status(403).json({success:false,status:'pending',message:'Admin approval pending.'});
  if(u.status==='blocked') return res.status(403).json({success:false,status:'blocked',message:'Account is blocked. Contact admin.'});
  req.session.userId=Number(u.id); req.session.username=u.username;
  await db.execute({sql:'UPDATE users SET last_login=CURRENT_TIMESTAMP WHERE id=?',args:[u.id]});
  await db.execute({sql:'INSERT INTO audit_log(user_id,event) VALUES(?,?)',args:[u.id,'login']});
  res.json({success:true,status:'success',user:{id:Number(u.id),username:u.username,name:u.name}});
 } catch(e){ console.error(e); res.status(500).json({success:false,message:'Login failed.'}); }
});
app.post('/api/logout',(req,res)=>req.session.destroy(()=>res.json({success:true})));
app.get('/api/me',userOnly,async(req,res)=>{ const r=await db.execute({sql:'SELECT id,username,name,status,created_at,last_login FROM users WHERE id=?',args:[req.session.userId]}); if(!r.rows[0]||r.rows[0].status!=='active'){req.session.destroy(()=>{});return res.status(403).json({success:false,message:'Account is not active'});} res.json({success:true,user:r.rows[0]}); });
app.get('/api/my-links',userOnly,async(req,res)=>{ const r=await db.execute({sql:'SELECT id,label,target_url,expires_at,created_at FROM user_links WHERE user_id=? AND revoked=0 ORDER BY id DESC',args:[req.session.userId]}); res.json(r.rows); });
app.get('/u/:token',async(req,res)=>{
 try { const r=await db.execute({sql:`SELECT l.target_url,l.expires_at,l.revoked,u.status FROM user_links l JOIN users u ON u.id=l.user_id WHERE l.token_hash=?`,args:[sha(req.params.token)]}); const l=r.rows[0];
  if(!l||l.revoked||l.status!=='active'||(l.expires_at&&new Date(l.expires_at)<new Date())) return res.status(404).send('This link is invalid, expired, revoked, or its account is inactive.');
  res.redirect(302,l.target_url);
 } catch(e){console.error(e);res.status(500).send('Unable to open link.');}
});
app.get('/admin', (req,res)=>res.sendFile(path.join(__dirname,'public','admin.html')));
app.post('/api/admin/login',rateLimit({windowMs:15*60*1000,limit:10}), (req,res)=>{
 const u=String(req.body.username||''), p=String(req.body.password||'');
 const a=Buffer.from(u), b=Buffer.from(process.env.ADMIN_USERNAME); const c=Buffer.from(p), d=Buffer.from(process.env.ADMIN_PASSWORD);
 const safeEq=(x,y)=>x.length===y.length&&crypto.timingSafeEqual(x,y);
 if(!safeEq(a,b)||!safeEq(c,d)) return res.status(401).json({success:false,message:'Invalid admin credentials'});
 req.session.regenerate(err=>{if(err)return res.status(500).json({success:false});req.session.isAdmin=true;res.json({success:true});});
});
app.get('/api/admin/session',(req,res)=>res.json({authenticated:!!req.session?.isAdmin}));
app.post('/api/admin/logout',adminOnly,(req,res)=>req.session.destroy(()=>res.json({success:true})));
app.get('/api/admin/stats',adminOnly,async(req,res)=>{const r=await db.execute(`SELECT COUNT(*) total, SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) pending, SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) active, SUM(CASE WHEN status='blocked' THEN 1 ELSE 0 END) blocked FROM users`);res.json(r.rows[0]||{total:0,pending:0,active:0,blocked:0});});
app.get('/api/admin/get-users',adminOnly,async(req,res)=>{const r=await db.execute('SELECT id,username,name,mobile,email,status,created_at,last_login FROM users ORDER BY id DESC');res.json(r.rows);});
app.post('/api/admin/update-status',adminOnly,async(req,res)=>{const id=Number(req.body.id),status=String(req.body.status||'');if(!Number.isInteger(id)||!['pending','active','blocked'].includes(status))return res.status(400).json({success:false,message:'Invalid id/status'});await db.execute({sql:'UPDATE users SET status=? WHERE id=?',args:[status,id]});res.json({success:true,message:'User status updated'});});
app.post('/api/admin/create-user',adminOnly,async(req,res)=>{try{const {name,mobile,email,username,password}=req.body;if(!name||!mobile||!username||!password||String(password).length<10)return res.status(400).json({success:false,message:'Name, mobile, username and password (10+ chars) required'});const hash=await bcrypt.hash(String(password),12);await db.execute({sql:"INSERT INTO users(username,password_hash,name,mobile,email,status) VALUES(?,?,?,?,?,'active')",args:[String(username).trim(),hash,String(name).trim(),String(mobile).trim(),String(email||'').trim()]});res.json({success:true,message:'Active user created'});}catch(e){res.status(409).json({success:false,message:'Could not create user; username may already exist.'});}});
app.get('/api/admin/settings',adminOnly,async(req,res)=>res.json({maintenance:(await setting('maintenance_mode','off'))==='on',url:await setting('redirect_url','https://example.com'),broadcast:await setting('broadcast_message','')}));
app.post('/api/admin/maintenance',adminOnly,async(req,res)=>{const enabled=!!req.body.enabled;await setSetting('maintenance_mode',enabled?'on':'off');res.json({success:true,enabled});});
app.post('/api/admin/settings',adminOnly,async(req,res)=>{const url=String(req.body.url||'').trim(),broadcast=String(req.body.broadcast||'').trim();if(url&&!validUrl(url))return res.status(400).json({success:false,message:'A valid http/https URL is required'});if(url)await setSetting('redirect_url',url);await setSetting('broadcast_message',broadcast.slice(0,1000));res.json({success:true});});
app.post('/api/admin/user-links',adminOnly,async(req,res)=>{
 try {const userId=Number(req.body.userId),label=String(req.body.label||'Personal link').trim().slice(0,80),target=String(req.body.targetUrl||'').trim(),days=Number(req.body.expiresInDays||0);if(!Number.isInteger(userId)||!validUrl(target))return res.status(400).json({success:false,message:'Valid user and http/https target URL required'});if(days<0||days>3650)return res.status(400).json({success:false,message:'Expiry must be 0–3650 days'});const u=await db.execute({sql:'SELECT id FROM users WHERE id=?',args:[userId]});if(!u.rows.length)return res.status(404).json({success:false,message:'User not found'});const token=crypto.randomBytes(32).toString('base64url'),expires=days?new Date(Date.now()+days*86400000).toISOString():null;await db.execute({sql:'INSERT INTO user_links(user_id,token_hash,label,target_url,expires_at) VALUES(?,?,?,?,?)',args:[userId,sha(token),label,target,expires]});const base=(process.env.APP_BASE_URL||'').replace(/\/$/,'');res.json({success:true,url:`${base}/u/${token}`,expiresAt:expires});}catch(e){console.error(e);res.status(500).json({success:false,message:'Could not create link'});}
});
app.get('/api/admin/user-links/:id',adminOnly,async(req,res)=>{const r=await db.execute({sql:'SELECT id,label,target_url,expires_at,revoked,created_at FROM user_links WHERE user_id=? ORDER BY id DESC',args:[Number(req.params.id)]});res.json(r.rows);});
app.post('/api/admin/revoke-link',adminOnly,async(req,res)=>{await db.execute({sql:'UPDATE user_links SET revoked=1 WHERE id=?',args:[Number(req.body.id)]});res.json({success:true});});
app.get('/api/admin/audit',adminOnly,async(req,res)=>{const r=await db.execute('SELECT a.id,a.user_id,u.username,a.event,a.created_at FROM audit_log a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 200');res.json(r.rows);});
app.use(express.static(path.join(__dirname,'public')));
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({success:false,message:'Internal server error'});});
const port=Number(process.env.PORT||10000);
init().then(()=>app.listen(port,'0.0.0.0',()=>console.log(`Portal listening on ${port}`))).catch(e=>{console.error('Database init failed:',e);process.exit(1)});
