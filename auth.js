import {DatabaseSync} from 'node:sqlite';
import {randomBytes,scryptSync,timingSafeEqual,createHash} from 'node:crypto';
const db=new DatabaseSync(process.env.DB_PATH||'./poker.sqlite');
db.exec(`CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,nick TEXT NOT NULL,hash TEXT NOT NULL,created_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL,expires INTEGER NOT NULL);`);
const hashToken=t=>createHash('sha256').update(t).digest('hex');
function passwordHash(p){const salt=randomBytes(16).toString('hex');return salt+':'+scryptSync(p,salt,64).toString('hex')}
function checkPassword(p,h){const [salt,hex]=h.split(':');const actual=scryptSync(p,salt,64);const expected=Buffer.from(hex,'hex');return actual.length===expected.length&&timingSafeEqual(actual,expected)}
export function register(email,nick,password){email=String(email||'').trim().toLowerCase();nick=String(nick||'').trim().slice(0,30);if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||nick.length<2||typeof password!=='string'||password.length<10||password.length>128)throw Error('Укажите email, ник от 2 символов и пароль от 10 символов');const id=randomBytes(16).toString('hex');try{db.prepare('INSERT INTO users VALUES(?,?,?,?,?)').run(id,email,nick,passwordHash(password),Date.now())}catch{throw Error('Email уже зарегистрирован')}return {id,nick,email}}
export function login(email,password){const u=db.prepare('SELECT * FROM users WHERE email=?').get(String(email||'').trim().toLowerCase());if(!u||typeof password!=='string'||!checkPassword(password,u.hash))throw Error('Неверный email или пароль');return {id:u.id,nick:u.nick,email:u.email}}
export function newSession(user){const token=randomBytes(32).toString('base64url');db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(hashToken(token),user.id,Date.now()+30*86400000);return token}
export function getUser(token){if(!token)return null;return db.prepare('SELECT u.id,u.email,u.nick FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires>?').get(hashToken(token),Date.now())||null}
export function logout(token){if(token)db.prepare('DELETE FROM sessions WHERE token_hash=?').run(hashToken(token))}
