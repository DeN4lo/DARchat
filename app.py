import sqlite3
import hashlib
import secrets
import time
import json
import os
import shutil
import random
import string
from uuid import uuid4
from typing import Dict
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

os.makedirs("uploads", exist_ok=True)
app.mount('/static', StaticFiles(directory='static'), name='static')
app.mount('/uploads', StaticFiles(directory='uploads'), name='uploads')

DB_PATH = 'chat.db'
sessions: Dict[str, dict] = {}
connections: Dict[str, list] = {} 
verification_codes: Dict[str, str] = {}

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
    CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY,
        nick TEXT UNIQUE,
        pwd_hash TEXT,
        avatar TEXT,
        status TEXT DEFAULT 'offline',
        user_code TEXT UNIQUE,
        code_rotation TEXT DEFAULT NULL,
        last_rotation INTEGER DEFAULT 0
    )
    ''')
    cur.execute('''
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT, recipient TEXT, text TEXT, msg_type TEXT DEFAULT 'text', ts INTEGER,
        reply_to_id INTEGER DEFAULT NULL
    )
    ''')
    try:
        cur.execute("ALTER TABLE messages ADD COLUMN reply_to_id INTEGER DEFAULT NULL")
    except:
        pass

    cur.execute('''
    CREATE TABLE IF NOT EXISTS blocked_users (
        blocker TEXT,
        blocked TEXT,
        PRIMARY KEY (blocker, blocked)
    )
    ''')
    conn.commit()
    conn.close()

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def generate_user_code(conn):
    while True:
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
        exists = conn.execute('SELECT 1 FROM users WHERE user_code = ?', (code,)).fetchone()
        if not exists: return code

def check_code_rotation(user_row, conn):
    rotation = user_row['code_rotation']
    last = user_row['last_rotation'] or 0
    now = int(time.time())
    interval_map = {'day': 86400, 'week': 604800, 'month': 2592000, 'year': 31536000}
    
    if rotation in interval_map and (now - last) > interval_map[rotation]:
        new_code = generate_user_code(conn)
        conn.execute('UPDATE users SET user_code = ?, last_rotation = ? WHERE email = ?', 
                     (new_code, now, user_row['email']))
        conn.commit()
        return new_code
    return user_row['user_code']

# Helper: Broadcast status change
async def broadcast_status(nick: str, status: str):
    conn = get_db_connection()
    conn.execute('UPDATE users SET status = ? WHERE nick = ?', (status, nick))
    conn.commit()
    conn.close()
    
    msg = {'type': 'status_update', 'nick': nick, 'status': status}
    for user_sockets in connections.values():
        for ws in user_sockets:
            try:
                await ws.send_json(msg)
            except:
                pass

init_db()

# ========== API ===========

@app.get('/')
async def index():
    return FileResponse('static/index.html')

@app.post('/send-code')
async def send_code(data: dict):
    email = data.get('email')
    conn = get_db_connection()
    exists = conn.execute('SELECT email FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()
    if exists: return JSONResponse({'ok': False, 'error': 'Пошта зайнята'})
    code = str(random.randint(100000, 999999))
    verification_codes[email] = code
    print(f"\n>>> EMAIL: {email} | CODE: {code} <<<\n")
    return {'ok': True}

@app.post('/verify-code')
async def verify_code(data: dict):
    if verification_codes.get(data.get('email')) == data.get('code'): return {'ok': True}
    return JSONResponse({'ok': False, 'error': 'Невірний код'})

@app.post('/complete-register')
async def complete_register(email: str = Form(...), password: str = Form(...), nick: str = Form(...), avatar: UploadFile = File(None)):
    pwd_hash = hash_password(password)
    avatar_url = "/static/default-avatar.png"
    if avatar:
        filename = f"{uuid4()}.{avatar.filename.split('.')[-1]}"
        with open(f"uploads/{filename}", "wb") as buffer: shutil.copyfileobj(avatar.file, buffer)
        avatar_url = f"/uploads/{filename}"
    conn = get_db_connection()
    new_code = generate_user_code(conn)
    try:
        conn.execute('INSERT INTO users (email, nick, pwd_hash, avatar, status, user_code, last_rotation) VALUES (?, ?, ?, ?, ?, ?, ?)', 
                     (email, nick, pwd_hash, avatar_url, 'offline', new_code, int(time.time())))
        conn.commit()
    except: return JSONResponse({'ok': False, 'error': 'Нік або пошта зайняті'})
    finally: conn.close()
    return {'ok': True, 'code': new_code}

@app.post('/login')
async def login(data: dict):
    email = data.get('email')
    pwd = data.get('password')
    conn = get_db_connection()
    row = conn.execute('SELECT nick, pwd_hash, avatar, status, user_code, code_rotation, last_rotation, email FROM users WHERE email = ?', (email,)).fetchone()
    if not row or row['pwd_hash'] != hash_password(pwd): 
        conn.close()
        return JSONResponse({'ok': False, 'error': 'Помилка входу'})
    check_code_rotation(row, conn)
    token = secrets.token_hex(16)
    sessions[token] = {'email': email, 'nick': row['nick'], 'avatar': row['avatar'], 'status': row['status']}
    conn.close()
    return {'ok': True, 'token': token, 'nick': row['nick'], 'avatar': row['avatar'], 'status': row['status']}

@app.get('/me')
async def get_me(token: str = ''):
    user = sessions.get(token)
    if not user: raise HTTPException(401)
    conn = get_db_connection()
    row = conn.execute('SELECT nick, avatar, status, user_code, code_rotation, last_rotation, email FROM users WHERE email = ?', (user['email'],)).fetchone()
    if row:
        check_code_rotation(row, conn)
        user['nick'] = row['nick']
        user['avatar'] = row['avatar']
        user['status'] = row['status']
        user['email'] = row['email'] 
    conn.close()
    return {'ok': True, 'user': user}

@app.get('/get-code')
async def get_user_code(token: str = ''):
    user = sessions.get(token)
    if not user: raise HTTPException(401)
    conn = get_db_connection()
    row = conn.execute('SELECT user_code, code_rotation FROM users WHERE email=?', (user['email'],)).fetchone()
    conn.close()
    if row: return {'ok': True, 'code': row['user_code'], 'code_rotation': row['code_rotation']}
    return {'ok': False}

@app.post('/change-code')
async def change_code(data: dict):
    token = data.get('token')
    # Ми більше не читаємо 'new_code' з data, тільки генеруємо
    user = sessions.get(token)
    if not user: raise HTTPException(401)
    
    conn = get_db_connection()
    # Завжди генеруємо новий код
    final_code = generate_user_code(conn)
    
    conn.execute('UPDATE users SET user_code = ?, last_rotation = ? WHERE email = ?', 
                 (final_code, int(time.time()), user['email']))
    conn.commit()
    conn.close()
    return {'ok': True, 'code': final_code}

@app.post('/set-status')
async def set_status_api(data: dict):
    token = data.get('token')
    status = data.get('status')
    user = sessions.get(token)
    if not user: raise HTTPException(401)
    
    valid_statuses = ['online', 'offline', 'dnd', 'invisible']
    if status not in valid_statuses: return {'ok': False}
    
    user['status'] = status # Update session
    # Якщо invisible, в БД пишемо offline, але сесія знає правду (спрощено пишемо offline всім)
    db_status = 'offline' if status == 'invisible' else status
    await broadcast_status(user['nick'], db_status)
    
    return {'ok': True}

@app.post('/update-profile')
async def update_profile(
    token: str = Form(...), 
    nick: str = Form(None), 
    password: str = Form(None),
    avatar: UploadFile = File(None)
):
    user = sessions.get(token)
    if not user: raise HTTPException(401)
    conn = get_db_connection()
    
    if nick and nick != user['nick']:
        try:
            conn.execute('UPDATE users SET nick = ? WHERE email = ?', (nick, user['email']))
            conn.execute('UPDATE messages SET sender = ? WHERE sender = ?', (nick, user['nick']))
            conn.execute('UPDATE messages SET recipient = ? WHERE recipient = ?', (nick, user['nick']))
            conn.execute('UPDATE blocked_users SET blocker = ? WHERE blocker = ?', (nick, user['nick']))
            conn.execute('UPDATE blocked_users SET blocked = ? WHERE blocked = ?', (nick, user['nick']))
            
            if user['nick'] in connections:
                connections[nick] = connections.pop(user['nick'])
            
            user['nick'] = nick
        except: return JSONResponse({'ok': False, 'error': 'Нік зайнятий'})

    if password and len(password) >= 3:
        new_hash = hash_password(password)
        conn.execute('UPDATE users SET pwd_hash = ? WHERE email = ?', (new_hash, user['email']))

    if avatar:
        filename = f"{uuid4()}.{avatar.filename.split('.')[-1]}"
        with open(f"uploads/{filename}", "wb") as buffer: shutil.copyfileobj(avatar.file, buffer)
        new_url = f"/uploads/{filename}"
        conn.execute('UPDATE users SET avatar = ? WHERE email = ?', (new_url, user['email']))
        user['avatar'] = new_url
        
    conn.commit()
    conn.close()
    return {'ok': True, 'user': user}

@app.post('/block-user')
async def block_user(data: dict):
    token = data.get('token')
    target = data.get('target_nick')
    action = data.get('action') 
    user = sessions.get(token)
    if not user: raise HTTPException(401)
    conn = get_db_connection()
    if action == 'block':
        conn.execute('INSERT OR IGNORE INTO blocked_users (blocker, blocked) VALUES (?, ?)', (user['nick'], target))
    elif action == 'unblock':
        conn.execute('DELETE FROM blocked_users WHERE blocker = ? AND blocked = ?', (user['nick'], target))
    conn.commit()
    conn.close()
    return {'ok': True}

@app.get('/chat-info')
async def chat_info(with_user: str, token: str = ''):
    user = sessions.get(token)
    if not user: raise HTTPException(401)
    conn = get_db_connection()
    i_blocked = conn.execute('SELECT 1 FROM blocked_users WHERE blocker = ? AND blocked = ?', (user['nick'], with_user)).fetchone()
    conn.close()
    return {'ok': True, 'i_blocked': bool(i_blocked), 'he_blocked': False} 

@app.get('/contacts')
async def get_contacts(token: str = ''):
    user = sessions.get(token)
    if not user: raise HTTPException(401)
    mynick = user['nick']
    conn = get_db_connection()
    sql = '''
    SELECT DISTINCT other_nick FROM (
        SELECT recipient as other_nick, ts FROM messages WHERE sender = ?
        UNION
        SELECT sender as other_nick, ts FROM messages WHERE recipient = ?
    ) ORDER BY ts DESC
    '''
    chat_partners = [r['other_nick'] for r in conn.execute(sql, (mynick, mynick)).fetchall()]
    contacts = []
    for p in chat_partners:
        row = conn.execute('SELECT avatar, status FROM users WHERE nick = ?', (p,)).fetchone()
        if row:
            contacts.append({'nick': p, 'avatar': row['avatar'], 'status': row['status']})
    conn.close()
    return {'ok': True, 'contacts': contacts}

@app.get('/search')
async def search(nick: str = '', token: str = ''):
    user = sessions.get(token)
    if not user: raise HTTPException(401)
    conn = get_db_connection()
    row = conn.execute("SELECT nick, avatar, status FROM users WHERE user_code = ?", (nick.strip(),)).fetchone()
    results = []
    if row and row['nick'] != user['nick']:
        results.append({'nick': row['nick'], 'avatar': row['avatar'], 'status': row['status']})
    conn.close()
    return {'ok': True, 'results': results}

@app.post('/delete-chat')
async def delete_chat(data: dict):
    user = sessions.get(data.get('token'))
    if not user: raise HTTPException(401)
    conn = get_db_connection()
    conn.execute('DELETE FROM messages WHERE (sender=? AND recipient=?) OR (sender=? AND recipient=?)', 
                 (user['nick'], data.get('with_user'), data.get('with_user'), user['nick']))
    conn.commit()
    conn.close()
    return {'ok': True}

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    name = f"{uuid4()}.{file.filename.split('.')[-1]}"
    with open(f"uploads/{name}", "wb") as buffer: shutil.copyfileobj(file.file, buffer)
    return {"url": f"/uploads/{name}", "filename": file.filename}

@app.get('/messages')
async def get_messages(with_user: str, token: str = ''):
    user = sessions.get(token)
    if not user: raise HTTPException(401)
    conn = get_db_connection()
    
    sql = '''
        SELECT m.id, m.sender, m.recipient, m.text, m.msg_type, m.ts, m.reply_to_id, 
               rm.text as reply_text, rm.sender as reply_sender
        FROM messages m
        LEFT JOIN messages rm ON m.reply_to_id = rm.id
        WHERE (m.sender=? AND m.recipient=?) OR (m.sender=? AND m.recipient=?) 
        ORDER BY m.ts ASC
    '''
    rows = conn.execute(sql, (user['nick'], with_user, with_user, user['nick'])).fetchall()
    
    msgs = []
    for r in rows:
        msgs.append({
            'id': r['id'],
            'from': r['sender'], 
            'text': r['text'], 
            'type': r['msg_type'], 
            'ts': r['ts'],
            'reply_to': {'text': r['reply_text'], 'sender': r['reply_sender']} if r['reply_to_id'] else None
        })
    conn.close()
    return {'ok': True, 'messages': msgs}

@app.websocket('/ws')
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    token = ws.query_params.get('token')
    user = sessions.get(token)
    
    if not user:
        await ws.close()
        return
        
    nick = user['nick']
    if nick not in connections: connections[nick] = []
    connections[nick].append(ws)
    
    # Автоматично ставимо онлайн при вході, якщо він не був у DND
    if user.get('status') != 'dnd':
        await broadcast_status(nick, 'online')

    try:
        while True:
            data = await ws.receive_text()
            try:
                obj = json.loads(data)
                to = obj.get('to')
                text = obj.get('text')
                type_ = obj.get('type', 'text')
                reply_id = obj.get('reply_to_id')

                if text and len(text) > 4096:
                    await ws.send_json({'type': 'error', 'message': 'Повідомлення занадто довге (макс 4096).'})
                    continue

                conn = get_db_connection()
                is_blocked = conn.execute('SELECT 1 FROM blocked_users WHERE blocker = ? AND blocked = ?', (to, nick)).fetchone()
                if is_blocked:
                    await ws.send_json({'type': 'error', 'message': 'Ви заблоковані цим користувачем.'})
                    conn.close()
                    continue
                
                ts = int(time.time())
                
                reply_data = None
                if reply_id:
                    rr = conn.execute('SELECT text, sender FROM messages WHERE id=?', (reply_id,)).fetchone()
                    if rr: reply_data = {'text': rr['text'], 'sender': rr['sender']}

                cur = conn.execute('INSERT INTO messages (sender, recipient, text, msg_type, ts, reply_to_id) VALUES (?, ?, ?, ?, ?, ?)', 
                             (nick, to, text, type_, ts, reply_id))
                msg_id = cur.lastrowid
                conn.commit()
                conn.close()
                
                payload = {
                    'type': 'message', 
                    'id': msg_id,
                    'msg_type': type_, 
                    'from': nick, 
                    'to': to, 
                    'text': text, 
                    'ts': ts,
                    'reply_to': reply_data
                }
                
                for s in connections.get(nick, []):
                    await s.send_json(payload)
                
                if to in connections:
                    for s in connections[to]:
                        await s.send_json(payload)
                        
            except Exception as e:
                print(f"WS Error: {e}")
                break
    except WebSocketDisconnect:
        pass
    finally:
        if nick in connections:
            if ws in connections[nick]:
                connections[nick].remove(ws)
            if not connections[nick]:
                del connections[nick]
                # Ставимо офлайн тільки якщо більше немає з'єднань
                await broadcast_status(nick, 'offline')