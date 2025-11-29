# app.py - COMPLETE CODE WITH ALL FEATURES
"""
Admin-only Query-Match Telegram Bot
- ALL admin actions in private chat with bot (/start)
- Groups for users only - they send messages
- Welcome messages with Rules and Request Format buttons
- Image: Telegram file_id (preferred) or URL
- Production-ready for Render.com
"""
import os
import re
import time
import logging
from flask import Flask, request, abort
import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton, ReplyKeyboardMarkup, KeyboardButton
from pymongo import MongoClient, ASCENDING
from bson.objectid import ObjectId

# -------------------- Logging --------------------
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# -------------------- Configuration --------------------
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN")
WEBHOOK_URL = os.environ.get("WEBHOOK_URL")
WEBHOOK_PATH = os.environ.get("WEBHOOK_PATH", "/webhook")
MONGO_URI = os.environ.get("MONGODB_URI")
DB_NAME = os.environ.get("DB_NAME", "tg_bot_db")

if not all([TELEGRAM_TOKEN, WEBHOOK_URL, MONGO_URI]):
    raise RuntimeError("Missing env vars: TELEGRAM_TOKEN, WEBHOOK_URL, MONGODB_URI")

bot = telebot.TeleBot(TELEGRAM_TOKEN, parse_mode="HTML", threaded=False)
app = Flask(__name__)

# -------------------- Fixed Welcome & Rules --------------------
FIXED_REQ_FORMAT = (
    "{𝙍𝙚𝙦𝙪𝙚𝙨𝙩 𝙁𝙤𝙧𝙢𝙖𝙩}\n\n"
    "🫵𝖥𝗂𝗋𝗌𝗍 𝖦𝗈𝗈𝗀𝗅𝖾 𝗂𝗍 𝗆𝗈𝗏𝗂𝖾 𝗌𝗉𝖾𝗅𝗅𝗂𝗇𝗀 𝖳𝗁𝖾𝗇 𝖯𝖺𝗌𝗍𝖾 𝖧𝖾𝗋𝖾\n\n"
    "➠ 𝗙𝗢𝗥 𝗠𝗢𝗩𝗜𝗘𝗦 🎬\n"
    "→ Vikram (or)\n"
    "→ Vikram 2022 Tam (or)\n"
    "→ Vikram 2022 Tamil (or)\n"
    "→ Vikram Tamil\n\n"
    "➠ 𝗙𝗢𝗥 𝗦𝗘𝗥𝗜𝗘𝗦 🍿\n"
    "→ The Family Man S01 (or)\n"
    "→ The Family Man S01 720p Tamil (or)\n"
    "→ The Family Man S01 720p Tam\n\n"
    "👇👇👇\n"
    "Thank You ❤️."
)

FIXED_WELCOME = (
    "Welcome {name} 👋\n\n"
    "👇👇\n"
    "{req_format}\n\n"
    "ஏதேனும் கேட்கும் முன்பு, இதை படிக்கவும் 👍\n\n"
    "Thank You ❤️."
)

FIXED_RULES = (
    "Rules\n\n"
    "✘ Don't share or promote your own channels or any links; it will lead to your ban.\n\n"
    "✔ Ask whatever you want with the correct format of movies and series names."
)

# -------------------- MongoDB --------------------
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.server_info()
    db = client[DB_NAME]
    matches = db.matches
    pending = db.pending_sessions
    admins = db.admins
    matches.create_index([("admin_id", ASCENDING)])
    pending.create_index([("admin_id", ASCENDING)], unique=True)
    admins.create_index([("user_id", ASCENDING)], unique=True)
    logger.info("✅ MongoDB connected")
except Exception as e:
    logger.error(f"❌ MongoDB failed: {e}")
    raise

# -------------------- Helper Functions --------------------
def is_admin(user_id):
    return admins.find_one({"user_id": str(user_id)}) is not None

def register_admin(user_id, username=None, first_name=None):
    admins.update_one({"user_id": str(user_id)}, {"$set": {
        "user_id": str(user_id), "username": username, "first_name": first_name,
        "registered_at": int(time.time())
    }}, upsert=True)
    logger.info(f"✅ Admin: {user_id}")

def get_admin_menu():
    markup = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    markup.add(KeyboardButton("➕ Add Match"), KeyboardButton("📋 List Matches"),
               KeyboardButton("🔍 Search"), KeyboardButton("🗑️ Delete"),
               KeyboardButton("👁️ Preview"), KeyboardButton("📊 Stats"),
               KeyboardButton("❌ Cancel"))
    return markup

def remove_keyboard():
    return telebot.types.ReplyKeyboardRemove()

def build_welcome_buttons():
    """Build welcome message buttons (Rules & Request Format)"""
    kb = InlineKeyboardMarkup()
    kb.add(InlineKeyboardButton("📜 Rules", callback_data="show_rules"),
           InlineKeyboardButton("📝 Request Format", callback_data="show_format"))
    return kb

def build_buttons(buttons):
    if not buttons:
        return None
    kb = InlineKeyboardMarkup(row_width=1)
    for b in buttons:
        text, url = b.get("text", "Link"), b.get("url", "")
        if url and (url.startswith("http://") or url.startswith("https://")):
            kb.add(InlineKeyboardButton(text, url=url))
    return kb

def safe_send_photo(chat_id, photo, caption=None, reply_markup=None, reply_to=None):
    try:
        return bot.send_photo(chat_id, photo=photo, caption=caption, 
                            reply_markup=reply_markup, parse_mode="HTML",
                            reply_to_message_id=reply_to)
    except Exception as e:
        logger.warning(f"Photo failed: {e}")
        return bot.send_message(chat_id, (caption or "Content") + "\n\n⚠️ Image unavailable",
                              reply_markup=reply_markup, parse_mode="HTML", reply_to_message_id=reply_to)

def get_session(admin_id):
    return pending.find_one({"admin_id": str(admin_id)})

def start_session(admin_id):
    pending.replace_one({"admin_id": str(admin_id)}, {
        "admin_id": str(admin_id), "state": "await_name", 
        "created_at": int(time.time()), "data": {}
    }, upsert=True)

def update_session(admin_id, state=None, data_patch=None):
    update_dict = {}
    if state:
        update_dict["state"] = state
    if data_patch:
        for k, v in data_patch.items():
            update_dict[f"data.{k}"] = v
    if update_dict:
        pending.update_one({"admin_id": str(admin_id)}, {"$set": update_dict})

def clear_session(admin_id):
    pending.delete_one({"admin_id": str(admin_id)})

# -------------------- Commands --------------------
@bot.message_handler(commands=["start"])
def cmd_start(message):
    if message.chat.type != "private":
        bot.reply_to(message, "✅ Bot active! Users can query in group.")
        return
    user = message.from_user
    if not is_admin(user.id):
        register_admin(user.id, user.username, user.first_name)
        text = f"👋 Welcome <b>{user.first_name}</b>!\n\n✅ Registered as admin\n\n💡 Use buttons below:"
    else:
        text = f"👋 Welcome back <b>{user.first_name}</b>!\n\nUse menu buttons:"
    bot.send_message(message.chat.id, text, reply_markup=get_admin_menu())

@bot.message_handler(commands=["cancel", "help"])
def cmd_other(message):
    if message.chat.type != "private" or not is_admin(message.from_user.id):
        return
    clear_session(message.from_user.id)
    bot.send_message(message.chat.id, "✅ Ready", reply_markup=get_admin_menu())

# -------------------- Menu Handlers --------------------
@bot.message_handler(func=lambda m: m.chat.type == "private" and m.text == "➕ Add Match")
def menu_add(message):
    if not is_admin(message.from_user.id):
        return
    start_session(message.from_user.id)
    bot.send_message(message.chat.id, 
        "🎯 <b>Step 1/4</b>\n\n📝 Send <b>Match Name</b>\n\n<i>Example: Stranger Things</i>",
        reply_markup=remove_keyboard())

@bot.message_handler(func=lambda m: m.chat.type == "private" and m.text == "📋 List Matches")
def menu_list(message):
    if not is_admin(message.from_user.id):
        return
    docs = list(matches.find({"admin_id": str(message.from_user.id)}).sort("created_at", -1).limit(50))
    if not docs:
        bot.send_message(message.chat.id, "📭 No matches yet", reply_markup=get_admin_menu())
        return
    lines = [f"📋 <b>{len(docs)} Matches</b>\n"]
    for i, d in enumerate(docs, 1):
        lines.append(f"{i}. {'🖼️' if d.get('image_ref') else '📄'} <b>{d.get('name')}</b>\n   <code>{d['_id']}</code>")
    bot.send_message(message.chat.id, "\n\n".join(lines), reply_markup=get_admin_menu())

@bot.message_handler(func=lambda m: m.chat.type == "private" and m.text == "🔍 Search")
def menu_search(message):
    if not is_admin(message.from_user.id):
        return
    clear_session(message.from_user.id)
    update_session(message.from_user.id, state="search_match")
    bot.send_message(message.chat.id, "🔍 Send keyword:", reply_markup=remove_keyboard())

@bot.message_handler(func=lambda m: m.chat.type == "private" and m.text == "👁️ Preview")
def menu_preview(message):
    if not is_admin(message.from_user.id):
        return
    clear_session(message.from_user.id)
    update_session(message.from_user.id, state="preview_match")
    bot.send_message(message.chat.id, "👁️ Send Match ID:", reply_markup=remove_keyboard())

@bot.message_handler(func=lambda m: m.chat.type == "private" and m.text == "🗑️ Delete")
def menu_delete(message):
    if not is_admin(message.from_user.id):
        return
    clear_session(message.from_user.id)
    update_session(message.from_user.id, state="delete_match")
    bot.send_message(message.chat.id, "🗑️ Send Match ID to delete:", reply_markup=remove_keyboard())

@bot.message_handler(func=lambda m: m.chat.type == "private" and m.text == "📊 Stats")
def menu_stats(message):
    if not is_admin(message.from_user.id):
        return
    aid = str(message.from_user.id)
    total = matches.count_documents({"admin_id": aid})
    with_img = matches.count_documents({"admin_id": aid, "image_ref": {"$exists": True, "$ne": ""}})
    bot.send_message(message.chat.id, f"📊 <b>Stats</b>\n\n🎯 Total: {total}\n🖼️ Images: {with_img}",
                    reply_markup=get_admin_menu())

@bot.message_handler(func=lambda m: m.chat.type == "private" and m.text == "❌ Cancel")
def menu_cancel(message):
    if not is_admin(message.from_user.id):
        return
    clear_session(message.from_user.id)
    bot.send_message(message.chat.id, "✅ Cancelled", reply_markup=get_admin_menu())

# -------------------- Match Creation Flow --------------------
@bot.message_handler(func=lambda m: m.chat.type == "private" and m.text and not m.text.startswith('/'), content_types=["text"])
def handle_text(message):
    uid = message.from_user.id
    if not is_admin(uid):
        return
    session = get_session(uid)
    if not session:
        return
    
    state = session.get("state")
    data = session.get("data", {})
    
    # Step 1: Name
    if state == "await_name":
        name = message.text.strip()
        if not name:
            bot.reply_to(message, "⚠️ Send text name")
            return
        update_session(uid, state="await_image", data_patch={"name": name})
        bot.send_message(message.chat.id, 
            f"✅ Name: <b>{name}</b>\n\n🎯 <b>Step 2/4</b>\n\n📸 Send photo or URL")
        return
    
    # Step 2: Image URL
    if state == "await_image":
        txt = message.text.strip()
        if txt.startswith("http://") or txt.startswith("https://"):
            name = data.get("name", "Content")
            caption = f"🎬 <b>{name}</b>\n\n✅ {name} available here 👇"
            update_session(uid, state="await_buttons", data_patch={"image_ref": txt, "caption": caption})
            safe_send_photo(message.chat.id, txt, caption=caption)
            bot.send_message(message.chat.id,
                "✅ Image saved\n\n🎯 <b>Step 3/4</b>\n\n🔘 Buttons:\n<code>Text|https://url.com</code>\n\nSend 'done' when finished")
        else:
            bot.reply_to(message, "⚠️ Send photo or http/https URL")
        return
    
    # Step 3: Buttons
    if state == "await_buttons":
        if message.text.strip().lower() == "done":
            update_session(uid, state="await_confirm")
            name = data.get("name", "Match")
            caption = data.get("caption", "")
            buttons = data.get("buttons", [])
            img = data.get("image_ref")
            bot.send_message(message.chat.id, "🎯 <b>Step 4/4 - Preview</b>")
            if img:
                safe_send_photo(message.chat.id, img, caption=caption, reply_markup=build_buttons(buttons))
            else:
                bot.send_message(message.chat.id, caption, reply_markup=build_buttons(buttons))
            bot.send_message(message.chat.id,
                f"📋 Name: <b>{name}</b>\nButtons: {len(buttons)}\n\n✅ Send 'confirm'\n❌ Send 'cancel'")
            return
        
        lines = message.text.splitlines()
        buttons = data.get("buttons", [])
        added = 0
        for ln in lines:
            ln = ln.strip()
            if "|" not in ln:
                continue
            parts = ln.split("|", 1)
            text, url = parts[0].strip(), parts[1].strip()
            if url.startswith("http://") or url.startswith("https://"):
                buttons.append({"text": text or "Link", "url": url})
                added += 1
        update_session(uid, data_patch={"buttons": buttons})
        bot.reply_to(message, f"✅ Added {added}. Total: {len(buttons)}\n\nSend more or 'done'")
        return
    
    # Step 4: Confirm
    if state == "await_confirm":
        cmd = message.text.strip().lower()
        if cmd == "confirm":
            doc = {"admin_id": str(uid), "name": data.get("name"), "image_ref": data.get("image_ref"),
                   "caption": data.get("caption"), "buttons": data.get("buttons", []), "created_at": int(time.time())}
            result = matches.insert_one(doc)
            clear_session(uid)
            bot.send_message(message.chat.id,
                f"🎉 <b>Created!</b>\n\n✅ {doc['name']}\n✅ <code>{result.inserted_id}</code>",
                reply_markup=get_admin_menu())
            logger.info(f"✅ Match: {doc['name']}")
            return
        elif cmd == "cancel":
            clear_session(uid)
            bot.send_message(message.chat.id, "❌ Cancelled", reply_markup=get_admin_menu())
            return
        else:
            bot.reply_to(message, "⚠️ Send 'confirm' or 'cancel'")
            return
    
    # Other states
    if state == "search_match":
        query = message.text.strip()
        results = list(matches.find({"admin_id": str(uid), "name": {"$regex": query, "$options": "i"}}).limit(10))
        if results:
            lines = [f"🔍 <b>{len(results)} Results</b>\n"]
            for r in results:
                lines.append(f"• <b>{r.get('name')}</b>\n  <code>{r['_id']}</code>")
            bot.send_message(message.chat.id, "\n\n".join(lines), reply_markup=get_admin_menu())
        else:
            bot.send_message(message.chat.id, f"❌ No results for: {query}", reply_markup=get_admin_menu())
        clear_session(uid)
        return
    
    if state == "preview_match":
        try:
            d = matches.find_one({"_id": ObjectId(message.text.strip()), "admin_id": str(uid)})
            if d:
                bot.send_message(message.chat.id, f"👁️ <b>{d.get('name')}</b>")
                if d.get("image_ref"):
                    safe_send_photo(message.chat.id, d["image_ref"], 
                                  caption=d.get("caption"), reply_markup=build_buttons(d.get("buttons")))
                else:
                    bot.send_message(message.chat.id, d.get("caption"), reply_markup=build_buttons(d.get("buttons")))
                bot.send_message(message.chat.id, "✅ Preview", reply_markup=get_admin_menu())
            else:
                bot.send_message(message.chat.id, "❌ Not found", reply_markup=get_admin_menu())
        except:
            bot.send_message(message.chat.id, "❌ Invalid ID", reply_markup=get_admin_menu())
        clear_session(uid)
        return
    
    if state == "delete_match":
        try:
            d = matches.find_one({"_id": ObjectId(message.text.strip()), "admin_id": str(uid)})
            if d:
                matches.delete_one({"_id": d["_id"]})
                bot.send_message(message.chat.id, f"✅ Deleted: {d.get('name')}", reply_markup=get_admin_menu())
                logger.info(f"🗑️ Deleted: {d.get('name')}")
            else:
                bot.send_message(message.chat.id, "❌ Not found", reply_markup=get_admin_menu())
        except:
            bot.send_message(message.chat.id, "❌ Invalid ID", reply_markup=get_admin_menu())
        clear_session(uid)
        return

@bot.message_handler(func=lambda m: m.chat.type == "private", content_types=["photo"])
def handle_photo(message):
    uid = message.from_user.id
    if not is_admin(uid):
        return
    session = get_session(uid)
    if not session or session.get("state") != "await_image":
        return
    
    data = session.get("data", {})
    file_id = message.photo[-1].file_id
    name = data.get("name", "Content")
    caption = f"🎬 <b>{name}</b>\n\n✅ {name} available here 👇"
    
    bot.send_message(message.chat.id, "⏳ Processing...")
    update_session(uid, state="await_buttons", data_patch={"image_ref": file_id, "caption": caption})
    safe_send_photo(message.chat.id, file_id, caption=caption)
    bot.send_message(message.chat.id,
        "✅ Image saved!\n\n🎯 <b>Step 3/4</b>\n\n🔘 Buttons:\n<code>Text|https://url.com</code>\n\nSend 'done' when finished")

# -------------------- Welcome & Rules Buttons --------------------
@bot.message_handler(func=lambda m: m.chat.type in ("group", "supergroup"), content_types=["new_chat_members"])
def welcome_new_members(message):
    """Welcome new members with Rules and Request Format buttons"""
    try:
        for member in message.new_chat_members:
            if member.id == bot.get_me().id:
                # Bot added to group
                bot.send_message(message.chat.id, 
                    "👋 <b>Hello! I'm your Match Bot!</b>\n\n"
                    "✅ Ready to help!\n\n"
                    "💡 Users send queries, I respond automatically.")
            else:
                # Regular user joined - send welcome with buttons
                name_html = f"<a href='tg://user?id={member.id}'>{member.first_name}</a>"
                welcome_text = FIXED_WELCOME.replace("{name}", name_html).replace("{req_format}", FIXED_REQ_FORMAT)
                bot.send_message(message.chat.id, welcome_text, reply_markup=build_welcome_buttons())
                logger.info(f"👋 Welcome sent to {member.first_name}")
    except Exception as e:
        logger.error(f"Welcome error: {e}")

@bot.callback_query_handler(func=lambda c: c.data in ("show_rules", "show_format"))
def handle_welcome_buttons(call):
    """Handle Rules and Request Format button clicks"""
    try:
        if call.data == "show_rules":
            bot.answer_callback_query(call.id, "Showing rules...")
            bot.send_message(call.message.chat.id, FIXED_RULES)
        elif call.data == "show_format":
            bot.answer_callback_query(call.id, "Showing request format...")
            bot.send_message(call.message.chat.id, FIXED_REQ_FORMAT)
    except Exception as e:
        logger.error(f"Callback error: {e}")

# -------------------- Group Message Handler --------------------
@bot.message_handler(func=lambda m: m.chat.type in ("group", "supergroup"), content_types=["text"])
def handle_group(message):
    """Handle user queries in groups - match patterns"""
    if not message.text or message.text.startswith('/') or len(message.text) < 2:
        return
    
    txt = message.text.strip()
    
    try:
        # Get all matches and try to find one that matches
        all_matches = list(matches.find().sort("created_at", -1))
        
        for doc in all_matches:
            name = doc.get("name", "").strip()
            if not name:
                continue
            
            # Try pattern matching (case-insensitive)
            pattern = doc.get("pattern", name).strip()
            matched = False
            
            try:
                # Try regex first
                if re.search(pattern, txt, flags=re.IGNORECASE):
                    matched = True
            except re.error:
                # Fallback to simple substring match
                if pattern.lower() in txt.lower():
                    matched = True
            
            if matched:
                # Build response
                title = doc.get("name", "")
                custom = doc.get("caption", "")
                caption = f"🔔 <b>{title}</b>\n\n{custom}"
                caption = caption.replace("{query}", txt).replace("{user}", message.from_user.first_name)
                
                img = doc.get("image_ref")
                kb = build_buttons(doc.get("buttons", []))
                
                # Send response
                if img:
                    safe_send_photo(message.chat.id, img, caption=caption, 
                                  reply_markup=kb, reply_to=message.message_id)
                else:
                    bot.reply_to(message, caption, reply_markup=kb)
                
                logger.info(f"✅ Matched: {name} for query: {txt}")
                return  # Stop after first match
    
    except Exception as e:
        logger.error(f"Group handler error: {e}")

# -------------------- Flask Routes --------------------
@app.route(WEBHOOK_PATH, methods=["POST"])
def webhook():
    if request.headers.get("content-type") != "application/json":
        abort(403)
    try:
        json_str = request.get_data().decode("utf-8")
        update = telebot.types.Update.de_json(json_str)
        bot.process_new_updates([update])
        return "", 200
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return "", 500

@app.route("/")
def index():
    return {"status": "ok", "bot": "active", "time": int(time.time())}, 200

@app.route("/health")
def health():
    try:
        client.server_info()
        db_status = "connected"
    except:
        db_status = "disconnected"
    try:
        info = bot.get_me()
        bot_status = "active"
        username = info.username
    except:
        bot_status = "inactive"
        username = None
    return {"status": "ok" if db_status == "connected" and bot_status == "active" else "degraded",
            "database": db_status, "bot": bot_status, "username": username}, 200

# -------------------- Startup --------------------
def setup():
    webhook_url = WEBHOOK_URL.rstrip("/") + WEBHOOK_PATH
    for i in range(3):
        try:
            bot.remove_webhook()
            time.sleep(1)
            if bot.set_webhook(url=webhook_url):
                logger.info(f"✅ Webhook: {webhook_url}")
                info = bot.get_me()
                logger.info(f"🤖 Bot: @{info.username}")
                return
        except Exception as e:
            logger.error(f"Setup error: {e}")
            if i < 2:
                time.sleep(2)
    raise RuntimeError("Webhook setup failed")

if __name__ == "__main__":
    setup()
    port = int(os.environ.get("PORT", 5000))
    logger.info(f"🌐 Starting on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
