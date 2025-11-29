# app.py
"""
Admin-only Query-Match Telegram Bot
- Admins create matches via /addmatch in the group. Bot DMs the admin a step-by-step create flow.
- Users in the group can send messages; if the message matches a stored pattern, the bot replies with
  a polished message: image, nice caption (auto or custom), and inline URL buttons.
- MongoDB stores matches and pending sessions.
- Env vars required: TELEGRAM_TOKEN, WEBHOOK_URL, MONGODB_URI. Optional: DB_NAME, WEBHOOK_PATH.
"""
import os
import re
import time
from flask import Flask, request, abort
import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
from pymongo import MongoClient, ASCENDING
from bson.objectid import ObjectId

# -------------------- Configuration --------------------
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN")
WEBHOOK_URL = os.environ.get("WEBHOOK_URL")   # e.g. https://your-app.onrender.com
WEBHOOK_PATH = os.environ.get("WEBHOOK_PATH", "/webhook")
MONGO_URI = os.environ.get("MONGODB_URI")
DB_NAME = os.environ.get("DB_NAME", "tg_bot_db")

if not TELEGRAM_TOKEN or not WEBHOOK_URL or not MONGO_URI:
    raise RuntimeError("Set TELEGRAM_TOKEN, WEBHOOK_URL and MONGODB_URI environment variables.")

bot = telebot.TeleBot(TELEGRAM_TOKEN, parse_mode="HTML")
app = Flask(__name__)

# -------------------- MongoDB --------------------
client = MongoClient(MONGO_URI)
db = client[DB_NAME]
matches = db.matches        # collection: saved matches
pending = db.pending_adds   # collection: interactive admin sessions

# index for quick lookups
matches.create_index([("chat_id", ASCENDING)])
pending.create_index([("admin_id", ASCENDING)], unique=True)

# -------------------- Fixed welcome / rules (non-customizable) --------------------
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

# -------------------- Helpers --------------------
def is_admin(chat_id, user_id):
    try:
        member = bot.get_chat_member(chat_id, user_id)
        return member.status in ("administrator", "creator")
    except Exception:
        return False

def build_fixed_buttons():
    kb = InlineKeyboardMarkup()
    kb.add(InlineKeyboardButton("📜 Rules", callback_data="show_rules"),
           InlineKeyboardButton("📝 Request Format", callback_data="show_format"))
    return kb

def build_href_buttons(buttons):
    """buttons: list of {'text':..., 'url':...}"""
    if not buttons:
        return None
    kb = InlineKeyboardMarkup()
    for b in buttons:
        text = b.get("text", "Link")
        url = b.get("url", "")
        if url:
            kb.add(InlineKeyboardButton(text, url=url))
    return kb

def safe_send_photo(chat_id, image_ref, caption=None, reply_markup=None):
    """image_ref: Telegram file_id or absolute URL"""
    try:
        return bot.send_photo(chat_id, photo=image_ref, caption=caption, reply_markup=reply_markup)
    except Exception:
        # fallback to text if photo fails
        note = (caption or "") + "\n\n(Note: failed to send image.)"
        return bot.send_message(chat_id, note, reply_markup=reply_markup)

# Pending session helpers
def start_pending_session(admin_id, chat_id):
    doc = {
        "admin_id": str(admin_id),
        "chat_id": str(chat_id),
        "state": "await_name",
        "created_at": int(time.time()),
        "data": {}
    }
    pending.replace_one({"admin_id": str(admin_id)}, doc, upsert=True)
    return doc

def get_pending(admin_id):
    return pending.find_one({"admin_id": str(admin_id)})

def update_pending(admin_id, patch):
    pending.update_one({"admin_id": str(admin_id)}, {"$set": patch})

def clear_pending(admin_id):
    pending.delete_one({"admin_id": str(admin_id)})

# -------------------- Admin command (group): start add-match --------------------
@bot.message_handler(commands=["addmatch"])
def cmd_addmatch(message):
    chat = message.chat
    if chat.type not in ("group", "supergroup"):
        bot.reply_to(message, "Run this command in the group where you want to add a match.")
        return
    user = message.from_user
    if not is_admin(chat.id, user.id):
        bot.reply_to(message, "Only group admins can add matches.")
        return
    # Start interactive session and DM the admin
    start_pending_session(user.id, chat.id)
    try:
        bot.send_message(user.id,
            f"Create Match — Step 1/5\n\nSend the <b>Match Name</b> (example: <i>Breaking Bad</i>).",
            parse_mode="HTML")
        bot.reply_to(message, "I've sent you a DM to configure the match. Follow the steps there.")
    except Exception:
        bot.reply_to(message, "I cannot DM you. Please open a chat with the bot first (@%s) and then run /addmatch again." % bot.get_me().username)

# -------------------- Private DM: interactive flow --------------------
@bot.message_handler(func=lambda m: m.chat.type == "private")
def handle_private_dm(message):
    admin_id = message.from_user.id
    session = get_pending(admin_id)
    if not session:
        bot.reply_to(message, "No active add-match session. Start in group with /addmatch.")
        return

    state = session.get("state")
    data = session.get("data", {})

    # 1) await_name
    if state == "await_name":
        text = (message.text or "").strip()
        if not text:
            bot.reply_to(message, "Send the Match Name (text).")
            return
        data["name"] = text
        update_pending(admin_id, {"state": "await_pattern", "data": data})
        bot.reply_to(message,
            "Step 2/5 — Send the <b>pattern</b> to match (regex accepted). Send empty message to use the Name as pattern.",
            parse_mode="HTML")
        return

    # 2) await_pattern
    if state == "await_pattern":
        raw = message.text or ""
        pattern = raw.strip() or data.get("name", "")
        data["pattern"] = pattern
        update_pending(admin_id, {"state": "await_image", "data": data})
        bot.reply_to(message,
            "Step 3/5 — Send the <b>image</b> for this match.\n\n• Upload a photo OR\n• Send an image URL (http/https).\n\n(If you upload a photo, the bot will save file_id.)",
            parse_mode="HTML")
        return

    # 3) await_image
    if state == "await_image":
        image_ref = None
        if message.photo:
            image_ref = message.photo[-1].file_id
        elif message.text and (message.text.startswith("http://") or message.text.startswith("https://")):
            image_ref = message.text.strip()
        else:
            bot.reply_to(message, "Send a photo or an image URL (starting with http/https).")
            return
        data["image_ref"] = image_ref
        # auto-generate caption using Name
        name = data.get("name", "Requested")
        auto_caption = f"<b>{name}</b>\n\n{name} available here 👇"
        data["caption"] = auto_caption
        update_pending(admin_id, {"state": "caption_choice", "data": data})
        # show preview with inline options: Keep / Edit
        kb = InlineKeyboardMarkup()
        kb.add(InlineKeyboardButton("✅ Keep Caption", callback_data="keep_caption"),
               InlineKeyboardButton("✏️ Edit Caption", callback_data="edit_caption"))
        safe_send_photo(admin_id, image_ref, caption=auto_caption, reply_markup=kb)
        bot.send_message(admin_id, "Choose: keep auto caption or edit it.")
        return

    # 4) await_caption_text (after edit choice)
    if state == "await_caption_text":
        text = (message.text or "").strip()
        if not text:
            bot.reply_to(message, "Send the caption text. You may use {query} and {user} placeholders.")
            return
        data["caption"] = text
        update_pending(admin_id, {"state": "await_buttons", "data": data})
        bot.reply_to(message,
            "Step 4/5 — Send buttons, one per line, format:\nButtonText|https://example.com\n\nWhen finished send: done")
        return

    # 5) await_buttons
    if state == "await_buttons":
        body = message.text or ""
        if body.strip().lower() == "done":
            update_pending(admin_id, {"state": "preview", "data": data})
            # preview
            kb = build_href_buttons(data.get("buttons", []))
            safe_send_photo(admin_id, data.get("image_ref"), caption=data.get("caption"), reply_markup=kb)
            bot.send_message(admin_id, "Preview shown. Send 'confirm' to save, or 'cancel' to abort.")
            return
        # parse one or more lines
        lines = body.splitlines()
        btns = data.get("buttons", [])
        for ln in lines:
            ln = ln.strip()
            if not ln:
                continue
            if "|" not in ln:
                bot.reply_to(message, f"Ignored: invalid button format: {ln}\nUse: ButtonText|https://example.com")
                continue
            t, u = ln.split("|", 1)
            t = t.strip()
            u = u.strip()
            if not (u.startswith("http://") or u.startswith("https://")):
                bot.reply_to(message, f"Ignored button with invalid URL: {u}")
                continue
            btns.append({"text": t or "Link", "url": u})
        data["buttons"] = btns
        update_pending(admin_id, {"data": data})
        bot.reply_to(message, "Buttons recorded. Send more lines or 'done' when finished.")
        return

    # 6) preview -> confirm/cancel handled below for plain text
    if state == "preview":
        cmd = (message.text or "").strip().lower()
        if cmd == "confirm":
            # persist match to DB
            doc = {
                "chat_id": session.get("chat_id"),
                "name": data.get("name"),
                "pattern": data.get("pattern"),
                "image_ref": data.get("image_ref"),
                "caption": data.get("caption"),
                "buttons": data.get("buttons", []),
                "created_at": int(time.time())
            }
            matches.insert_one(doc)
            clear_pending(admin_id)
            bot.reply_to(message, "Match saved and active in the group.")
            # notify group (best-effort)
            try:
                gid = int(session.get("chat_id"))
                bot.send_message(gid, f"✅ New match added: <b>{doc['name']}</b>", parse_mode="HTML")
            except Exception:
                pass
            return
        elif cmd == "cancel":
            clear_pending(admin_id)
            bot.reply_to(message, "Session cancelled.")
            return
        else:
            bot.reply_to(message, "Send 'confirm' to save or 'cancel' to abort.")
            return

    bot.reply_to(message, "Unhandled step. To abort send 'cancel' or start again with /addmatch in your group.")

# -------------------- Callback query handlers (caption choice) --------------------
@bot.callback_query_handler(func=lambda c: c.data in ("keep_caption", "edit_caption"))
def handle_caption_choice(call):
    admin_id = call.from_user.id
    session = get_pending(admin_id)
    if not session:
        bot.answer_callback_query(call.id, "No active session.")
        return
    if call.data == "keep_caption":
        update_pending(admin_id, {"state": "await_buttons"})
        bot.answer_callback_query(call.id, "Caption kept. Now send buttons (one per line: Text|URL). Send 'done' when finished.")
        bot.send_message(admin_id, "Step 4/5 — Send buttons one per line (ButtonText|https://...)\nSend 'done' when finished.")
    else:
        update_pending(admin_id, {"state": "await_caption_text"})
        bot.answer_callback_query(call.id, "Send the new caption now.")
        bot.send_message(admin_id, "Send the new caption text (you can use {query} and {user}).")

# -------------------- Admin commands in group: list / del / preview --------------------
@bot.message_handler(commands=["listmatches"])
def cmd_listmatches(message):
    chat = message.chat
    if chat.type not in ("group", "supergroup"):
        bot.reply_to(message, "Use this in the group.")
        return
    docs = list(matches.find({"chat_id": str(chat.id)}))
    if not docs:
        bot.reply_to(message, "No matches configured for this group.")
        return
    lines = []
    for d in docs:
        lines.append(f"{d.get('_id')}  |  {d.get('name')}  |  {d.get('pattern')}")
    bot.reply_to(message, "Matches:\n" + "\n".join(lines))

@bot.message_handler(commands=["delmatch"])
def cmd_delmatch(message):
    chat = message.chat
    user = message.from_user
    if chat.type not in ("group", "supergroup"):
        bot.reply_to(message, "Use this in the group.")
        return
    if not is_admin(chat.id, user.id):
        bot.reply_to(message, "Only group admins can delete matches.")
        return
    parts = message.text.split(" ", 1)
    if len(parts) < 2:
        bot.reply_to(message, "Usage: /delmatch <match_id>")
        return
    mid = parts[1].strip()
    try:
        res = matches.delete_one({"_id": ObjectId(mid), "chat_id": str(chat.id)})
        if res.deleted_count:
            bot.reply_to(message, "Deleted.")
        else:
            bot.reply_to(message, "Not found or invalid id.")
    except Exception:
        bot.reply_to(message, "Invalid id format.")

@bot.message_handler(commands=["previewmatch"])
def cmd_previewmatch(message):
    chat = message.chat
    if chat.type not in ("group", "supergroup"):
        bot.reply_to(message, "Use this in the group.")
        return
    parts = message.text.split(" ", 1)
    if len(parts) < 2:
        bot.reply_to(message, "Usage: /previewmatch <match_id>")
        return
    mid = parts[1].strip()
    try:
        d = matches.find_one({"_id": ObjectId(mid), "chat_id": str(chat.id)})
        if not d:
            bot.reply_to(message, "Not found.")
            return
        caption = d.get("caption", "").replace("{query}", d.get("name", "")).replace("{user}", "User")
        kb = build_href_buttons(d.get("buttons", []))
        img = d.get("image_ref")
        if img:
            safe_send_photo(chat.id, img, caption=caption, reply_markup=kb)
        else:
            bot.reply_to(message, caption, reply_markup=kb)
    except Exception:
        bot.reply_to(message, "Invalid id format.")

# -------------------- Welcome & rules buttons --------------------
@bot.message_handler(content_types=["new_chat_members"])
def welcome_new_members(message):
    for nm in message.new_chat_members:
        name_html = f"<a href='tg://user?id={nm.id}'>{nm.first_name}</a>"
        welcome_text = FIXED_WELCOME.replace("{name}", name_html).replace("{req_format}", FIXED_REQ_FORMAT)
        bot.send_message(message.chat.id, welcome_text, reply_markup=build_fixed_buttons())

@bot.callback_query_handler(func=lambda c: c.data in ("show_rules", "show_format"))
def cb_rules_format(call):
    if call.data == "show_rules":
        bot.answer_callback_query(call.id)
        bot.send_message(call.message.chat.id, FIXED_RULES)
    else:
        bot.answer_callback_query(call.id)
        bot.send_message(call.message.chat.id, FIXED_REQ_FORMAT)

# -------------------- Message watcher: match group messages --------------------
@bot.message_handler(content_types=["text"])
def watch_group_messages(message):
    if message.chat.type not in ("group", "supergroup"):
        return
    txt = (message.text or "").strip()
    if not txt:
        return
    chat_id = str(message.chat.id)
    docs = list(matches.find({"chat_id": chat_id}).sort("created_at", 1))
    if not docs:
        return
    for d in docs:
        pattern = (d.get("pattern") or "").strip()
        if not pattern:
            continue
        matched = False
        try:
            if re.search(pattern, txt, flags=re.IGNORECASE):
                matched = True
        except re.error:
            if pattern.lower() in txt.lower():
                matched = True
        if matched:
            # Build nice caption: Title + custom caption (supports {query} & {user})
            title = d.get("name", "")
            custom = d.get("caption", "")
            caption = f"🔔 <b>{title}</b>\n\n{custom}"
            caption = caption.replace("{query}", txt).replace("{user}", message.from_user.first_name)
            kb = build_href_buttons(d.get("buttons", []))
            img = d.get("image_ref")
            if img:
                safe_send_photo(message.chat.id, img, caption=caption, reply_markup=kb)
            else:
                bot.send_message(message.chat.id, caption, reply_markup=kb)
            return  # stop after first match

# -------------------- Webhook endpoints --------------------
@app.route(WEBHOOK_PATH, methods=["POST"])
def receive_update():
    if request.headers.get("content-type") != "application/json":
        abort(403)
    json_str = request.get_data().decode("utf-8")
    update = telebot.types.Update.de_json(json_str)
    bot.process_new_updates([update])
    return "", 200

@app.route("/")
def index():
    return "OK", 200

# -------------------- Startup: set webhook --------------------
def setup():
    full = WEBHOOK_URL.rstrip("/") + WEBHOOK_PATH
    try:
        bot.remove_webhook()
    except Exception:
        pass
    ok = bot.set_webhook(url=full)
    print("Webhook set:", ok, "->", full)

if __name__ == "__main__":
    setup()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
