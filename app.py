# ==================== IMPORTS ====================

import os
import re
import time
import logging
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, asdict
from enum import Enum
from dotenv import load_dotenv

from flask import Flask, request, abort, jsonify
import telebot
from telebot.types import (
    InlineKeyboardMarkup, InlineKeyboardButton,
    ReplyKeyboardMarkup, KeyboardButton, ReplyKeyboardRemove
)
from pymongo import MongoClient, ASCENDING, DESCENDING, errors as mongo_errors
from bson.objectid import ObjectId
from redis import Redis, RedisError
from apscheduler.schedulers.background import BackgroundScheduler

load_dotenv()

# ==================== CONFIGURATION ====================

class Config:
    TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
    WEBHOOK_URL = os.getenv("WEBHOOK_URL")
    WEBHOOK_PATH = os.getenv("WEBHOOK_PATH", "/webhook")

    MONGODB_URI = os.getenv("MONGODB_URI")
    DB_NAME = os.getenv("DB_NAME", "tg_bot_db")

    ADMIN_IDS = [int(x.strip()) for x in os.getenv("ADMIN_IDS", "").split(",") if x.strip()]
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    USE_REDIS = os.getenv("USE_REDIS", "true").lower() == "true"

    RATE_LIMIT_MESSAGES = int(os.getenv("RATE_LIMIT_MESSAGES", "5"))
    RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))
    MAX_BUTTONS_PER_MATCH = int(os.getenv("MAX_BUTTONS_PER_MATCH", "10"))
    MAX_CAPTION_LENGTH = int(os.getenv("MAX_CAPTION_LENGTH", "1024"))

    CACHE_TTL = int(os.getenv("CACHE_TTL", "300"))
    MAX_SEARCH_RESULTS = int(os.getenv("MAX_SEARCH_RESULTS", "50"))

    ENABLE_ANALYTICS = os.getenv("ENABLE_ANALYTICS", "true").lower() == "true"

    PORT = int(os.getenv("PORT", "5000"))
    DEBUG = os.getenv("DEBUG", "false").lower() == "true"

    AUTO_DELETE_MATCHED_QUERY = int(os.getenv("AUTO_DELETE_MATCHED_QUERY", "10"))
    AUTO_DELETE_WELCOME_MSG = int(os.getenv("AUTO_DELETE_WELCOME_MSG", "30"))

    @classmethod
    def validate(cls):
        required = ["TELEGRAM_TOKEN", "WEBHOOK_URL", "MONGODB_URI"]
        missing = [k for k in required if not getattr(cls, k)]
        if missing:
            raise RuntimeError(f"Missing required config: {', '.join(missing)}")


# ==================== LOGGING ====================

class CustomFormatter(logging.Formatter):
    grey = "\x1b[38;21m"
    blue = "\x1b[38;5;39m"
    yellow = "\x1b[38;5;226m"
    red = "\x1b[38;5;196m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"

    def __init__(self):
        super().__init__()
        self.fmt = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        self.FORMATS = {
            logging.DEBUG: self.grey + self.fmt + self.reset,
            logging.INFO: self.blue + self.fmt + self.reset,
            logging.WARNING: self.yellow + self.fmt + self.reset,
            logging.ERROR: self.red + self.fmt + self.reset,
            logging.CRITICAL: self.bold_red + self.fmt + self.reset
        }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt='%Y-%m-%d %H:%M:%S')
        return formatter.format(record)


def setup_logging():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO if not Config.DEBUG else logging.DEBUG)
    handler = logging.StreamHandler()
    handler.setFormatter(CustomFormatter())
    logger.addHandler(handler)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("telebot").setLevel(logging.WARNING)
    return logging.getLogger(__name__)


logger = setup_logging()


# ==================== DATA MODELS ====================

@dataclass
class Button:
    text: str
    url: str
    def validate(self) -> bool:
        if not self.text or len(self.text) > 100:
            return False
        if not self.url.startswith(("http://", "https://")):
            return False
        return True


@dataclass
class Match:
    name: str
    pattern: str
    caption: str
    image_ref: Optional[str] = None
    buttons: List[Dict[str, str]] = None
    admin_id: Optional[str] = None
    created_at: Optional[int] = None
    updated_at: Optional[int] = None
    match_count: int = 0
    _id: Optional[ObjectId] = None

    def __post_init__(self):
        if self.buttons is None:
            self.buttons = []
        now = int(time.time())
        self.created_at = self.created_at or now
        self.updated_at = self.updated_at or now
        if not self.pattern:
            self.pattern = self.name
        if not self.caption:
            self.caption = f"🎬 <b>{self.name}</b>\n\nAvailable 👇"

    def to_dict(self):
        d = asdict(self)
        if self._id:
            d["_id"] = self._id
        return {k: v for k, v in d.items() if v is not None}


@dataclass
class SessionData:
    admin_id: str
    state: str
    data: Dict[str, Any]
    created_at: int
    expires_at: int

    @staticmethod
    def create(admin_id: str, state: str, ttl=600):
        now = int(time.time())
        return SessionData(
            admin_id=str(admin_id),
            state=state,
            data={},
            created_at=now,
            expires_at=now + ttl
        )


# ==================== DATABASE CONNECTION ====================

class DatabaseConnection:
    def __init__(self, uri, db_name, max_retries=3):
        self.uri = uri
        self.db_name = db_name
        self.max_retries = max_retries
        self._client = None
        self._db = None
        self.connect()

    def connect(self):
        for attempt in range(self.max_retries):
            try:
                self._client = MongoClient(self.uri, serverSelectionTimeoutMS=5000)
                self._client.server_info()
                self._db = self._client[self.db_name]
                self._setup_indexes()
                logger.info("MongoDB connected")
                return
            except Exception as e:
                logger.error(f"MongoDB error: {e}")
                time.sleep(1)

    def _setup_indexes(self):
        try:
            self._db.matches.create_index([("admin_id", ASCENDING)])
            self._db.matches.create_index([("name", ASCENDING)])
            self._db.matches.create_index([("pattern", ASCENDING)])
            self._db.matches.create_index([("created_at", DESCENDING)])
            self._db.matches.create_index([("match_count", DESCENDING)])
            self._db.matches.create_index([("name", "text"), ("pattern", "text")])
            self._db.admins.create_index([("user_id", ASCENDING)], unique=True)
        except Exception as e:
            logger.warning(f"Index warning: {e}")

    @property
    def db(self):
        return self._db

    def health_check(self):
        try:
            self._client.admin.command("ping")
            return True
        except:
            return False


# ==================== CACHE ====================

class CacheManager:
    def __init__(self, redis_url, enabled=True):
        self.enabled = enabled
        self.client = None
        if enabled:
            try:
                self.client = Redis.from_url(redis_url, decode_responses=True)
                self.client.ping()
                logger.info("Redis connected")
            except:
                logger.warning("Redis disabled")
                self.enabled = False

    def get(self, key):
        if not self.enabled:
            return None
        try:
            return self.client.get(key)
        except:
            return None

    def set(self, key, value, ttl=Config.CACHE_TTL):
        if not self.enabled:
            return
        try:
            self.client.setex(key, ttl, value)
        except:
            pass

    def delete(self, key):
        if self.enabled:
            try:
                self.client.delete(key)
            except:
                pass

    def clear_pattern(self, pattern):
        if self.enabled:
            try:
                keys = self.client.keys(pattern)
                if keys:
                    self.client.delete(*keys)
            except:
                pass


# ==================== FIXED REPOSITORIES ====================

class MatchRepository:

    def __init__(self, db, cache):
        self.col = db.matches
        self.cache = cache

    # FORCE admin_id → string everywhere
    def _aid(self, admin_id):
        return str(admin_id)

    def create(self, match: Match):
        match.admin_id = self._aid(match.admin_id)
        res = self.col.insert_one(match.to_dict())
        self.cache.clear_pattern("matches:*")
        return res.inserted_id

    def find_by_id(self, match_id, admin_id):
        admin_id = self._aid(admin_id)
        try:
            doc = self.col.find_one({"_id": ObjectId(match_id), "admin_id": admin_id})
            return Match(**doc) if doc else None
        except:
            return None

    def find_by_name(self, name, admin_id):
        admin_id = self._aid(admin_id)
        try:
            doc = self.col.find_one({
                "admin_id": admin_id,
                "name": {"$regex": f"^{re.escape(name)}$", "$options": "i"}
            })
            return Match(**doc) if doc else None
        except:
            return None

    def find_by_id_or_name(self, identifier, admin_id):
        admin_id = self._aid(admin_id)

        # Try ID first
        if ObjectId.is_valid(identifier):
            m = self.find_by_id(identifier, admin_id)
            if m:
                return m

        # Then name
        return self.find_by_name(identifier, admin_id)

# ==================== PART 2 / 3 ====================
# ==================== SERVICES ====================

class RateLimiter:
    def __init__(self, cache: CacheManager):
        self.cache = cache

    def is_allowed(self, user_id: str, limit: int = Config.RATE_LIMIT_MESSAGES,
                   window: int = Config.RATE_LIMIT_WINDOW) -> bool:
        if not self.cache.enabled:
            return True
        try:
            key = f"ratelimit:{user_id}"
            cnt = self.cache.client.incr(key)
            if cnt == 1:
                self.cache.client.expire(key, window)
            return cnt <= limit
        except:
            return True


class MatchingService:
    def __init__(self, match_repo: MatchRepository, analytics_repo):
        self.match_repo = match_repo
        self.analytics_repo = analytics_repo
        self._compile_cache = {}

    def find_match(self, query: str):
        q = query.lower().strip()
        matches = self.match_repo.col.find().sort("created_at", DESCENDING)
        for doc in matches:
            try:
                match = Match(**doc)
            except Exception:
                continue

            if self._matches_pattern(q, match):
                try:
                    self.match_repo.col.update_one({"_id": match._id}, {"$inc": {"match_count": 1}})
                except:
                    pass
                if self.analytics_repo:
                    try:
                        self.analytics_repo.log_event("match_found", {
                            "match_id": str(match._id),
                            "match_name": match.name,
                            "query": query
                        })
                    except:
                        pass
                return match
        return None

    def _matches_pattern(self, query: str, match: Match) -> bool:
        pattern = (match.pattern or match.name or "").strip()
        if not pattern:
            return False

        cache_key = f"pattern:{pattern}"
        if cache_key not in self._compile_cache:
            try:
                self._compile_cache[cache_key] = re.compile(pattern, re.IGNORECASE)
            except re.error:
                self._compile_cache[cache_key] = None

        regex = self._compile_cache[cache_key]
        if regex:
            try:
                return bool(regex.search(query))
            except:
                return False
        else:
            return pattern.lower() in query


class ValidationService:
    @staticmethod
    def sanitize_text(text: str, max_length: int = 1000) -> str:
        if not text:
            return ""
        text = re.sub(r'<[^>]+>', '', text)
        return text[:max_length].strip()

    @staticmethod
    def validate_url(url: str) -> bool:
        if not url:
            return False
        return url.startswith("http://") or url.startswith("https://")

    @staticmethod
    def validate_buttons(buttons: List[Dict]) -> List[Dict]:
        valid = []
        for btn in (buttons or [])[:Config.MAX_BUTTONS_PER_MATCH]:
            text = ValidationService.sanitize_text(btn.get("text", "") or "Link", 100)
            url = btn.get("url", "")
            if text and ValidationService.validate_url(url):
                valid.append({"text": text, "url": url})
        return valid


class AutoDeleteService:
    def __init__(self, bot):
        self.bot = bot

    def delete_after(self, chat_id: int, message_id: int, delay: int):
        def job():
            try:
                time.sleep(delay)
                self.bot.delete_message(chat_id, message_id)
            except Exception:
                pass

        import threading
        t = threading.Thread(target=job, daemon=True)
        t.start()

    def delete_query_and_response(self, query_msg_id: int, response_msg_id: int, chat_id: int):
        def job():
            try:
                time.sleep(Config.AUTO_DELETE_MATCHED_QUERY)
                try:
                    self.bot.delete_message(chat_id, response_msg_id)
                except:
                    pass
                try:
                    self.bot.delete_message(chat_id, query_msg_id)
                except:
                    pass
            except Exception:
                pass

        import threading
        t = threading.Thread(target=job, daemon=True)
        t.start()


# ==================== BOT & FLASK INIT ====================

# Validate config (raises if important envs missing)
Config.validate()

# Create Flask app and TeleBot
app = Flask(__name__)
bot = telebot.TeleBot(Config.TELEGRAM_TOKEN, parse_mode="HTML", threaded=False)

# Placeholder repository/service variables (will be initialized in Part 3)
db_manager = None
cache_manager = None
match_repo = None
admin_repo = None
session_repo = None
analytics_repo = None
rate_limiter = None
matching_service = None
validation_service = ValidationService()
auto_delete_service = AutoDeleteService(bot)


# ==================== DECORATORS ====================

def admin_only(func):
    @wraps(func)
    def wrapper(message, *args, **kwargs):
        try:
            if message.from_user.id not in Config.ADMIN_IDS:
                return
        except Exception:
            return
        return func(message, *args, **kwargs)
    return wrapper


def private_chat_only(func):
    @wraps(func)
    def wrapper(message, *args, **kwargs):
        if getattr(message, "chat", None) and message.chat.type != "private":
            return
        return func(message, *args, **kwargs)
    return wrapper


def rate_limited(func):
    @wraps(func)
    def wrapper(message, *args, **kwargs):
        uid = str(getattr(message.from_user, "id", ""))
        if rate_limiter and not rate_limiter.is_allowed(uid):
            try:
                bot.reply_to(message, "⚠️ Too many requests. Please wait.")
            except:
                pass
            return
        return func(message, *args, **kwargs)
    return wrapper


# ==================== HELPERS / UI ====================

def get_admin_menu() -> ReplyKeyboardMarkup:
    """Get admin menu keyboard"""
    markup = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    markup.add(
        KeyboardButton("➕ Add Match"),
        KeyboardButton("📋 List Matches"),
        KeyboardButton("🔍 Search"),
        KeyboardButton("✏️ Edit Match"),
        KeyboardButton("🗑️ Delete"),
        KeyboardButton("👁️ Preview"),
        KeyboardButton("📊 Stats"),
        KeyboardButton("❌ Cancel")
    )
    return markup


def get_edit_menu() -> ReplyKeyboardMarkup:
    markup = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    markup.add(
        KeyboardButton("📝 Edit Name"),
        KeyboardButton("🎯 Edit Pattern"),
        KeyboardButton("📄 Edit Caption"),
        KeyboardButton("🖼️ Edit Image"),
        KeyboardButton("🔘 Edit Buttons"),
        KeyboardButton("👁️ Preview"),
        KeyboardButton("✅ Done Editing"),
        KeyboardButton("❌ Cancel Edit")
    )
    return markup


def build_welcome_buttons() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup()
    kb.add(
        InlineKeyboardButton("📜 Rules", callback_data="show_rules"),
        InlineKeyboardButton("📝 Request Format", callback_data="show_format")
    )
    return kb


def build_inline_buttons(buttons: List[Dict]) -> Optional[InlineKeyboardMarkup]:
    if not buttons:
        return None
    kb = InlineKeyboardMarkup(row_width=1)
    for btn in buttons:
        text = btn.get("text", "Link")
        url = btn.get("url", "")
        if url:
            kb.add(InlineKeyboardButton(text, url=url))
    return kb


def safe_send_photo(chat_id: int, photo: str, caption: str = None,
                   reply_markup=None, reply_to: int = None):
    try:
        return bot.send_photo(
            chat_id,
            photo=photo,
            caption=caption,
            reply_markup=reply_markup,
            parse_mode="HTML",
            reply_to_message_id=reply_to
        )
    except Exception as e:
        logger.warning(f"Photo send failed: {e}")
        fallback_text = (caption or "Content") + "\n\n⚠️ Image unavailable"
        try:
            return bot.send_message(
                chat_id,
                fallback_text,
                reply_markup=reply_markup,
                parse_mode="HTML",
                reply_to_message_id=reply_to
            )
        except:
            return None


# ==================== COMMANDS ====================

@bot.message_handler(commands=["start"])
@private_chat_only
def cmd_start(message):
    user = message.from_user
    try:
        # Only allow admin IDs from environment
        if user.id not in Config.ADMIN_IDS:
            bot.send_message(
                message.chat.id,
                "❌ You are not authorized to use this bot."
            )
            return

        # Register admin (but only from ADMIN_IDS)
        admin_repo.create_or_update(user.id, user.username, user.first_name)

        bot.send_message(
            message.chat.id,
            f"👋 Welcome <b>{user.first_name}</b>!\n\n"
            f"🎯 Use menu buttons to manage your matches:",
            reply_markup=get_admin_menu()
        )
        logger.info(f"Admin started bot: {user.id}")

    except Exception as e:
        logger.error(f"start error: {e}")

@bot.message_handler(commands=["cancel", "help"])
@private_chat_only
@admin_only
def cmd_cancel(message):
    try:
        if session_repo:
            session_repo.delete(message.from_user.id)
        bot.send_message(
            message.chat.id,
            "✅ Ready to help! Use menu buttons:",
            reply_markup=get_admin_menu()
        )
    except Exception as e:
        logger.error(f"cancel error: {e}")


@bot.message_handler(commands=["stats"])
@private_chat_only
@admin_only
def cmd_stats(message):
    try:
        aid = str(message.from_user.id)
        stats = match_repo.col.count_documents({"admin_id": aid}), match_repo.col.count_documents({
            "admin_id": aid, "image_ref": {"$exists": True, "$ne": ""}})
        total, with_images = stats[0], stats[1]
        text = (
            f"📊 <b>Your Statistics</b>\n\n"
            f"🎯 Total Matches: {total}\n"
            f"🖼️ With Images: {with_images}\n"
            f"📄 Text Only: {total - with_images}"
        )
        if analytics_repo and Config.ENABLE_ANALYTICS:
            top = analytics_repo.get_popular_matches(5)
            if top:
                text += "\n\n<b>🔥 Most Popular:</b>\n"
                for i, p in enumerate(top, 1):
                    text += f"{i}. {p.get('name', 'Unknown')} ({p['count']} hits)\n"
        bot.send_message(message.chat.id, text, reply_markup=get_admin_menu())
    except Exception as e:
        logger.error(f"stats error: {e}")


# ==================== MENU HANDLERS ====================

@bot.message_handler(func=lambda m: m.chat.type == "private" and m.text == "➕ Add Match")
@admin_only
def menu_add_match(message):
    try:
        session = SessionData.create(message.from_user.id, "AWAIT_NAME")
        if session_repo:
            session_repo.save(session)
        bot.send_message(
            message.chat.id,
            "🎯 <b>Step 1/4: Match Name</b>\n\n"
            "📝 Send the name for this match\n\n"
            "<i>Example: Stranger Things S01</i>",
            reply_markup=ReplyKeyboardRemove()
        )
    except Exception as e:
        logger.error(f"add_match error: {e}")


@bot.message_handler(func=lambda m: m.chat.type == "private" and m.text == "📋 List Matches")
@admin_only
def menu_list_matches(message):
    try:
        aid = str(message.from_user.id)
        docs = list(match_repo.col.find({"admin_id": aid}).sort("created_at", -1).limit(50))
        if not docs:
            bot.send_message(message.chat.id, "📭 <b>No matches yet</b>\n\nCreate your first match using ➕ Add Match", reply_markup=get_admin_menu())
            return
        text = f"📋 <b>Your Matches ({len(docs)})</b>\n\n"
        for i, d in enumerate(docs, 1):
            icon = "🖼️" if d.get("image_ref") else "📄"
            name = d.get("name", "Unnamed")
            match_count = d.get("match_count", 0)
            text += f"{i}. {icon} <b>{name}</b> ({match_count} hits)\n   <code>{d['_id']}</code>\n\n"
        bot.send_message(message.chat.id, text, reply_markup=get_admin_menu())
    except Exception as e:
        logger.error(f"list_matches error: {e}")


@bot.message_handler(func=lambda m: m.chat.type == "private" and m.text == "🔍 Search")
@admin_only
def menu_search(message):
    try:
        if session_repo:
            session_repo.delete(message.from_user.id)
            session = SessionData.create(message.from_user.id, "SEARCH_MATCH")
            session_repo.save(session)
        bot.send_message(message.chat.id, "🔍 <b>Search Matches</b>\n\nSend a keyword to search:", reply_markup=ReplyKeyboardRemove())
    except Exception as e:
        logger.error(f"search error: {e}")


@bot.message_handler(func=lambda m: m.chat.type == "private" and m.text == "👁️ Preview")
@admin_only
def menu_preview(message):
    try:
        if session_repo:
            session_repo.delete(message.from_user.id)
            session = SessionData.create(message.from_user.id, "PREVIEW_MATCH")
            session_repo.save(session)
        bot.send_message(message.chat.id, "👁️ <b>Preview Match</b>\n\nSend the Match ID or Name to preview:", reply_markup=ReplyKeyboardRemove())
    except Exception as e:
        logger.error(f"preview error: {e}")


@bot.message_handler(func=lambda m: m.chat.type == "private" and m.text == "🗑️ Delete")
@admin_only
def menu_delete(message):
    try:
        if session_repo:
            session_repo.delete(message.from_user.id)
            session = SessionData.create(message.from_user.id, "DELETE_MATCH")
            session_repo.save(session)
        bot.send_message(message.chat.id, "🗑️ <b>Delete Match</b>\n\n⚠️ Send the Match ID or Name to delete:\n\n<i>This action cannot be undone!</i>", reply_markup=ReplyKeyboardRemove())
    except Exception as e:
        logger.error(f"delete error: {e}")


@bot.message_handler(func=lambda m: m.chat.type == "private" and m.text == "✏️ Edit Match")
@admin_only
def menu_edit_match(message):
    try:
        if session_repo:
            session_repo.delete(message.from_user.id)
            session = SessionData.create(message.from_user.id, "EDIT_MATCH")
            session_repo.save(session)
        bot.send_message(message.chat.id, "✏️ <b>Edit Match</b>\n\nSend the Match ID or Name to edit:", reply_markup=ReplyKeyboardRemove())
    except Exception as e:
        logger.error(f"edit_match error: {e}")


@bot.message_handler(func=lambda m: m.chat.type == "private" and m.text == "📊 Stats")
@admin_only
def menu_stats(message):
    cmd_stats(message)


@bot.message_handler(func=lambda m: m.chat.type == "private" and m.text == "❌ Cancel")
@admin_only
def menu_cancel(message):
    try:
        if session_repo:
            session_repo.delete(message.from_user.id)
        bot.send_message(message.chat.id, "✅ Operation cancelled", reply_markup=get_admin_menu())
    except Exception as e:
        logger.error(f"cancel menu error: {e}")


# ==================== TEXT MESSAGE HANDLING (ADMIN FLOWS) ====================

@bot.message_handler(func=lambda m: m.chat.type == "private" and m.text and not m.text.startswith('/'), content_types=["text"])
@admin_only
def handle_admin_text(message):
    try:
        uid = str(message.from_user.id)
        session = session_repo.get(uid) if session_repo else None
        if not session:
            return

        state = session.state
        data = session.data

        # EDIT MATCH FLOW - ask for identifier
        if state == "EDIT_MATCH":
            identifier = message.text.strip()
            m = match_repo.find_by_id_or_name(identifier, uid)
            if m:
                data["editing_match_id"] = str(m._id)
                data["editing_match"] = m.to_dict()
                session.state = "EDIT_SELECT_FIELD"
                session_repo.save(session)
                bot.send_message(
                    message.chat.id,
                    f"✏️ <b>Editing: {m.name}</b>\n\n"
                    f"🆔 <code>{m._id}</code>\n"
                    f"🎯 Pattern: {m.pattern}\n"
                    f"🖼️ Image: {'Yes' if m.image_ref else 'No'}\n"
                    f"🔘 Buttons: {len(m.buttons)}\n\nSelect what you want to edit:",
                    reply_markup=get_edit_menu()
                )
            else:
                bot.send_message(message.chat.id, "❌ Match not found or you don't have permission\n\nPlease check the Match ID or Name and try again:", reply_markup=get_admin_menu())
                session_repo.delete(uid)
            return

        # EDIT_SELECT_FIELD
        if state == "EDIT_SELECT_FIELD":
            match_id = data.get("editing_match_id")
            match_data = data.get("editing_match", {})

            txt = message.text.strip()
            if txt == "📝 Edit Name":
                session.state = "EDIT_NAME"
                session_repo.save(session)
                bot.send_message(message.chat.id, f"📝 <b>Edit Name</b>\n\nCurrent name: <b>{match_data.get('name','')}</b>\n\nSend new name:", reply_markup=ReplyKeyboardRemove())
                return

            if txt == "🎯 Edit Pattern":
                session.state = "EDIT_PATTERN"
                session_repo.save(session)
                bot.send_message(message.chat.id, f"🎯 <b>Edit Pattern</b>\n\nCurrent pattern: <code>{match_data.get('pattern','')}</code>\n\nSend new pattern (regex supported):", reply_markup=ReplyKeyboardRemove())
                return

            if txt == "📄 Edit Caption":
                session.state = "EDIT_CAPTION"
                session_repo.save(session)
                bot.send_message(message.chat.id, f"📄 <b>Edit Caption</b>\n\nCurrent caption:\n<code>{match_data.get('caption','')}</code>\n\nSend new caption:", reply_markup=ReplyKeyboardRemove())
                return

            if txt == "🖼️ Edit Image":
                session.state = "EDIT_IMAGE"
                session_repo.save(session)
                current_image = "Exists" if match_data.get("image_ref") else "None"
                bot.send_message(message.chat.id, f"🖼️ <b>Edit Image</b>\n\nCurrent image: {current_image}\n\nSend new photo or URL:\n• Send a photo to update image\n• Send URL to update image\n• Send 'remove' to remove current image\n• Send 'keep' to keep current image", reply_markup=ReplyKeyboardRemove())
                return

            if txt == "🔘 Edit Buttons":
                session.state = "EDIT_BUTTONS"
                session_repo.save(session)
                current_buttons = match_data.get("buttons", [])
                buttons_text = "\n".join([f"{b.get('text','')}|{b.get('url','')}" for b in current_buttons]) if current_buttons else "No buttons"
                bot.send_message(message.chat.id, f"🔘 <b>Edit Buttons</b>\n\nCurrent buttons:\n<code>{buttons_text}</code>\n\nSend new buttons (one per line, format: Text|URL):\n• Send 'remove' to remove all buttons\n• Send 'keep' to keep current buttons", reply_markup=ReplyKeyboardRemove())
                return

            if txt == "👁️ Preview":
                m = Match(**match_data)
                bot.send_message(message.chat.id, "👁️ <b>Current Preview:</b>")
                if m.image_ref:
                    safe_send_photo(message.chat.id, m.image_ref, caption=m.caption, reply_markup=build_inline_buttons(m.buttons))
                else:
                    bot.send_message(message.chat.id, m.caption, reply_markup=build_inline_buttons(m.buttons))
                return

            if txt == "✅ Done Editing":
                session_repo.delete(uid)
                bot.send_message(message.chat.id, "✅ Editing completed!", reply_markup=get_admin_menu())
                return

            if txt == "❌ Cancel Edit":
                session_repo.delete(uid)
                bot.send_message(message.chat.id, "❌ Edit cancelled", reply_markup=get_admin_menu())
                return

        # EDIT NAME
        if state == "EDIT_NAME":
            match_id = data.get("editing_match_id")
            new_name = validation_service.sanitize_text(message.text, 200)
            if not new_name:
                bot.reply_to(message, "⚠️ Please send a valid name")
                return
            updated = match_repo.col.update_one({"_id": ObjectId(match_id), "admin_id": str(uid)}, {"$set": {"name": new_name, "updated_at": int(time.time())}})
            if updated.modified_count > 0:
                data["editing_match"]["name"] = new_name
                session.state = "EDIT_SELECT_FIELD"
                session_repo.save(session)
                bot.send_message(message.chat.id, f"✅ Name updated to: <b>{new_name}</b>", reply_markup=get_edit_menu())
            else:
                bot.send_message(message.chat.id, "❌ Failed to update name", reply_markup=get_edit_menu())
            return

        # EDIT PATTERN
        if state == "EDIT_PATTERN":
            match_id = data.get("editing_match_id")
            new_pattern = validation_service.sanitize_text(message.text, 200)
            if not new_pattern:
                bot.reply_to(message, "⚠️ Please send a valid pattern")
                return
            updated = match_repo.col.update_one({"_id": ObjectId(match_id), "admin_id": str(uid)}, {"$set": {"pattern": new_pattern, "updated_at": int(time.time())}})
            if updated.modified_count > 0:
                data["editing_match"]["pattern"] = new_pattern
                session.state = "EDIT_SELECT_FIELD"
                session_repo.save(session)
                bot.send_message(message.chat.id, f"✅ Pattern updated to: <code>{new_pattern}</code>", reply_markup=get_edit_menu())
            else:
                bot.send_message(message.chat.id, "❌ Failed to update pattern", reply_markup=get_edit_menu())
            return

        # EDIT CAPTION
        if state == "EDIT_CAPTION":
            match_id = data.get("editing_match_id")
            new_caption = validation_service.sanitize_text(message.text, Config.MAX_CAPTION_LENGTH)
            if not new_caption:
                bot.reply_to(message, "⚠️ Please send a valid caption")
                return
            updated = match_repo.col.update_one({"_id": ObjectId(match_id), "admin_id": str(uid)}, {"$set": {"caption": new_caption, "updated_at": int(time.time())}})
            if updated.modified_count > 0:
                data["editing_match"]["caption"] = new_caption
                session.state = "EDIT_SELECT_FIELD"
                session_repo.save(session)
                bot.send_message(message.chat.id, "✅ Caption updated!", reply_markup=get_edit_menu())
            else:
                bot.send_message(message.chat.id, "❌ Failed to update caption", reply_markup=get_edit_menu())
            return

        # EDIT IMAGE (text flows)
        if state == "EDIT_IMAGE":
            match_id = data.get("editing_match_id")
            text = message.text.strip().lower() if message.text else ""
            if text == "remove":
                updated = match_repo.col.update_one({"_id": ObjectId(match_id), "admin_id": str(uid)}, {"$set": {"image_ref": None, "updated_at": int(time.time())}})
                if updated.modified_count > 0:
                    data["editing_match"]["image_ref"] = None
                    session.state = "EDIT_SELECT_FIELD"
                    session_repo.save(session)
                    bot.send_message(message.chat.id, "✅ Image removed", reply_markup=get_edit_menu())
                else:
                    bot.send_message(message.chat.id, "❌ Failed to remove image", reply_markup=get_edit_menu())
                return
            if text == "keep":
                session.state = "EDIT_SELECT_FIELD"
                session_repo.save(session)
                bot.send_message(message.chat.id, "✅ Image unchanged", reply_markup=get_edit_menu())
                return
            if validation_service.validate_url(message.text):
                url = message.text.strip()
                updated = match_repo.col.update_one({"_id": ObjectId(match_id), "admin_id": str(uid)}, {"$set": {"image_ref": url, "updated_at": int(time.time())}})
                if updated.modified_count > 0:
                    data["editing_match"]["image_ref"] = url
                    session.state = "EDIT_SELECT_FIELD"
                    session_repo.save(session)
                    safe_send_photo(message.chat.id, url, caption=data["editing_match"].get("caption",""))
                    bot.send_message(message.chat.id, "✅ Image updated!", reply_markup=get_edit_menu())
                else:
                    bot.send_message(message.chat.id, "❌ Failed to update image", reply_markup=get_edit_menu())
                return
            bot.reply_to(message, "⚠️ Send a photo, valid URL, 'remove', or 'keep'")
            return

        # EDIT BUTTONS
        if state == "EDIT_BUTTONS":
            match_id = data.get("editing_match_id")
            text = message.text.strip()
            if text.lower() == "remove":
                updated = match_repo.col.update_one({"_id": ObjectId(match_id), "admin_id": str(uid)}, {"$set": {"buttons": [], "updated_at": int(time.time())}})
                if updated.modified_count > 0:
                    data["editing_match"]["buttons"] = []
                    session.state = "EDIT_SELECT_FIELD"
                    session_repo.save(session)
                    bot.send_message(message.chat.id, "✅ All buttons removed", reply_markup=get_edit_menu())
                else:
                    bot.send_message(message.chat.id, "❌ Failed to remove buttons", reply_markup=get_edit_menu())
                return
            if text.lower() == "keep":
                session.state = "EDIT_SELECT_FIELD"
                session_repo.save(session)
                bot.send_message(message.chat.id, "✅ Buttons unchanged", reply_markup=get_edit_menu())
                return
            # Parse new buttons
            lines = message.text.strip().split("\n")
            buttons = []
            for line in lines:
                if "|" not in line:
                    continue
                left, right = line.split("|", 1)
                t = validation_service.sanitize_text(left, 100)
                u = right.strip()
                if validation_service.validate_url(u):
                    buttons.append({"text": t or "Link", "url": u})
                if len(buttons) >= Config.MAX_BUTTONS_PER_MATCH:
                    break
            updated = match_repo.col.update_one({"_id": ObjectId(match_id), "admin_id": str(uid)}, {"$set": {"buttons": buttons, "updated_at": int(time.time())}})
            if updated.modified_count > 0:
                data["editing_match"]["buttons"] = buttons
                session.state = "EDIT_SELECT_FIELD"
                session_repo.save(session)
                bot.send_message(message.chat.id, f"✅ Buttons updated! Total: {len(buttons)}", reply_markup=get_edit_menu())
            else:
                bot.send_message(message.chat.id, "❌ Failed to update buttons", reply_markup=get_edit_menu())
            return

        # PREVIEW MATCH
        if state == "PREVIEW_MATCH":
            identifier = message.text.strip()
            m = match_repo.find_by_id_or_name(identifier, uid)
            if m:
                bot.send_message(message.chat.id, f"👁️ <b>Preview: {m.name}</b>")
                if m.image_ref:
                    safe_send_photo(message.chat.id, m.image_ref, caption=m.caption, reply_markup=build_inline_buttons(m.buttons))
                else:
                    bot.send_message(message.chat.id, m.caption, reply_markup=build_inline_buttons(m.buttons))
                bot.send_message(message.chat.id, f"📊 Stats: {m.match_count} hits\n🆔 ID: <code>{m._id}</code>", reply_markup=get_admin_menu())
            else:
                bot.send_message(message.chat.id, "❌ Match not found or you don't have permission", reply_markup=get_admin_menu())
            session_repo.delete(uid)
            return

        # DELETE MATCH
        if state == "DELETE_MATCH":
            identifier = message.text.strip()
            m = match_repo.find_by_id_or_name(identifier, uid)
            if m:
                deleted = match_repo.col.delete_one({"_id": m._id, "admin_id": str(uid)})
                if deleted.deleted_count > 0:
                    bot.send_message(message.chat.id, f"✅ Deleted: <b>{m.name}</b>", reply_markup=get_admin_menu())
                    if analytics_repo:
                        analytics_repo.log_event("match_deleted", {"admin_id": str(uid), "match_id": str(m._id), "name": m.name})
                else:
                    bot.send_message(message.chat.id, "❌ Failed to delete", reply_markup=get_admin_menu())
            else:
                bot.send_message(message.chat.id, "❌ Match not found", reply_markup=get_admin_menu())
            session_repo.delete(uid)
            return

        # SEARCH MATCH
        if state == "SEARCH_MATCH":
            query = validation_service.sanitize_text(message.text, 100)
            docs = list(match_repo.col.find({
                "admin_id": str(uid),
                "$or": [{"name": {"$regex": query, "$options": "i"}}, {"pattern": {"$regex": query, "$options": "i"}}]
            }).limit(Config.MAX_SEARCH_RESULTS))
            if docs:
                text = f"🔍 <b>Found {len(docs)} result(s)</b>\n\n"
                for i, d in enumerate(docs, 1):
                    icon = "🖼️" if d.get("image_ref") else "📄"
                    text += f"{i}. {icon} <b>{d.get('name','')}</b>\n   <code>{d.get('_id')}</code>\n\n"
                bot.send_message(message.chat.id, text, reply_markup=get_admin_menu())
            else:
                bot.send_message(message.chat.id, f"❌ No results for: <b>{query}</b>", reply_markup=get_admin_menu())
            session_repo.delete(uid)
            return

        # CREATE FLOW - AWAIT_NAME
        if state == "AWAIT_NAME":
            name = validation_service.sanitize_text(message.text, 200)
            if not name:
                bot.reply_to(message, "⚠️ Please send a valid name")
                return
            # check duplicates
            if match_repo.col.count_documents({"admin_id": str(uid), "name": {"$regex": f"^{re.escape(name)}$", "$options": "i"}}) > 0:
                bot.reply_to(message, f"❌ Match name '{name}' already exists. Please use a different name.")
                return
            data["name"] = name
            data["pattern"] = name
            session.state = "AWAIT_IMAGE"
            session_repo.save(session)
            bot.send_message(message.chat.id, f"✅ Name: <b>{name}</b>\n\n🎯 <b>Step 2/4: Image</b>\n\n📸 Send a photo OR\n🔗 Send an image URL (http://...)\n\n<i>Skip: Send 'skip' to continue without image</i>")
            return

        # AWAIT_IMAGE
        if state == "AWAIT_IMAGE":
            text = message.text.strip().lower() if message.text else ""
            if text == "skip":
                name = data.get("name", "Content")
                data["caption"] = f"🎬 <b>{name}</b>\n\n✅ {name} available here 👇"
                session.state = "AWAIT_BUTTONS"
                session_repo.save(session)
                bot.send_message(message.chat.id, "✅ Skipped image\n\n🎯 <b>Step 3/4: Buttons</b>\n\n🔘 Add buttons (optional):\n<code>Button Text|https://your-link.com</code>\n\nSend one per line, or 'done' to finish")
                return
            if validation_service.validate_url(message.text):
                url = message.text.strip()
                name = data.get("name", "Content")
                data["image_ref"] = url
                data["caption"] = f"🎬 <b>{name}</b>\n\n✅ {name} available here 👇"
                session.state = "AWAIT_BUTTONS"
                session_repo.save(session)
                safe_send_photo(message.chat.id, url, caption=data["caption"])
                bot.send_message(message.chat.id, "✅ Image saved!\n\n🎯 <b>Step 3/4: Buttons</b>\n\n🔘 Add buttons (optional):\n<code>Button Text|https://your-link.com</code>\n\nSend one per line, or 'done' to finish")
                return
            bot.reply_to(message, "⚠️ Send a photo, valid URL, or 'skip'")
            return

        # AWAIT_BUTTONS
        if state == "AWAIT_BUTTONS":
            if message.text.strip().lower() == "done":
                session.state = "AWAIT_CONFIRM"
                session_repo.save(session)
                name = data.get("name", "Match")
                caption = data.get("caption", "")
                buttons = data.get("buttons", [])
                img = data.get("image_ref")
                bot.send_message(message.chat.id, "🎯 <b>Step 4/4: Confirm</b>\n\n📋 Preview:")
                if img:
                    safe_send_photo(message.chat.id, img, caption=caption, reply_markup=build_inline_buttons(buttons))
                else:
                    bot.send_message(message.chat.id, caption, reply_markup=build_inline_buttons(buttons))
                bot.send_message(message.chat.id, f"📝 <b>Summary:</b>\nName: {name}\nPattern: {data.get('pattern', name)}\nButtons: {len(buttons)}\nImage: {'Yes' if img else 'No'}\n\n✅ Send 'confirm' to create\n❌ Send 'cancel' to abort")
                return
            # parse added buttons
            lines = message.text.strip().split("\n")
            buttons = data.get("buttons", [])
            added = 0
            for line in lines:
                if "|" not in line:
                    continue
                parts = line.split("|", 1)
                t = validation_service.sanitize_text(parts[0], 100)
                u = parts[1].strip()
                if validation_service.validate_url(u):
                    buttons.append({"text": t or "Link", "url": u})
                    added += 1
                if len(buttons) >= Config.MAX_BUTTONS_PER_MATCH:
                    break
            data["buttons"] = buttons
            session_repo.save(session)
            bot.reply_to(message, f"✅ Added {added} button(s). Total: {len(buttons)}\n\nSend more buttons or 'done' to finish")
            return

        # AWAIT_CONFIRM
        if state == "AWAIT_CONFIRM":
            cmd = message.text.strip().lower()
            if cmd == "confirm":
                match = Match(
                    name=data.get("name"),
                    pattern=data.get("pattern", data.get("name")),
                    caption=data.get("caption", ""),
                    image_ref=data.get("image_ref"),
                    buttons=validation_service.validate_buttons(data.get("buttons", [])),
                    admin_id=str(uid),
                    created_at=int(time.time())
                )
                try:
                    mid = match_repo.create(match)
                    session_repo.delete(uid)
                    bot.send_message(message.chat.id, f"🎉 <b>Match Created!</b>\n\n✅ {match.name}\n🆔 <code>{mid}</code>\n\nYour match is now active!", reply_markup=get_admin_menu())
                    if analytics_repo:
                        analytics_repo.log_event("match_created", {"admin_id": str(uid), "match_id": str(mid), "name": match.name})
                except Exception as e:
                    logger.error(f"create match failed: {e}")
                    bot.send_message(message.chat.id, "❌ Failed to create match. Please try again.", reply_markup=get_admin_menu())
                return
            if cmd == "cancel":
                session_repo.delete(uid)
                bot.send_message(message.chat.id, "❌ Match creation cancelled", reply_markup=get_admin_menu())
                return
            bot.reply_to(message, "⚠️ Send 'confirm' or 'cancel'")
            return

    except Exception as e:
        logger.error(f"handle_admin_text error: {e}")


# ==================== PHOTO HANDLER ====================

@bot.message_handler(func=lambda m: m.chat.type == "private", content_types=["photo"])
@admin_only
def handle_admin_photo(message):
    try:
        uid = str(message.from_user.id)
        session = session_repo.get(uid) if session_repo else None
        if not session:
            return
        state = session.state
        data = session.data
        file_id = message.photo[-1].file_id

        if state == "EDIT_IMAGE":
            match_id = data.get("editing_match_id")
            updated = match_repo.col.update_one({"_id": ObjectId(match_id), "admin_id": str(uid)}, {"$set": {"image_ref": file_id, "updated_at": int(time.time())}})
            if updated.modified_count > 0:
                data["editing_match"]["image_ref"] = file_id
                session.state = "EDIT_SELECT_FIELD"
                session_repo.save(session)
                safe_send_photo(message.chat.id, file_id, caption=data["editing_match"].get("caption",""))
                bot.send_message(message.chat.id, "✅ Photo updated!", reply_markup=get_edit_menu())
            else:
                bot.send_message(message.chat.id, "❌ Failed to update photo", reply_markup=get_edit_menu())
            return

        if state == "AWAIT_IMAGE":
            name = data.get("name", "Content")
            data["image_ref"] = file_id
            data["caption"] = f"🎬 <b>{name}</b>\n\n✅ {name} available here 👇"
            session.state = "AWAIT_BUTTONS"
            session_repo.save(session)
            bot.send_message(message.chat.id, "⏳ Processing photo...")
            safe_send_photo(message.chat.id, file_id, caption=data["caption"])
            bot.send_message(message.chat.id, "✅ Photo saved!\n\n🎯 <b>Step 3/4: Buttons</b>\n\n🔘 Add buttons (optional):\n<code>Button Text|https://your-link.com</code>\n\nSend one per line, or 'done' to finish")
            return
    except Exception as e:
        logger.error(f"photo handler error: {e}")


# ==================== GROUP HANDLERS ====================

@bot.message_handler(func=lambda m: m.chat.type in ("group", "supergroup"), content_types=["new_chat_members"])
def handle_new_members(message):
    try:
        for member in message.new_chat_members:
            if member.id == bot.get_me().id:
                welcome_msg = bot.send_message(message.chat.id, "👋 <b>Hello! Match Bot is now active!</b>\n\n✅ Users can send queries and I'll respond automatically\n💡 Admins manage matches via private chat with me")
                auto_delete_service.delete_after(message.chat.id, welcome_msg.message_id, Config.AUTO_DELETE_WELCOME_MSG)
            else:
                name_html = f"<a href='tg://user?id={member.id}'>{member.first_name}</a>"
                welcome_text = f"Welcome {name_html}!\n\nPlease use the format to query."
                welcome_msg = bot.send_message(message.chat.id, welcome_text, reply_markup=build_welcome_buttons())
                auto_delete_service.delete_after(message.chat.id, welcome_msg.message_id, Config.AUTO_DELETE_WELCOME_MSG)
                logger.info(f"Welcomed user: {member.id}")
    except Exception as e:
        logger.error(f"welcome error: {e}")


@bot.callback_query_handler(func=lambda c: c.data in ("show_rules", "show_format"))
def handle_info_buttons(call):
    try:
        if call.data == "show_rules":
            bot.answer_callback_query(call.id, "Showing rules...")
            rules_msg = bot.send_message(call.message.chat.id, "Rules: Do not spam.")
            auto_delete_service.delete_after(call.message.chat.id, rules_msg.message_id, Config.AUTO_DELETE_WELCOME_MSG)
        elif call.data == "show_format":
            bot.answer_callback_query(call.id, "Showing request format...")
            fmt_msg = bot.send_message(call.message.chat.id, "Format: Movie name")
            auto_delete_service.delete_after(call.message.chat.id, fmt_msg.message_id, Config.AUTO_DELETE_WELCOME_MSG)
    except Exception as e:
        logger.error(f"callback error: {e}")


@bot.message_handler(func=lambda m: m.chat.type in ("group", "supergroup"), content_types=["text"])
@rate_limited
def handle_group_message(message):
    try:
        if not message.text or message.text.startswith('/') or len(message.text) < 2:
            return
        text = validation_service.sanitize_text(message.text, 500)
        match = matching_service.find_match(text) if matching_service else None
        if match:
            caption = match.caption.replace("{query}", text).replace("{user}", message.from_user.first_name)
            if match.image_ref:
                response_msg = safe_send_photo(message.chat.id, match.image_ref, caption=caption, reply_markup=build_inline_buttons(match.buttons), reply_to=message.message_id)
            else:
                response_msg = bot.reply_to(message, caption, reply_markup=build_inline_buttons(match.buttons))
            if response_msg:
                auto_delete_service.delete_query_and_response(message.message_id, response_msg.message_id, message.chat.id)
            logger.info(f"Match found: {match.name} for query: {text[:50]}")
            if analytics_repo:
                analytics_repo.log_event("query_matched", {
                    "match_id": str(match._id),
                    "match_name": match.name,
                    "query": text[:100],
                    "user_id": message.from_user.id,
                    "chat_id": message.chat.id
                })
    except Exception as e:
        logger.error(f"group message error: {e}")

# End of Part 2
# ==================== PART 3 / 3 ====================
# ==================== ANALYTICS REPOSITORY ====================

class AnalyticsRepository:
    def __init__(self, db):
        self.col = db.analytics

    def log_event(self, event_type: str, data: Dict[str, Any]):
        try:
            doc = {
                "event_type": event_type,
                "data": data,
                "timestamp": int(time.time())
            }
            self.col.insert_one(doc)
        except Exception as e:
            logger.error(f"Analytics log error: {e}")

    def get_popular_matches(self, limit: int = 10):
        try:
            pipeline = [
                {"$match": {"event_type": "query_matched"}},
                {"$group": {"_id": "$data.match_id", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": limit},
                {"$lookup": {
                    "from": "matches",
                    "localField": "_id",
                    "foreignField": "_id",
                    "as": "match"
                }},
                {"$unwind": {"path": "$match", "preserveNullAndEmptyArrays": True}},
                {"$project": {
                    "match_id": "$_id",
                    "count": 1,
                    "name": "$match.name"
                }}
            ]
            return list(self.col.aggregate(pipeline))
        except Exception as e:
            logger.error(f"Analytics fetch error: {e}")
            return []


# ==================== SESSION REPOSITORY ====================

class SessionRepository:
    def __init__(self, db):
        self.col = db.sessions

    def save(self, session: SessionData):
        try:
            self.col.update_one(
                {"admin_id": str(session.admin_id)},
                {"$set": {
                    "state": session.state,
                    "data": session.data,
                    "created_at": session.created_at,
                    "expires_at": session.expires_at
                }},
                upsert=True
            )
        except Exception as e:
            logger.error(f"Session save error: {e}")

    def get(self, admin_id: str) -> Optional[SessionData]:
        try:
            doc = self.col.find_one({"admin_id": str(admin_id)})
            if not doc:
                return None
            if doc["expires_at"] < int(time.time()):
                self.delete(admin_id)
                return None
            return SessionData(
                admin_id=doc["admin_id"],
                state=doc["state"],
                data=doc.get("data", {}),
                created_at=doc["created_at"],
                expires_at=doc["expires_at"]
            )
        except Exception as e:
            logger.error(f"Session get error: {e}")
            return None

    def delete(self, admin_id: str):
        try:
            self.col.delete_one({"admin_id": str(admin_id)})
        except Exception as e:
            logger.error(f"Session delete error: {e}")


# ==================== ADMIN REPOSITORY ====================

class AdminRepository:
    def __init__(self, db):
        self.col = db.admins

    def is_admin(self, user_id: int) -> bool:
        try:
            return bool(self.col.find_one({"user_id": str(user_id)}))
        except:
            return False

    def create_or_update(self, user_id: int, username: str, first_name: str):
        try:
            self.col.update_one(
                {"user_id": str(user_id)},
                {"$set": {"username": username, "first_name": first_name}},
                upsert=True
            )
        except Exception as e:
            logger.error(f"Admin upsert error: {e}")


# ==================== INITIALIZATION ====================

def initialize():
    global db_manager, cache_manager, match_repo
    global admin_repo, session_repo, analytics_repo
    global rate_limiter, matching_service

    db_manager = DatabaseConnection(Config.MONGODB_URI, Config.DB_NAME)
    cache_manager = CacheManager(Config.REDIS_URL, Config.USE_REDIS)

    match_repo = MatchRepository(db_manager.db, cache_manager)
    admin_repo = AdminRepository(db_manager.db)
    session_repo = SessionRepository(db_manager.db)
    analytics_repo = AnalyticsRepository(db_manager.db) if Config.ENABLE_ANALYTICS else None

    rate_limiter = RateLimiter(cache_manager)
    matching_service = MatchingService(match_repo, analytics_repo)

    logger.info("Initialization complete.")


initialize()


# ==================== WEBHOOK SETUP ====================

def setup_webhook():
    try:
        bot.remove_webhook()
        time.sleep(1)
        bot.set_webhook(url=Config.WEBHOOK_URL + Config.WEBHOOK_PATH)
        logger.info("Webhook set!")
    except Exception as e:
        logger.error(f"Webhook setup error: {e}")


setup_webhook()


# ==================== FLASK ROUTES ====================

@app.route(Config.WEBHOOK_PATH, methods=["POST"])
def webhook():
    try:
        if request.headers.get("content-type") == "application/json":
            json_str = request.get_data(as_text=True)
            update = telebot.types.Update.de_json(json_str)
            bot.process_new_updates([update])
            return "OK", 200
        abort(403)
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return "ERROR", 500


@app.route("/", methods=["GET"])
def index():
    return jsonify({"status": "running", "bot": bot.get_me().username})


# ==================== BOT POLLING FALLBACK ====================

def run_polling():
    logger.warning("⚠️ Starting polling mode (useful if webhook fails) ...")
    bot.infinity_polling(timeout=30, long_polling_timeout=10)


# ==================== MAIN ENTRY ====================

if __name__ == "__main__":
    if Config.DEBUG:
        run_polling()
    else:
        app.run(host="0.0.0.0", port=5000)
