"""
PRODUCTION-GRADE TELEGRAM MATCH BOT
====================================
Enterprise architecture with:
- Service Layer Pattern
- Repository Pattern  
- Middleware System
- Redis Caching
- Error Recovery
- Rate Limiting
- Comprehensive Logging
- Transaction Safety
- Background Tasks
- Analytics
"""

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

# ==================== CONFIGURATION ====================

class Config:
    """Centralized configuration management"""
    
    # Telegram
    TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
    WEBHOOK_URL = os.getenv("WEBHOOK_URL")
    WEBHOOK_PATH = os.getenv("WEBHOOK_PATH", "/webhook")
    
    # Database
    MONGODB_URI = os.getenv("MONGODB_URI")
    DB_NAME = os.getenv("DB_NAME", "tg_bot_db")
    
    # Redis (optional - will work without it)
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    USE_REDIS = os.getenv("USE_REDIS", "true").lower() == "true"
    
    # Security
    RATE_LIMIT_MESSAGES = int(os.getenv("RATE_LIMIT_MESSAGES", "5"))
    RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))
    MAX_BUTTONS_PER_MATCH = int(os.getenv("MAX_BUTTONS_PER_MATCH", "10"))
    MAX_CAPTION_LENGTH = int(os.getenv("MAX_CAPTION_LENGTH", "1024"))
    
    # Performance
    CACHE_TTL = int(os.getenv("CACHE_TTL", "300"))
    MAX_SEARCH_RESULTS = int(os.getenv("MAX_SEARCH_RESULTS", "50"))
    QUERY_TIMEOUT = int(os.getenv("QUERY_TIMEOUT", "5"))
    
    # Features
    ENABLE_ANALYTICS = os.getenv("ENABLE_ANALYTICS", "true").lower() == "true"
    ENABLE_AUTO_BACKUP = os.getenv("ENABLE_AUTO_BACKUP", "false").lower() == "true"
    
    # Flask
    PORT = int(os.getenv("PORT", "5000"))
    DEBUG = os.getenv("DEBUG", "false").lower() == "true"
    
    @classmethod
    def validate(cls):
        """Validate required configuration"""
        required = ["TELEGRAM_TOKEN", "WEBHOOK_URL", "MONGODB_URI"]
        missing = [k for k in required if not getattr(cls, k)]
        if missing:
            raise RuntimeError(f"Missing required config: {', '.join(missing)}")


# ==================== LOGGING ====================

class CustomFormatter(logging.Formatter):
    """Colored logging formatter"""
    
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
    """Configure application logging"""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO if not Config.DEBUG else logging.DEBUG)
    
    # Console handler
    handler = logging.StreamHandler()
    handler.setFormatter(CustomFormatter())
    logger.addHandler(handler)
    
    # Suppress noisy libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("telebot").setLevel(logging.WARNING)
    
    return logging.getLogger(__name__)


logger = setup_logging()


# ==================== CONSTANTS ====================

class SessionState(Enum):
    """Session states for admin flows"""
    IDLE = "idle"
    AWAIT_NAME = "await_name"
    AWAIT_IMAGE = "await_image"
    AWAIT_BUTTONS = "await_buttons"
    AWAIT_CONFIRM = "await_confirm"
    SEARCH_MATCH = "search_match"
    PREVIEW_MATCH = "preview_match"
    DELETE_MATCH = "delete_match"


class AdminRole(Enum):
    """Admin roles for future RBAC"""
    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"
    MODERATOR = "moderator"


# Fixed welcome messages
WELCOME_MESSAGE = """Welcome {name} 👋

👇👇
{req_format}

ஏதேனும் கேட்கும் முன்பு, இதை படிக்கவும் 👍

Thank You ❤️"""

REQUEST_FORMAT = """{𝙍𝙚𝙦𝙪𝙚𝙨𝙩 𝙁𝙤𝙧𝙢𝙖𝙩}

🫵𝖥𝗂𝗋𝗌𝗍 𝖦𝗈𝗈𝗀𝗅𝖾 𝗂𝗍 𝗆𝗈𝗏𝗂𝖾 𝗌𝗉𝖾𝗅𝗅𝗂𝗇𝗀 𝖳𝗁𝖾𝗇 𝖯𝖺𝗌𝗍𝖾 𝖧𝖾𝗋𝖾

➠ 𝗙𝗢𝗥 𝗠𝗢𝗩𝗜𝗘𝗦 🎬
→ Vikram (or)
→ Vikram 2022 Tam (or)
→ Vikram 2022 Tamil (or)
→ Vikram Tamil

➠ 𝗙𝗢𝗥 𝗦𝗘𝗥𝗜𝗘𝗦 🍿
→ The Family Man S01 (or)
→ The Family Man S01 720p Tamil (or)
→ The Family Man S01 720p Tam

👇👇👇
Thank You ❤️"""

RULES_MESSAGE = """Rules

✘ Don't share or promote your own channels or any links; it will lead to your ban.

✔ Ask whatever you want with the correct format of movies and series names."""


# ==================== DATA MODELS ====================

@dataclass
class Button:
    """Button model"""
    text: str
    url: str
    
    def validate(self) -> bool:
        """Validate button data"""
        if not self.text or len(self.text) > 100:
            return False
        if not self.url or not (self.url.startswith('http://') or self.url.startswith('https://')):
            return False
        return True


@dataclass
class Match:
    """Match model"""
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
        if self.created_at is None:
            self.created_at = int(time.time())
        if self.pattern is None or self.pattern.strip() == "":
            self.pattern = self.name
    
    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB"""
        data = asdict(self)
        if self._id:
            data['_id'] = self._id
        return data


@dataclass
class SessionData:
    """Session data model"""
    admin_id: str
    state: SessionState
    data: Dict[str, Any]
    created_at: int
    expires_at: int
    
    @staticmethod
    def create(admin_id: str, state: SessionState = SessionState.IDLE, ttl: int = 600):
        """Create new session"""
        now = int(time.time())
        return SessionData(
            admin_id=str(admin_id),
            state=state,
            data={},
            created_at=now,
            expires_at=now + ttl
        )


# ==================== DATABASE LAYER ====================

class DatabaseConnection:
    """MongoDB connection manager with retry logic"""
    
    def __init__(self, uri: str, db_name: str, max_retries: int = 3):
        self.uri = uri
        self.db_name = db_name
        self.max_retries = max_retries
        self._client = None
        self._db = None
        self.connect()
    
    def connect(self):
        """Establish database connection with retry"""
        for attempt in range(self.max_retries):
            try:
                self._client = MongoClient(
                    self.uri,
                    serverSelectionTimeoutMS=5000,
                    connectTimeoutMS=10000,
                    socketTimeoutMS=10000,
                    maxPoolSize=50,
                    retryWrites=True
                )
                self._client.server_info()
                self._db = self._client[self.db_name]
                self._setup_indexes()
                logger.info("✅ MongoDB connected successfully")
                return
            except Exception as e:
                logger.error(f"❌ MongoDB connection attempt {attempt + 1} failed: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)
                else:
                    raise RuntimeError("Failed to connect to MongoDB after retries")
    
    def _setup_indexes(self):
        """Create database indexes for performance"""
        try:
            # Matches indexes
            self._db.matches.create_index([("admin_id", ASCENDING)])
            self._db.matches.create_index([("name", ASCENDING)])
            self._db.matches.create_index([("pattern", ASCENDING)])
            self._db.matches.create_index([("created_at", DESCENDING)])
            self._db.matches.create_index([("match_count", DESCENDING)])
            
            # Text index for fuzzy search
            self._db.matches.create_index([("name", "text"), ("pattern", "text")])
            
            # Admins indexes
            self._db.admins.create_index([("user_id", ASCENDING)], unique=True)
            
            # Analytics indexes
            if Config.ENABLE_ANALYTICS:
                self._db.analytics.create_index([("event_type", ASCENDING), ("timestamp", DESCENDING)])
                self._db.analytics.create_index([("match_id", ASCENDING)])
            
            logger.info("✅ Database indexes created")
        except Exception as e:
            logger.warning(f"⚠️ Index creation warning: {e}")
    
    @property
    def db(self):
        """Get database instance"""
        if self._client is None:
            self.connect()
        return self._db
    
    def health_check(self) -> bool:
        """Check database health"""
        try:
            self._client.admin.command('ping')
            return True
        except:
            return False


class CacheManager:
    """Redis cache manager (optional)"""
    
    def __init__(self, redis_url: str, enabled: bool = True):
        self.enabled = enabled and redis_url
        self._client = None
        
        if self.enabled:
            try:
                self._client = Redis.from_url(redis_url, decode_responses=True)
                self._client.ping()
                logger.info("✅ Redis cache connected")
            except Exception as e:
                logger.warning(f"⚠️ Redis unavailable, running without cache: {e}")
                self.enabled = False
    
    def get(self, key: str) -> Optional[str]:
        """Get cached value"""
        if not self.enabled:
            return None
        try:
            return self._client.get(key)
        except RedisError:
            return None
    
    def set(self, key: str, value: str, ttl: int = Config.CACHE_TTL):
        """Set cached value"""
        if not self.enabled:
            return
        try:
            self._client.setex(key, ttl, value)
        except RedisError:
            pass
    
    def delete(self, key: str):
        """Delete cached value"""
        if not self.enabled:
            return
        try:
            self._client.delete(key)
        except RedisError:
            pass
    
    def clear_pattern(self, pattern: str):
        """Clear keys matching pattern"""
        if not self.enabled:
            return
        try:
            keys = self._client.keys(pattern)
            if keys:
                self._client.delete(*keys)
        except RedisError:
            pass


# ==================== REPOSITORIES ====================

class MatchRepository:
    """Repository for match operations"""
    
    def __init__(self, db, cache: CacheManager):
        self.collection = db.matches
        self.cache = cache
    
    def create(self, match: Match) -> ObjectId:
        """Create new match"""
        try:
            result = self.collection.insert_one(match.to_dict())
            self.cache.clear_pattern(f"matches:*")
            logger.info(f"✅ Match created: {match.name}")
            return result.inserted_id
        except mongo_errors.PyMongoError as e:
            logger.error(f"❌ Failed to create match: {e}")
            raise
    
    def find_by_id(self, match_id: str, admin_id: str) -> Optional[Match]:
        """Find match by ID"""
        try:
            doc = self.collection.find_one({
                "_id": ObjectId(match_id),
                "admin_id": admin_id
            })
            return Match(**doc) if doc else None
        except Exception as e:
            logger.error(f"❌ Find by ID error: {e}")
            return None
    
    def find_all_active(self) -> List[Match]:
        """Get all active matches (cached)"""
        cache_key = "matches:all_active"
        cached = self.cache.get(cache_key)
        
        if cached:
            import json
            return [Match(**m) for m in json.loads(cached)]
        
        try:
            docs = list(self.collection.find().sort("created_at", DESCENDING))
            matches = [Match(**doc) for doc in docs]
            
            # Cache results
            import json
            self.cache.set(cache_key, json.dumps([asdict(m) for m in matches]))
            
            return matches
        except Exception as e:
            logger.error(f"❌ Find all error: {e}")
            return []
    
    def search(self, admin_id: str, query: str, limit: int = 50) -> List[Match]:
        """Search matches by name/pattern"""
        try:
            docs = list(self.collection.find({
                "admin_id": admin_id,
                "$or": [
                    {"name": {"$regex": query, "$options": "i"}},
                    {"pattern": {"$regex": query, "$options": "i"}}
                ]
            }).limit(limit))
            return [Match(**doc) for doc in docs]
        except Exception as e:
            logger.error(f"❌ Search error: {e}")
            return []
    
    def delete(self, match_id: str, admin_id: str) -> bool:
        """Delete match"""
        try:
            result = self.collection.delete_one({
                "_id": ObjectId(match_id),
                "admin_id": admin_id
            })
            if result.deleted_count > 0:
                self.cache.clear_pattern(f"matches:*")
                logger.info(f"✅ Match deleted: {match_id}")
                return True
            return False
        except Exception as e:
            logger.error(f"❌ Delete error: {e}")
            return False
    
    def increment_match_count(self, match_id: ObjectId):
        """Increment match counter"""
        try:
            self.collection.update_one(
                {"_id": match_id},
                {"$inc": {"match_count": 1}}
            )
        except Exception:
            pass
    
    def get_stats(self, admin_id: str) -> Dict[str, int]:
        """Get admin statistics"""
        try:
            total = self.collection.count_documents({"admin_id": admin_id})
            with_image = self.collection.count_documents({
                "admin_id": admin_id,
                "image_ref": {"$exists": True, "$ne": ""}
            })
            return {"total": total, "with_images": with_image}
        except Exception as e:
            logger.error(f"❌ Stats error: {e}")
            return {"total": 0, "with_images": 0}


class AdminRepository:
    """Repository for admin operations"""
    
    def __init__(self, db):
        self.collection = db.admins
    
    def create_or_update(self, user_id: str, username: str = None, 
                        first_name: str = None, role: AdminRole = AdminRole.ADMIN):
        """Create or update admin"""
        try:
            self.collection.update_one(
                {"user_id": str(user_id)},
                {"$set": {
                    "user_id": str(user_id),
                    "username": username,
                    "first_name": first_name,
                    "role": role.value,
                    "updated_at": int(time.time())
                }, "$setOnInsert": {
                    "created_at": int(time.time())
                }},
                upsert=True
            )
            logger.info(f"✅ Admin registered: {user_id}")
        except Exception as e:
            logger.error(f"❌ Admin create error: {e}")
    
    def is_admin(self, user_id: str) -> bool:
        """Check if user is admin"""
        return self.collection.find_one({"user_id": str(user_id)}) is not None
    
    def get_all(self) -> List[Dict]:
        """Get all admins"""
        try:
            return list(self.collection.find())
        except Exception:
            return []


class SessionRepository:
    """Repository for session management"""
    
    def __init__(self, db, cache: CacheManager):
        self.collection = db.sessions
        self.cache = cache
        self.use_redis = cache.enabled
    
    def _get_cache_key(self, admin_id: str) -> str:
        return f"session:{admin_id}"
    
    def get(self, admin_id: str) -> Optional[SessionData]:
        """Get session"""
        cache_key = self._get_cache_key(admin_id)
        
        if self.use_redis:
            import json
            cached = self.cache.get(cache_key)
            if cached:
                data = json.loads(cached)
                data['state'] = SessionState(data['state'])
                return SessionData(**data)
        
        doc = self.collection.find_one({"admin_id": str(admin_id)})
        if doc:
            doc['state'] = SessionState(doc['state'])
            return SessionData(**doc)
        return None
    
    def save(self, session: SessionData):
        """Save session"""
        cache_key = self._get_cache_key(session.admin_id)
        data = asdict(session)
        data['state'] = session.state.value
        
        if self.use_redis:
            import json
            ttl = session.expires_at - int(time.time())
            if ttl > 0:
                self.cache.set(cache_key, json.dumps(data), ttl)
        
        self.collection.replace_one(
            {"admin_id": session.admin_id},
            data,
            upsert=True
        )
    
    def delete(self, admin_id: str):
        """Delete session"""
        cache_key = self._get_cache_key(admin_id)
        self.cache.delete(cache_key)
        self.collection.delete_one({"admin_id": str(admin_id)})
    
    def cleanup_expired(self):
        """Clean up expired sessions"""
        now = int(time.time())
        self.collection.delete_many({"expires_at": {"$lt": now}})


class AnalyticsRepository:
    """Repository for analytics (optional)"""
    
    def __init__(self, db, enabled: bool):
        self.collection = db.analytics
        self.enabled = enabled
    
    def log_event(self, event_type: str, data: Dict[str, Any]):
        """Log analytics event"""
        if not self.enabled:
            return
        
        try:
            self.collection.insert_one({
                "event_type": event_type,
                "data": data,
                "timestamp": int(time.time())
            })
        except Exception:
            pass  # Don't fail on analytics errors
    
    def get_popular_matches(self, limit: int = 10) -> List[Dict]:
        """Get most popular matches"""
        if not self.enabled:
            return []
        
        try:
            pipeline = [
                {"$match": {"event_type": "match_found"}},
                {"$group": {
                    "_id": "$data.match_id",
                    "count": {"$sum": 1},
                    "name": {"$first": "$data.match_name"}
                }},
                {"$sort": {"count": -1}},
                {"$limit": limit}
            ]
            return list(self.collection.aggregate(pipeline))
        except Exception:
            return []


# ==================== SERVICES ====================

class RateLimiter:
    """Rate limiting service"""
    
    def __init__(self, cache: CacheManager):
        self.cache = cache
    
    def is_allowed(self, user_id: str, limit: int = Config.RATE_LIMIT_MESSAGES,
                   window: int = Config.RATE_LIMIT_WINDOW) -> bool:
        """Check if user is within rate limit"""
        if not self.cache.enabled:
            return True  # No rate limiting without Redis
        
        key = f"ratelimit:{user_id}"
        try:
            count = self.cache._client.incr(key)
            if count == 1:
                self.cache._client.expire(key, window)
            return count <= limit
        except:
            return True  # Allow on error


class MatchingService:
    """Service for matching user queries"""
    
    def __init__(self, match_repo: MatchRepository, analytics_repo: AnalyticsRepository):
        self.match_repo = match_repo
        self.analytics_repo = analytics_repo
        self._compile_cache = {}
    
    def find_match(self, query: str) -> Optional[Match]:
        """Find matching pattern for query"""
        query_lower = query.lower().strip()
        
        # Get all matches (cached)
        matches = self.match_repo.find_all_active()
        
        for match in matches:
            if self._matches_pattern(query_lower, match):
                # Update statistics
                self.match_repo.increment_match_count(match._id)
                self.analytics_repo.log_event("match_found", {
                    "match_id": str(match._id),
                    "match_name": match.name,
                    "query": query
                })
                return match
        
        return None
    
    def _matches_pattern(self, query: str, match: Match) -> bool:
        """Check if query matches pattern"""
        pattern = match.pattern.strip()
        
        # Try regex matching with cache
        cache_key = f"pattern:{pattern}"
        if cache_key not in self._compile_cache:
            try:
                self._compile_cache[cache_key] = re.compile(pattern, re.IGNORECASE)
            except re.error:
                # Fallback to simple substring
                self._compile_cache[cache_key] = None
        
        regex = self._compile_cache[cache_key]
        
        if regex:
            return bool(regex.search(query))
        else:
            # Simple substring matching
            return pattern.lower() in query


class ValidationService:
    """Input validation service"""
    
    @staticmethod
    def sanitize_text(text: str, max_length: int = 1000) -> str:
        """Sanitize user input"""
        if not text:
            return ""
        # Remove potential HTML/script tags
        text = re.sub(r'<[^>]+>', '', text)
        return text[:max_length].strip()
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL"""
        if not url:
            return False
        return url.startswith('http://') or url.startswith('https://')
    
    @staticmethod
    def validate_buttons(buttons: List[Dict]) -> List[Button]:
        """Validate and convert button data"""
        valid_buttons = []
        for btn in buttons[:Config.MAX_BUTTONS_PER_MATCH]:
            try:
                button = Button(
                    text=ValidationService.sanitize_text(btn.get('text', ''), 100),
                    url=btn.get('url', '')
                )
                if button.validate():
                    valid_buttons.append(asdict(button))
            except:
                continue
        return valid_buttons


# ==================== BOT SETUP ====================

# Initialize components
Config.validate()
db_manager = DatabaseConnection(Config.MONGODB_URI, Config.DB_NAME)
cache_manager = CacheManager(Config.REDIS_URL, Config.USE_REDIS)

# Initialize repositories
match_repo = MatchRepository(db_manager.db, cache_manager)
admin_repo = AdminRepository(db_manager.db)
session_repo = SessionRepository(db_manager.db, cache_manager)
analytics_repo = AnalyticsRepository(db_manager.db, Config.ENABLE_ANALYTICS)

# Initialize services
rate_limiter = RateLimiter(cache_manager)
matching_service = MatchingService(match_repo, analytics_repo)
validation_service = ValidationService()

# Initialize bot
bot = telebot.TeleBot(Config.TELEGRAM_TOKEN, parse_mode="HTML", threaded=False)
app = Flask(__name__)


# ==================== DECORATORS ====================

def admin_only(func):
    """Decorator for admin-only functions"""
    @wraps(func)
    def wrapper(message, *args, **kwargs):
        if not admin_repo.is_admin(message.from_user.id):
            return
        return func(message, *args, **kwargs)
    return wrapper


def private_chat_only(func):
    """Decorator for private chat only"""
    @wraps(func)
    def wrapper(message, *args, **kwargs):
        if message.chat.type != "private":
            return
        return func(message, *args, **kwargs)
    return wrapper


def rate_limited(func):
    """Decorator for rate limiting"""
    @wraps(func)
    def wrapper(message, *args, **kwargs):
        if not rate_limiter.is_allowed(message.from_user.id):
            bot.reply_to(message, "⚠️ Too many requests. Please wait.")
            return
        return func(message, *args, **kwargs)
    return wrapper


# ==================== HELPER FUNCTIONS ====================

def get_admin_menu() -> ReplyKeyboardMarkup:
    """Get admin menu keyboard"""
    markup = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    markup.add(
        KeyboardButton("➕ Add Match"),
        KeyboardButton("📋 List Matches"),
        KeyboardButton("🔍 Search"),
        KeyboardButton("🗑️ Delete"),
        KeyboardButton("👁️ Preview"),
        KeyboardButton("📊 Stats"),
        KeyboardButton("❌ Cancel")
    )
    return markup


def build_welcome_buttons() -> InlineKeyboardMarkup:
    """Build welcome message buttons"""
    kb = InlineKeyboardMarkup()
    kb.add(
        InlineKeyboardButton("📜 Rules", callback_data="show_rules"),
        InlineKeyboardButton("📝 Request Format", callback_data="show_format")
    )
    return kb


def build_inline_buttons(buttons: List[Dict]) -> Optional[InlineKeyboardMarkup]:
    """Build inline keyboard from button list"""
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
    """Safely send photo with fallback"""
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
        return bot.send_message(
            chat_id,
            fallback_text,
            reply_markup=reply_markup,
            parse_mode="HTML",
            reply_to_message_id=reply_to
        )
            reply_markup=reply_markup,
            parse_mode="HTML",
            reply_to_message_id=reply_to
        )


# ==================== BOT COMMANDS ====================

@bot.message_handler(commands=["start"])
@private_chat_only
def cmd_start(message):
    """Handle /start command"""
    user = message.from_user
    
    if not admin_repo.is_admin(user.id):
        admin_repo.create_or_update(user.id, user.username, user.first_name)
        text = (
            f"👋 Welcome <b>{user.first_name}</b>!\n\n"
            f"✅ You've been registered as an admin\n\n"
            f"💡 Use the menu buttons below to manage matches:"
        )
    else:
        text = (
            f"👋 Welcome back <b>{user.first_name}</b>!\n\n"
            f"🎯 Use menu buttons to manage your matches:"
        )
    
    bot.send_message(message.chat.id, text, reply_markup=get_admin_menu())
    logger.info(f"Admin started bot: {user.id}")


@bot.message_handler(commands=["cancel", "help"])
@private_chat_only
@admin_only
def cmd_cancel(message):
    """Handle /cancel and /help commands"""
    session_repo.delete(message.from_user.id)
    bot.send_message(
        message.chat.id,
        "✅ Ready to help! Use menu buttons:",
        reply_markup=get_admin_menu()
    )


@bot.message_handler(commands=["stats"])
@private_chat_only
@admin_only
def cmd_stats(message):
    """Show detailed statistics"""
    aid = str(message.from_user.id)
    stats = match_repo.get_stats(aid)
    
    text = (
        f"📊 <b>Your Statistics</b>\n\n"
        f"🎯 Total Matches: {stats['total']}\n"
        f"🖼️ With Images: {stats['with_images']}\n"
        f"📄 Text Only: {stats['total'] - stats['with_images']}"
    )
    
    if Config.ENABLE_ANALYTICS:
        popular = analytics_repo.get_popular_matches(5)
        if popular:
            text += "\n\n<b>🔥 Most Popular:</b>\n"
            for i, p in enumerate(popular, 1):
                text += f"{i}. {p.get('name', 'Unknown')} ({p['count']} hits)\n"
    
    bot.send_message(message.chat.id, text, reply_markup=get_admin_menu())

# ==================== MENU HANDLERS ====================

@bot.message_handler(func=lambda m: m.chat.type == "private" and m.text == "➕ Add Match")
@admin_only
def menu_add_match(message):
    """Start match creation flow"""
    session = SessionData.create(message.from_user.id, SessionState.AWAIT_NAME)
    session_repo.save(session)
    
    bot.send_message(
        message.chat.id,
        "🎯 <b>Step 1/4: Match Name</b>\n\n"
        "📝 Send the name for this match\n\n"
        "<i>Example: Stranger Things S01</i>",
        reply_markup=ReplyKeyboardRemove()
    )


@bot.message_handler(func=lambda m: m.chat.type == "private" and m.text == "📋 List Matches")
@admin_only
def menu_list_matches(message):
    """List all matches"""
    aid = str(message.from_user.id)
    docs = list(match_repo.collection.find({"admin_id": aid}).sort("created_at", -1).limit(50))
    
    if not docs:
        bot.send_message(
            message.chat.id,
            "📭 <b>No matches yet</b>\n\nCreate your first match using ➕ Add Match",
            reply_markup=get_admin_menu()
        )
        return
    
    text = f"📋 <b>Your Matches ({len(docs)})</b>\n\n"
    for i, d in enumerate(docs, 1):
        icon = "🖼️" if d.get('image_ref') else "📄"
        name = d.get('name', 'Unnamed')
        match_count = d.get('match_count', 0)
        text += f"{i}. {icon} <b>{name}</b> ({match_count} hits)\n   <code>{d['_id']}</code>\n\n"
    
    bot.send_message(message.chat.id, text, reply_markup=get_admin_menu())


@bot.message_handler(func=lambda m: m.chat.type == "private" and m.text == "🔍 Search")
@admin_only
def menu_search(message):
    """Start search flow"""
    session_repo.delete(message.from_user.id)
    session = SessionData.create(message.from_user.id, SessionState.SEARCH_MATCH)
    session_repo.save(session)
    
    bot.send_message(
        message.chat.id,
        "🔍 <b>Search Matches</b>\n\nSend a keyword to search:",
        reply_markup=ReplyKeyboardRemove()
    )


@bot.message_handler(func=lambda m: m.chat.type == "private" and m.text == "👁️ Preview")
@admin_only
def menu_preview(message):
    """Start preview flow"""
    session_repo.delete(message.from_user.id)
    session = SessionData.create(message.from_user.id, SessionState.PREVIEW_MATCH)
    session_repo.save(session)
    
    bot.send_message(
        message.chat.id,
        "👁️ <b>Preview Match</b>\n\nSend the Match ID to preview:",
        reply_markup=ReplyKeyboardRemove()
    )


@bot.message_handler(func=lambda m: m.chat.type == "private" and m.text == "🗑️ Delete")
@admin_only
def menu_delete(message):
    """Start delete flow"""
    session_repo.delete(message.from_user.id)
    session = SessionData.create(message.from_user.id, SessionState.DELETE_MATCH)
    session_repo.save(session)
    
    bot.send_message(
        message.chat.id,
        "🗑️ <b>Delete Match</b>\n\n⚠️ Send the Match ID to delete:\n\n"
        "<i>This action cannot be undone!</i>",
        reply_markup=ReplyKeyboardRemove()
    )


@bot.message_handler(func=lambda m: m.chat.type == "private" and m.text == "📊 Stats")
@admin_only
def menu_stats(message):
    """Show statistics"""
    cmd_stats(message)


@bot.message_handler(func=lambda m: m.chat.type == "private" and m.text == "❌ Cancel")
@admin_only
def menu_cancel(message):
    """Cancel current operation"""
    session_repo.delete(message.from_user.id)
    bot.send_message(
        message.chat.id,
        "✅ Operation cancelled",
        reply_markup=get_admin_menu()
    )


# ==================== MATCH CREATION FLOW ====================

@bot.message_handler(func=lambda m: m.chat.type == "private" and m.text and not m.text.startswith('/'), 
                    content_types=["text"])
@admin_only
def handle_admin_text(message):
    """Handle text input in admin flows"""
    uid = message.from_user.id
    session = session_repo.get(uid)
    
    if not session:
        return
    
    state = session.state
    data = session.data
    
    # STEP 1: Await Name
    if state == SessionState.AWAIT_NAME:
        name = validation_service.sanitize_text(message.text, 200)
        if not name:
            bot.reply_to(message, "⚠️ Please send a valid name")
            return
        
        data['name'] = name
        data['pattern'] = name  # Default pattern is the name
        session.state = SessionState.AWAIT_IMAGE
        session_repo.save(session)
        
        bot.send_message(
            message.chat.id,
            f"✅ Name: <b>{name}</b>\n\n"
            f"🎯 <b>Step 2/4: Image</b>\n\n"
            f"📸 Send a photo OR\n"
            f"🔗 Send an image URL (http://...)\n\n"
            f"<i>Skip: Send 'skip' to continue without image</i>"
        )
    
    # STEP 2: Await Image (URL or skip)
    elif state == SessionState.AWAIT_IMAGE:
        text = message.text.strip().lower()
        
        if text == 'skip':
            name = data.get('name', 'Content')
            data['caption'] = f"🎬 <b>{name}</b>\n\n✅ {name} available here 👇"
            session.state = SessionState.AWAIT_BUTTONS
            session_repo.save(session)
            
            bot.send_message(
                message.chat.id,
                "✅ Skipped image\n\n"
                "🎯 <b>Step 3/4: Buttons</b>\n\n"
                "🔘 Add buttons (optional):\n"
                "<code>Button Text|https://your-link.com</code>\n\n"
                "Send one per line, or 'done' to finish"
            )
        elif validation_service.validate_url(message.text):
            url = message.text.strip()
            name = data.get('name', 'Content')
            data['image_ref'] = url
            data['caption'] = f"🎬 <b>{name}</b>\n\n✅ {name} available here 👇"
            session.state = SessionState.AWAIT_BUTTONS
            session_repo.save(session)
            
            # Preview image
            safe_send_photo(message.chat.id, url, caption=data['caption'])
            
            bot.send_message(
                message.chat.id,
                "✅ Image saved!\n\n"
                "🎯 <b>Step 3/4: Buttons</b>\n\n"
                "🔘 Add buttons (optional):\n"
                "<code>Button Text|https://your-link.com</code>\n\n"
                "Send one per line, or 'done' to finish"
            )
        else:
            bot.reply_to(message, "⚠️ Send a photo, valid URL, or 'skip'")
    
    # STEP 3: Await Buttons
    elif state == SessionState.AWAIT_BUTTONS:
        if message.text.strip().lower() == 'done':
            session.state = SessionState.AWAIT_CONFIRM
            session_repo.save(session)
            
            # Show preview
            name = data.get('name', 'Match')
            caption = data.get('caption', '')
            buttons = data.get('buttons', [])
            img = data.get('image_ref')
            
            bot.send_message(message.chat.id, "🎯 <b>Step 4/4: Confirm</b>\n\n📋 Preview:")
            
            if img:
                safe_send_photo(
                    message.chat.id,
                    img,
                    caption=caption,
                    reply_markup=build_inline_buttons(buttons)
                )
            else:
                bot.send_message(
                    message.chat.id,
                    caption,
                    reply_markup=build_inline_buttons(buttons)
                )
            
            bot.send_message(
                message.chat.id,
                f"📝 <b>Summary:</b>\n"
                f"Name: {name}\n"
                f"Pattern: {data.get('pattern', name)}\n"
                f"Buttons: {len(buttons)}\n"
                f"Image: {'Yes' if img else 'No'}\n\n"
                f"✅ Send 'confirm' to create\n"
                f"❌ Send 'cancel' to abort"
            )
        else:
            # Parse button input
            lines = message.text.strip().split('\n')
            buttons = data.get('buttons', [])
            added = 0
            
            for line in lines:
                if '|' not in line:
                    continue
                
                parts = line.split('|', 1)
                text = validation_service.sanitize_text(parts[0], 100)
                url = parts[1].strip()
                
                if validation_service.validate_url(url):
                    buttons.append({"text": text or "Link", "url": url})
                    added += 1
                    
                    if len(buttons) >= Config.MAX_BUTTONS_PER_MATCH:
                        break
            
            data['buttons'] = buttons
            session_repo.save(session)
            
            bot.reply_to(
                message,
                f"✅ Added {added} button(s). Total: {len(buttons)}\n\n"
                f"Send more buttons or 'done' to finish"
            )
    
    # STEP 4: Await Confirmation
    elif state == SessionState.AWAIT_CONFIRM:
        cmd = message.text.strip().lower()
        
        if cmd == 'confirm':
            # Create match
            match = Match(
                name=data.get('name'),
                pattern=data.get('pattern', data.get('name')),
                caption=data.get('caption', ''),
                image_ref=data.get('image_ref'),
                buttons=validation_service.validate_buttons(data.get('buttons', [])),
                admin_id=str(uid),
                created_at=int(time.time())
            )
            
            try:
                match_id = match_repo.create(match)
                session_repo.delete(uid)
                
                bot.send_message(
                    message.chat.id,
                    f"🎉 <b>Match Created!</b>\n\n"
                    f"✅ {match.name}\n"
                    f"🆔 <code>{match_id}</code>\n\n"
                    f"Your match is now active!",
                    reply_markup=get_admin_menu()
                )
                
                analytics_repo.log_event("match_created", {
                    "admin_id": str(uid),
                    "match_id": str(match_id),
                    "name": match.name
                })
            except Exception as e:
                logger.error(f"Match creation failed: {e}")
                bot.send_message(
                    message.chat.id,
                    "❌ Failed to create match. Please try again.",
                    reply_markup=get_admin_menu()
                )
        
        elif cmd == 'cancel':
            session_repo.delete(uid)
            bot.send_message(
                message.chat.id,
                "❌ Match creation cancelled",
                reply_markup=get_admin_menu()
            )
        else:
            bot.reply_to(message, "⚠️ Send 'confirm' or 'cancel'")
    
    # Search Match
    elif state == SessionState.SEARCH_MATCH:
        query = validation_service.sanitize_text(message.text, 100)
        results = match_repo.search(str(uid), query, Config.MAX_SEARCH_RESULTS)
        
        if results:
            text = f"🔍 <b>Found {len(results)} result(s)</b>\n\n"
            for i, match in enumerate(results, 1):
                icon = "🖼️" if match.image_ref else "📄"
                text += f"{i}. {icon} <b>{match.name}</b>\n   <code>{match._id}</code>\n\n"
            bot.send_message(message.chat.id, text, reply_markup=get_admin_menu())
        else:
            bot.send_message(
                message.chat.id,
                f"❌ No results for: <b>{query}</b>",
                reply_markup=get_admin_menu()
            )
        
        session_repo.delete(uid)
    
    # Preview Match
    elif state == SessionState.PREVIEW_MATCH:
        try:
            match = match_repo.find_by_id(message.text.strip(), str(uid))
            
            if match:
                bot.send_message(message.chat.id, f"👁️ <b>Preview: {match.name}</b>")
                
                if match.image_ref:
                    safe_send_photo(
                        message.chat.id,
                        match.image_ref,
                        caption=match.caption,
                        reply_markup=build_inline_buttons(match.buttons)
                    )
                else:
                    bot.send_message(
                        message.chat.id,
                        match.caption,
                        reply_markup=build_inline_buttons(match.buttons)
                    )
                
                bot.send_message(
                    message.chat.id,
                    f"📊 Stats: {match.match_count} hits",
                    reply_markup=get_admin_menu()
                )
            else:
                bot.send_message(
                    message.chat.id,
                    "❌ Match not found or you don't have permission",
                    reply_markup=get_admin_menu()
                )
        except Exception as e:
            logger.error(f"Preview error: {e}")
            bot.send_message(
                message.chat.id,
                "❌ Invalid Match ID",
                reply_markup=get_admin_menu()
            )
        
        session_repo.delete(uid)
    
    # Delete Match
    elif state == SessionState.DELETE_MATCH:
        try:
            match = match_repo.find_by_id(message.text.strip(), str(uid))
            
            if match:
                if match_repo.delete(str(match._id), str(uid)):
                    bot.send_message(
                        message.chat.id,
                        f"✅ Deleted: <b>{match.name}</b>",
                        reply_markup=get_admin_menu()
                    )
                    
                    analytics_repo.log_event("match_deleted", {
                        "admin_id": str(uid),
                        "match_id": str(match._id),
                        "name": match.name
                    })
                else:
                    bot.send_message(
                        message.chat.id,
                        "❌ Failed to delete",
                        reply_markup=get_admin_menu()
                    )
            else:
                bot.send_message(
                    message.chat.id,
                    "❌ Match not found",
                    reply_markup=get_admin_menu()
                )
        except Exception as e:
            logger.error(f"Delete error: {e}")
            bot.send_message(
                message.chat.id,
                "❌ Invalid Match ID",
                reply_markup=get_admin_menu()
            )
        
        session_repo.delete(uid)


@bot.message_handler(func=lambda m: m.chat.type == "private", content_types=["photo"])
@admin_only
def handle_admin_photo(message):
    """Handle photo uploads in match creation"""
    uid = message.from_user.id
    session = session_repo.get(uid)
    
    if not session or session.state != SessionState.AWAIT_IMAGE:
        return
    
    data = session.data
    file_id = message.photo[-1].file_id
    name = data.get('name', 'Content')
    
    data['image_ref'] = file_id
    data['caption'] = f"🎬 <b>{name}</b>\n\n✅ {name} available here 👇"
    session.state = SessionState.AWAIT_BUTTONS
    session_repo.save(session)
    
    bot.send_message(message.chat.id, "⏳ Processing photo...")
    
    safe_send_photo(message.chat.id, file_id, caption=data['caption'])
    
    bot.send_message(
        message.chat.id,
        "✅ Photo saved!\n\n"
        "🎯 <b>Step 3/4: Buttons</b>\n\n"
        "🔘 Add buttons (optional):\n"
        "<code>Button Text|https://your-link.com</code>\n\n"
        "Send one per line, or 'done' to finish"
    )


# ==================== GROUP HANDLERS ====================

@bot.message_handler(func=lambda m: m.chat.type in ("group", "supergroup"), 
                    content_types=["new_chat_members"])
def handle_new_members(message):
    """Welcome new members"""
    try:
        for member in message.new_chat_members:
            if member.id == bot.get_me().id:
                # Bot added to group
                bot.send_message(
                    message.chat.id,
                    "👋 <b>Hello! Match Bot is now active!</b>\n\n"
                    "✅ Users can send queries and I'll respond automatically\n"
                    "💡 Admins manage matches via private chat with me"
                )
            else:
                # Welcome user
                name_html = f"<a href='tg://user?id={member.id}'>{member.first_name}</a>"
                welcome_text = WELCOME_MESSAGE.replace("{name}", name_html).replace("{req_format}", REQUEST_FORMAT)
                
                bot.send_message(
                    message.chat.id,
                    welcome_text,
                    reply_markup=build_welcome_buttons()
                )
                
                logger.info(f"Welcomed user: {member.id}")
    except Exception as e:
        logger.error(f"Welcome error: {e}")


@bot.callback_query_handler(func=lambda c: c.data in ("show_rules", "show_format"))
def handle_info_buttons(call):
    """Handle Rules and Format buttons"""
    try:
        if call.data == "show_rules":
            bot.answer_callback_query(call.id, "Showing rules...")
            bot.send_message(call.message.chat.id, RULES_MESSAGE)
        
        elif call.data == "show_format":
            bot.answer_callback_query(call.id, "Showing request format...")
            bot.send_message(call.message.chat.id, REQUEST_FORMAT)
    except Exception as e:
        logger.error(f"Callback error: {e}")


@bot.message_handler(func=lambda m: m.chat.type in ("group", "supergroup"), 
                    content_types=["text"])
@rate_limited
def handle_group_message(message):
    """Handle user queries in groups"""
    if not message.text or message.text.startswith('/') or len(message.text) < 2:
        return
    
    text = validation_service.sanitize_text(message.text, 500)
    
    try:
        # Find matching pattern
        match = matching_service.find_match(text)
        
        if match:
            # Build response
            caption = match.caption.replace("{query}", text).replace(
                "{user}", message.from_user.first_name
            )
            
            # Send response
            if match.image_ref:
                safe_send_photo(
                    message.chat.id,
                    match.image_ref,
                    caption=caption,
                    reply_markup=build_inline_buttons(match.buttons),
                    reply_to=message.message_id
                )
            else:
                bot.reply_to(
                    message,
                    caption,
                    reply_markup=build_inline_buttons(match.buttons)
                )
            
            logger.info(f"Match found: {match.name} for query: {text[:50]}")
            
            # Log analytics
            analytics_repo.log_event("query_matched", {
                "match_id": str(match._id),
                "match_name": match.name,
                "query": text[:100],
                "user_id": message.from_user.id,
                "chat_id": message.chat.id
            })
    
    except Exception as e:
        logger.error(f"Group message error: {e}")


# ==================== FLASK ROUTES ====================

@app.route(Config.WEBHOOK_PATH, methods=["POST"])
def webhook_handler():
    """Handle webhook updates"""
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
    """Health check endpoint"""
    return jsonify({
        "status": "ok",
        "bot": "active",
        "timestamp": int(time.time()),
        "version": "2.0.0"
    }), 200


@app.route("/health")
def health():
    """Detailed health check"""
    try:
        db_status = "connected" if db_manager.health_check() else "disconnected"
    except:
        db_status = "disconnected"
    
    try:
        bot_info = bot.get_me()
        bot_status = "active"
        username = bot_info.username
    except:
        bot_status = "inactive"
        username = None
    
    cache_status = "enabled" if cache_manager.enabled else "disabled"
    
    return jsonify({
        "status": "healthy" if db_status == "connected" and bot_status == "active" else "degraded",
        "components": {
            "database": db_status,
            "bot": bot_status,
            "cache": cache_status
        },
        "bot_username": username,
        "timestamp": int(time.time())
    }), 200


@app.route("/metrics")
def metrics():
    """Basic metrics endpoint"""
    try:
        total_matches = match_repo.collection.count_documents({})
        total_admins = admin_repo.collection.count_documents({})
        
        return jsonify({
            "matches": total_matches,
            "admins": total_admins,
            "timestamp": int(time.time())
        }), 200
    except:
        return jsonify({"error": "metrics unavailable"}), 500


# ==================== BACKGROUND TASKS ====================

def cleanup_expired_sessions():
    """Periodic task to clean up expired sessions"""
    try:
        session_repo.cleanup_expired()
        logger.info("✅ Cleaned up expired sessions")
    except Exception as e:
        logger.error(f"Session cleanup error: {e}")


def setup_scheduler():
    """Setup background task scheduler"""
    scheduler = BackgroundScheduler()
    
    # Clean up sessions every 10 minutes
    scheduler.add_job(
        cleanup_expired_sessions,
        'interval',
        minutes=10,
        id='cleanup_sessions'
    )
    
    scheduler.start()
    logger.info("✅ Background scheduler started")
    return scheduler


# ==================== STARTUP ====================

def setup_webhook():
    """Configure webhook"""
    webhook_url = Config.WEBHOOK_URL.rstrip("/") + Config.WEBHOOK_PATH
    
    for attempt in range(3):
        try:
            bot.remove_webhook()
            time.sleep(1)
            
            if bot.set_webhook(url=webhook_url):
                logger.info(f"✅ Webhook configured: {webhook_url}")
                
                bot_info = bot.get_me()
                logger.info(f"🤖 Bot: @{bot_info.username} (ID: {bot_info.id})")
                return True
        
        except Exception as e:
            logger.error(f"Webhook setup attempt {attempt + 1} failed: {e}")
            if attempt < 2:
                time.sleep(2)
    
    raise RuntimeError("Failed to setup webhook after retries")


def main():
    """Main application entry point"""
    logger.info("=" * 60)
    logger.info("🚀 Starting Production Telegram Bot")
    logger.info("=" * 60)
    
    try:
        # Setup webhook
        setup_webhook()
        
        # Setup background tasks
        scheduler = setup_scheduler()
        
        # Start Flask app
        logger.info(f"🌐 Starting Flask on port {Config.PORT}")
        app.run(
            host="0.0.0.0",
            port=Config.PORT,
            debug=Config.DEBUG,
            threaded=True
        )
    
    except KeyboardInterrupt:
        logger.info("\n⚠️ Shutting down gracefully...")
    except Exception as e:
        logger.error(f"❌ Fatal error: {e}")
        raise
    finally:
        logger.info("👋 Bot stopped")


if __name__ == "__main__":
    main()
