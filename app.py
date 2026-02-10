# app.py
import re
import traceback
import logging
import sys
import os

# Fix Windows console encoding - allows emojis/unicode in print() without UnicodeEncodeError
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Any, Dict, List, Union

# Load .env FIRST (before config) - script dir so it works from any cwd; override=True so project .env wins over system env
from pathlib import Path
from dotenv import load_dotenv
_env_file = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=_env_file, override=True)
load_dotenv(override=False)  # cwd .env as fallback (don't override script .env)
if os.environ.get("MONGO_URI"):
    _h = os.environ["MONGO_URI"].split("@")[-1].split("/")[0].split("?")[0] if "@" in os.environ.get("MONGO_URI", "") else "?"
    print("MONGO_URI loaded, host:", _h)
else:
    print("WARNING: MONGO_URI not in environment - check .env in project folder")

from fastapi import FastAPI, Request, Form, HTTPException, Depends, Query, UploadFile, File
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from pymongo import MongoClient
from bson import ObjectId
import certifi
import jwt
from google.cloud import storage

# ---------- LOGGING CONFIGURATION ----------
# Safe handler for Windows console (emojis stripped so cp1252 doesn't crash)
class _SafeStreamHandler(logging.StreamHandler):
    def emit(self, record):
        try:
            msg = self.format(record)
            # Strip chars that Windows cp1252 can't encode
            msg = msg.encode("ascii", errors="replace").decode("ascii")
            self.stream.write(msg + self.terminator)
            self.flush()
        except Exception:
            self.handleError(record)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[_SafeStreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Force flush output immediately
try:
    sys.stdout.reconfigure(line_buffering=True)
    sys.stderr.reconfigure(line_buffering=True)
except Exception:
    pass

logger.info("=" * 80)
logger.info("MULTIFOLKS BACKEND STARTING...")
logger.info("=" * 80)

# ---------- CONFIG ----------
import config  # Must contain: MONGO_URI, DATABASE_NAME, COLLECTION_NAME, SECRET_KEY, HOST, PORT

# Show which MongoDB host we're using (no password)
try:
    _uri = getattr(config, "MONGO_URI", "") or ""
    if "@" in _uri:
        _host = _uri.split("@", 1)[1].split("/")[0].split("?")[0]
        print("MongoDB URI host:", _host, "| length:", len(_uri))
        if "gamultilens.tuzaora" not in _uri:
            print("WARNING: URI does not contain gamultilens.tuzaora - check .env is loaded")
    else:
        print("MongoDB URI host: (invalid or default) | length:", len(_uri))
except Exception as e:
    print("MongoDB URI check failed:", e)

# ---------- APP ----------
app = FastAPI(title="Multifolks Login API (Fixed with Multi-Route Support)")

logger.info("FastAPI app initialized")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all (localhost, newbackend.multifolks.com, any domain)
    allow_credentials=False,  # Must be False when using "*" so browsers accept it
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

logger.info("CORS middleware configured")

# ---------- REQUEST LOGGING MIDDLEWARE ----------
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = datetime.now()
    
    # Log incoming request (ASCII only for Windows compatibility)
    logger.info(f"[INCOMING] {request.method} {request.url.path}")
    
    try:
        response = await call_next(request)
        
        # Calculate duration
        duration = (datetime.now() - start_time).total_seconds()
        
        # Log response
        status_str = "[OK]" if response.status_code < 400 else "[ERR]"
        logger.info(f"{status_str} RESPONSE: {request.method} {request.url.path} - Status: {response.status_code} - Duration: {duration:.3f}s")
        
        return response
    except Exception as e:
        duration = (datetime.now() - start_time).total_seconds()
        logger.error(f"[ERROR] {request.method} {request.url.path} - {str(e)} - Duration: {duration:.3f}s")
        raise

logger.info("Request logging middleware configured")

# ---------- AUTH / HASH ----------
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
security = HTTPBearer(auto_error=False)

# ---------- DATABASE (same as ga-admin: lazy connect on first request, URI from env) ----------
db_connected = False
mongo_connection_error = None
client = None
db = None
users_collection = None

payment_service = None
cart_service = None
delivery_service = None
notification_service = None
product_service = None
order_service = None

try:
    from payment_service import StripePaymentService
    from cart_service import CartService
    from delivery_service import DeliveryService
    from notification_service import MSG91Service
    from product_service import ProductService
    from order_service import OrderService
except Exception as e:
    logger.warning("Optional services not available: %s", e)
    StripePaymentService = CartService = DeliveryService = MSG91Service = ProductService = OrderService = None

def ensure_db():
    """Connect on first use. Uses config.MONGO_URI (loaded from .env in config.py) - never system env localhost."""
    global client, db, users_collection, db_connected, mongo_connection_error
    global payment_service, cart_service, delivery_service, product_service, order_service, notification_service
    if db is not None:
        return db
    uri = getattr(config, "MONGO_URI", None) or os.environ.get("MONGO_URI")
    if not uri or (isinstance(uri, str) and "localhost" in uri):
        mongo_connection_error = "MONGO_URI not set or points to localhost. Set MONGO_URI in newbackend/.env to your Atlas URI."
        return None
    sep = "&" if "?" in uri else "?"
    uri_with_opts = uri.rstrip("/") + sep + "tlsDisableOCSPEndpointCheck=true"
    def _connect(use_uri, tls_ca_file=None, tls_allow_invalid=False):
        kw = dict(
            serverSelectionTimeoutMS=30000,
            connectTimeoutMS=30000,
            socketTimeoutMS=30000,
            retryWrites=True,
        )
        if tls_ca_file:
            kw["tlsCAFile"] = tls_ca_file
        if tls_allow_invalid:
            kw["tlsAllowInvalidCertificates"] = True
            kw["tlsAllowInvalidHostnames"] = True
        return MongoClient(use_uri, **kw)

    try:
        attempts = [
            ("CA bundle", lambda: _connect(uri_with_opts, tls_ca_file=certifi.where())),
            ("tlsAllowInvalidCertificates", lambda: _connect(uri_with_opts + "&tlsAllowInvalidCertificates=true", tls_allow_invalid=True)),
        ]
        client = None
        last_err = None
        for name, connect_fn in attempts:
            try:
                c = connect_fn()
                c.server_info()  # force connection now
                client = c
                break
            except Exception as e:
                last_err = e
                if "SSL" in str(e) or "TLS" in str(e) or "handshake" in str(e).lower():
                    logger.warning("MongoDB TLS failed (%s), trying next option", name)
                    continue
                raise
        if client is None and last_err:
            raise last_err
        db = client[config.DATABASE_NAME]
        users_collection = db[config.COLLECTION_NAME]
        db_connected = True
        mongo_connection_error = None
        logger.info("MongoDB connected (lazy): %s | %s", config.DATABASE_NAME, config.COLLECTION_NAME)
        try:
            if StripePaymentService:
                payment_service = StripePaymentService(db)
            if CartService:
                cart_service = CartService(db)
            if ProductService:
                product_service = ProductService(db)
            if OrderService:
                order_service = OrderService(db)
            if DeliveryService:
                delivery_config = {
                    "BLUEDART_BASE_URL": getattr(config, "BLUEDART_BASE_URL", None),
                    "BLUEDART_CUSTOMER_CODE": getattr(config, "BLUEDART_CUSTOMER_CODE", None),
                    "BLUEDART_LOGIN_ID": getattr(config, "BLUEDART_LOGIN_ID", None),
                    "BLUEDART_LICENSE_KEY": getattr(config, "BLUEDART_LICENSE_KEY", None),
                    "WAREHOUSE_PINCODE": getattr(config, "WAREHOUSE_PINCODE", None),
                    "WAREHOUSE_ADDRESS": getattr(config, "WAREHOUSE_ADDRESS", None),
                }
                delivery_service = DeliveryService(db, delivery_config)
            if MSG91Service:
                notification_service = MSG91Service()
        except Exception as e:
            logger.warning("Some services failed to init: %s", e)
        return db
    except Exception as e:
        mongo_connection_error = str(e)
        db_connected = False
        print("")
        print("=" * 60)
        print("MONGODB DISCONNECTED - REAL REASON:")
        print("=" * 60)
        print(mongo_connection_error)
        print("=" * 60)
        print("")
        sys.stdout.flush()
        return None

@app.middleware("http")
async def ensure_db_middleware(request: Request, call_next):
    ensure_db()
    return await call_next(request)

# ... (Existing Code) ...

# ---------- VTO FRAME PROXY (for share/save capture - avoids CORS) ----------
VTO_IMAGE_BASE = "https://storage.googleapis.com/myapp-image-bucket-001/vto/vto_ready"

@app.get("/api/v1/vto-frame/{skuid}")
async def get_vto_frame_proxy(skuid: str):
    """Proxy VTO frame image from GCS for html2canvas capture (same-origin)."""
    import urllib.request
    import urllib.error
    url = f"{VTO_IMAGE_BASE}/{skuid}_VTO.png"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Multifolks-Backend/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = resp.read()
            return Response(content=data, media_type="image/png")
    except urllib.error.HTTPError as e:
        raise HTTPException(status_code=e.code, detail=f"VTO frame not found: {skuid}")
    except Exception as e:
        logger.warning(f"VTO frame proxy failed for {skuid}: {e}")
        raise HTTPException(status_code=502, detail="Could not fetch VTO frame")

# ---------- ROOT ----------
@app.get("/")
async def root():
    return {
        "message": "Multifolks API",
        "docs": "/docs",
        "health": "/api/health",
        "redoc": "/redoc"
    }

# ---------- PRODUCT ENDPOINTS ----------
@app.get("/api/v1/products/all")
async def get_all_products(
    gender: Optional[str] = None,
    price_min: Optional[float] = None,
    price_max: Optional[float] = None,
    shape: Optional[List[str]] = Query(None),
    colors: Optional[List[str]] = Query(None),
    material: Optional[List[str]] = Query(None),
    collections: Optional[List[str]] = Query(None),
    comfort: Optional[List[str]] = Query(None),
    size: Optional[List[str]] = Query(None),
    brand: Optional[List[str]] = Query(None),
    style: Optional[List[str]] = Query(None),
    limit: Optional[int] = None
):
    if not product_service:
        raise HTTPException(status_code=503, detail="Product service unavailable")
    
    filters = {
        "gender": gender,
        "price_min": price_min,
        "price_max": price_max,
        "shape": shape,
        "colors": colors,
        "material": material,
        "collections": collections,
        "comfort": comfort,
        "size": size,
        "brand": brand,
        "style": style,
        "limit": limit
    }
    
    # Filter out None values
    filters = {k: v for k, v in filters.items() if v is not None}
    
    return product_service.get_all_products(filters)

# ---------- HELPERS ----------
MOBILE_DIGITS_PATTERN = re.compile(r"^\+?[\d\s\-]{10,15}$")

def normalize_mobile(number: str) -> str:
    """Normalize for storage. Accepts any global format: digits with optional +, or raw string if no digits."""
    if not number or not number.strip():
        return ""
    s = number.strip().replace(" ", "").replace("-", "")
    digits = re.sub(r"\D", "", s)
    if not digits:
        return number.strip()
    if digits.startswith("0"):
        digits = digits[1:]
    return "+" + digits if len(digits) >= 10 else digits

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    if not hashed_password:
        return False
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        return False

def generate_jwt_token(user_id: str, email: str) -> str:
    payload = {
        "user_id": str(user_id),
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(hours=24),
        "iat": datetime.now(timezone.utc)
    }
    token = jwt.encode(payload, config.SECRET_KEY, algorithm="HS256")
    return token.decode("utf-8") if isinstance(token, bytes) else token

def decode_jwt_token(token: str) -> Dict[str, Any]:
    return jwt.decode(token, config.SECRET_KEY, algorithms=["HS256"])

# ---------- TOKEN DEPENDENCY ----------
# ---------- TOKEN DEPENDENCY ----------
def verify_token(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
):
    # Check for Guest ID first if no credentials
    if not credentials:
        guest_id = request.headers.get("X-Guest-ID")
        if guest_id:
            print(f"Guest access with ID: {guest_id}")
            return {"_id": guest_id, "email": "guest@multifolks.com", "is_guest": True}
        raise HTTPException(status_code=401, detail="Missing authentication credentials")

    try:
        token = credentials.credentials
        # print(f"Verifying token: {token[:20]}...")  # Log first 20 chars
        payload = decode_jwt_token(token)
        # print(f"Token payload: {payload}")
        email: str = payload.get("email")
        if not email:
            print("ERROR: No email in token payload")
            raise HTTPException(status_code=401, detail="Invalid token payload")

        if not db_connected:
            raise HTTPException(status_code=503, detail="Database not connected")

        user = users_collection.find_one({"email": email})
        if not user:
            print(f"ERROR: User not found for email: {email}")
            raise HTTPException(status_code=401, detail="User not found")

        # print(f"Token verified successfully for user: {email}")
        return user
    except jwt.ExpiredSignatureError:
        print("ERROR: Token expired")
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        print(f"ERROR: Invalid token - {e}")
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        print("Token verification error:", e)
        raise HTTPException(status_code=500, detail="Token verification failed")

# ---------- MODELS ----------
class LoginRequest(BaseModel):
    username: EmailStr
    password: str


class SimpleRegisterRequest(BaseModel):
    """JSON body for POST /api/v1/auth/simple-register (frontend sends this)."""
    model_config = {"extra": "ignore"}
    first_name: Optional[str] = ""
    last_name: Optional[str] = ""
    email: Optional[str] = None
    mobile: Optional[str] = ""
    password: Optional[str] = ""
    country_code: Optional[Union[str, int]] = "44"
    is_subscribed_whatsapp: Optional[bool] = True


class LoginResponse(BaseModel):
    success: bool
    status: int
    msg: str
    data: dict

class UpdateProfileRequest(BaseModel):
    model_config = {"extra": "allow"}  # Allow extra fields for flexibility
    
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    mobile: Optional[str] = None
    contact_number: Optional[str] = None  # Alternative field name
    country_code: Optional[int] = None
    gender: Optional[str] = None
    birth_date: Optional[str] = None
    birth_month: Optional[str] = None
    birth_year: Optional[str] = None
    billing_address: Optional[str] = None
    shipping_address: Optional[str] = None
    address: Optional[str] = None
    email: Optional[str] = None
    shop_address: Optional[str] = None
    store_id: Optional[str] = None
    retail_shop_name: Optional[str] = None
    bank_details: Optional[str] = None
    gst_number: Optional[str] = None
    pan_number: Optional[str] = None

class CreatePaymentSessionRequest(BaseModel):
    order_id: str
    amount: float
    currency: str = "GBP"
    metadata: Optional[Dict[str, Any]] = None
    prescriptions: Optional[List[Dict[str, Any]]] = None
    cart_items: Optional[List[Dict[str, Any]]] = None
    subtotal: Optional[float] = None
    discount_amount: Optional[float] = None
    shipping_cost: Optional[float] = None
    total_payable: Optional[float] = None


class UpdateOrderWithCartRequest(BaseModel):
    cart_items: Optional[List[Dict[str, Any]]] = None
    subtotal: Optional[float] = None
    discount_amount: Optional[float] = None
    shipping_cost: Optional[float] = None
    total_payable: Optional[float] = None

class CheckPincodeRequest(BaseModel):
    pincode: str

class CreateShipmentRequest(BaseModel):
    order_id: str
    customer_details: Dict[str, Any]

class MergeGuestCartRequest(BaseModel):
    guest_id: str

# ---------- LOGIN HELPER ----------
async def login_user_by_email(email: str, password: str):
    if not db_connected:
        raise HTTPException(status_code=503, detail="Database not connected")
    user = users_collection.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=400, detail={"success": False, "status": 4001, "msg": "Invalid username or password"})
    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail={"success": False, "status": 4002, "msg": "Account deactivated"})
    if not verify_password(password, user.get("password", "")):
        raise HTTPException(status_code=400, detail={"success": False, "status": 4001, "msg": "Invalid password"})

    users_collection.update_one({"_id": user["_id"]}, {"$set": {"updateTime": datetime.now(timezone.utc)}})
    token = generate_jwt_token(str(user["_id"]), user["email"])
    return {
        "success": True,
        "status": 200,
        "msg": "Welcome back! You are successfully logged in",
        "data": {
            "first_name": user.get("firstName", ""),
            "last_name": user.get("lastName", ""),
            "email": user["email"],
            "mobile": str(user.get("primaryContact", "")),
            "mobile_international": user.get("international_mobile", ""),
            "is_verified": user.get("is_verified", False),
            "refer_code": user.get("my_code", ""),
            "id": str(user["_id"]),
            "token": token,
            "is_new_user": False
        }
    }

@app.post("/api/v1/auth/login", response_model=LoginResponse)
async def v1_login(login_request: LoginRequest):
    return await login_user_by_email(login_request.username, login_request.password)

@app.get("/api/v1/accounts/check-email")
async def check_email(email: str):
    if not db_connected:
        raise HTTPException(status_code=503, detail="Database unavailable")
    exists = users_collection.find_one({"email": email}) is not None
    return {"success": True, "data": {"is_registered": exists}}


# ---------- SIMPLE REGISTER (JSON) - Frontend sends application/json ----------
@app.post("/api/v1/auth/simple-register")
async def simple_register_json(req: SimpleRegisterRequest):
    """Accept JSON body from frontend. Mobile: any format (global users, no UK restriction)."""
    print("[REG] simple-register called (no mobile format validation)")
    first_name = (req.first_name or "").strip()
    last_name = (req.last_name or "").strip()
    email = (req.email or "").strip() or None
    mobile = (req.mobile or "").strip()
    password = (req.password or "").strip()
    country_code = req.country_code if req.country_code is not None else "44"
    if isinstance(country_code, int):
        country_code = str(country_code)
    is_subscribed_whatsapp = req.is_subscribed_whatsapp if req.is_subscribed_whatsapp is not None else True

    if not first_name or not mobile or not password:
        raise HTTPException(
            status_code=400,
            detail={"success": False, "status": 4000, "msg": "Please fill first name, mobile number and password."},
        )

    # No format restriction: accept mobile numbers from anywhere in the world
    mobile_digits = re.sub(r"\D", "", mobile)
    email_to_use = (email or "").strip() or f"dummy_{mobile_digits}@multifolks.us"
    email_to_use = email_to_use.strip().lower()

    # Case-insensitive exact match (regex is more reliable than $expr across MongoDB versions)
    email_pattern = "^" + re.escape(email_to_use) + r"$"
    existing_by_email = users_collection.find_one({"email": {"$regex": email_pattern, "$options": "i"}})
    if existing_by_email:
        print(f"[REG] Blocked duplicate email: found existing user _id={existing_by_email.get('_id')} email={existing_by_email.get('email')}")
        raise HTTPException(status_code=400, detail={"success": False, "status": 4003, "msg": "An account with this email is already registered. Please log in with your password or use Forgot password."})

    international_mobile = normalize_mobile(mobile)
    primary_contact = int(mobile_digits) if mobile_digits.isdigit() else (mobile_digits or mobile.strip())

    user_doc = {
        "firstName": first_name,
        "lastName": last_name,
        "email": email_to_use,
        "primaryContact": primary_contact,
        "international_mobile": international_mobile,
        "password": hash_password(password),
        "country_code": int(country_code) if (str(country_code).replace("-", "").isdigit()) else 44,
        "subscription": True,
        "subscriptions": {"whatsapp": is_subscribed_whatsapp},
        "is_guest_user": False,
        "verify": 0,
        "dnd": 1,
        "my_code": "",
        "additional_features": {"is_email_set": bool(email_to_use and "@" in email_to_use)},
        "is_staff": False,
        "is_superuser": False,
        "is_active": True,
        "billing_address": "",
        "shipping_address": "",
        "updateTime": datetime.now(timezone.utc),
    }

    result = users_collection.insert_one(user_doc)
    token = generate_jwt_token(str(result.inserted_id), email_to_use)

    if notification_service:
        try:
            user_name = f"{first_name} {last_name}".strip()
            notification_service.send_welcome_email(email_to_use, user_name, password)
        except Exception as e:
            print(f"[ERR] Welcome email: {e}")

    return {
        "success": True,
        "status": 2019,
        "msg": "Registration successful",
        "data": {
            "first_name": first_name,
            "last_name": last_name,
            "email": email_to_use,
            "mobile": international_mobile,
            "mobile_international": international_mobile,
            "is_verified": False,
            "refer_code": "",
            "id": str(result.inserted_id),
            "token": token,
            "is_new_user": True,
        },
    }


# ---------- UNIFIED AUTH (FORM; login/unified/auth - simple-register is JSON above) ----------
@app.post("/api/v1/auth/login")
@app.post("/api/v1/auth/unified")
@app.post("/api/v1/auth/auth")
async def unified_auth(
    request: Request,
    username: Optional[str] = Form(None),
    first_name: Optional[str] = Form(None),
    last_name: Optional[str] = Form(None),
    email: Optional[str] = Form(None),
    mobile: Optional[str] = Form(None),
    password: Optional[str] = Form(None),
    country_code: str = Form("44"),
    is_subscribed_whatsapp: bool = Form(True),
    otp: Optional[str] = Form(None),  # Added for your payload
):
    try:
        current_path = request.url.path
        print(f"Request matched route: {current_path}")  # Debug log

        # Safe JSON fallback (only if Content-Type matches, with try-catch)
        content_type = request.headers.get("content-type", "").lower()
        if "application/json" in content_type:
            try:
                body = await request.json()
                username = body.get("username", username)
                first_name = body.get("first_name", first_name)
                last_name = body.get("last_name", last_name)
                email = body.get("email", email)
                mobile = body.get("mobile", mobile)
                password = body.get("password", password)
                country_code = body.get("country_code", country_code)
                is_subscribed_whatsapp = body.get("is_subscribed_whatsapp", is_subscribed_whatsapp)
                otp = body.get("otp", otp)
            except Exception as json_err:
                print(f"JSON parse failed (likely not JSON): {json_err}")
                # Fall back to form data (already parsed)

        # Route-specific logic (match path with or without trailing slash)
        is_register_route = "simple-register" in current_path or "unified" in current_path or "/auth/" in current_path
        is_login_route = "login" in current_path and "simple-register" not in current_path

        # Login path (for /login/ route, or if username provided)
        if username and password and is_login_route:
            return await login_user_by_email(username, password)

        # Registration path (for /simple-register/, /unified, /auth/)
        if is_register_route:
            print(f"\n{'='*60}")
            print(f"[REG] REGISTRATION REQUEST RECEIVED")
            print(f"{'='*60}")
            if not all([first_name, mobile, password]):
                raise HTTPException(status_code=400, detail={"success": False, "status": 4000, "msg": "Missing required fields for registration"})
            
            # Optional OTP validation (if provided)
            if otp and otp != "0000":  # Example: validate against stored OTP
                raise HTTPException(status_code=400, detail={"success": False, "status": 4005, "msg": "Invalid OTP"})

            # No format restriction: accept mobile numbers from anywhere in the world
            email_to_use = email.strip() if email and email.strip() else None
            mobile_digits = re.sub(r"\D", "", mobile)

            if not email_to_use:
                email_to_use = f"dummy_{mobile_digits}@multifolks.us"
            email_to_use = email_to_use.strip().lower()

            # Case-insensitive exact match (regex is more reliable than $expr across MongoDB versions)
            email_pattern = "^" + re.escape(email_to_use) + r"$"
            existing_by_email = users_collection.find_one({"email": {"$regex": email_pattern, "$options": "i"}})
            if existing_by_email:
                print(f"[REG] Blocked duplicate email: found existing user _id={existing_by_email.get('_id')} email={existing_by_email.get('email')}")
                raise HTTPException(status_code=400, detail={"success": False, "status": 4003, "msg": "An account with this email is already registered. Please log in with your password or use Forgot password."})

            international_mobile = normalize_mobile(mobile)
            primary_contact = int(mobile_digits) if mobile_digits.isdigit() else (mobile_digits or mobile.strip())

            user_doc = {
                "firstName": first_name.strip(),
                "lastName": last_name.strip() if last_name else "",
                "email": email_to_use,
                "primaryContact": primary_contact,
                "international_mobile": international_mobile,
                "password": hash_password(password),
                "country_code": int(country_code),
                "subscription": True,
                "subscriptions": {"whatsapp": is_subscribed_whatsapp},
                "is_guest_user": False,
                "verify": 0,
                "dnd": 1,
                "my_code": "",
                "additional_features": {"is_email_set": bool(email_to_use and "@" in email_to_use)},
                "is_staff": False,
                "is_superuser": False,
                "is_active": True,
                "billing_address": "",
                "shipping_address": "",
                "updateTime": datetime.now(timezone.utc),
            }

            result = users_collection.insert_one(user_doc)
            token = generate_jwt_token(str(result.inserted_id), email_to_use)
            
            print(f"[OK] User created successfully: {email_to_use}")
            print(f"   User ID: {result.inserted_id}")
            print(f"   Name: {first_name} {last_name}")

            # Send welcome email
            print(f"\n[EMAIL] ATTEMPTING TO SEND WELCOME EMAIL")
            print(f"   Notification service available: {notification_service is not None}")
            
            if notification_service:
                try:
                    user_name = f"{first_name} {last_name}".strip()
                    print(f"   Sending to: {email_to_use}")
                    print(f"   User name: {user_name}")
                    
                    result_email = notification_service.send_welcome_email(email_to_use, user_name, password)
                    
                    print(f"   Email send result: {result_email}")
                    if result_email.get('success'):
                        print(f"   [OK] Welcome email sent successfully!")
                        unique_id = result_email.get('data', {}).get('data', {}).get('unique_id', 'N/A')
                        print(f"   MSG91 Unique ID: {unique_id}")
                    else:
                        print(f"   [ERR] Welcome email failed: {result_email.get('msg')}")
                        
                except Exception as e:
                    print(f"   [ERR] Exception sending welcome email: {e}")
                    import traceback
                    print(f"   Traceback: {traceback.format_exc()}")
            else:
                print(f"   [WARN] Notification service not initialized!")
            
            print(f"{'='*60}\n")

            return {
                "success": True,
                "status": 2019,
                "msg": "Registration successful",
                "data": {
                    "first_name": first_name,
                    "last_name": last_name,
                    "email": email_to_use,
                    "mobile": international_mobile,
                    "mobile_international": international_mobile,
                    "is_verified": False,
                    "refer_code": "",
                    "id": str(result.inserted_id),
                    "token": token,
                    "is_new_user": True
                }
            }

        # Fallback if route doesn't match expected logic
        raise HTTPException(status_code=400, detail={"success": False, "status": 4000, "msg": "Invalid request for this endpoint"})

    except HTTPException:
        raise
    except Exception as e:
        print("Unified auth error:", e)
        print(traceback.format_exc())
        raise HTTPException(
            status_code=500,
            detail={"success": False, "status": 4011, "msg": f"Authentication failed due to server error: {str(e)}"}
        )

# ---------- PROFILE ----------
@app.get("/api/profile")
async def get_profile(current_user: dict = Depends(verify_token)):
    # Guest users have no real profile; require login so registered user data is shown
    if current_user.get("is_guest") is True:
        raise HTTPException(status_code=401, detail="Profile requires login. Please sign in or register.")
    return {
        "success": True,
        "data": {
            "id": str(current_user["_id"]),
            "first_name": current_user.get("firstName", ""),
            "last_name": current_user.get("lastName", ""),
            "email": current_user.get("email", ""),
            "contact_number": str(current_user.get("primaryContact", "")),  # Added for frontend compatibility
            "mobile": str(current_user.get("primaryContact", "")),
            "mobile_international": current_user.get("international_mobile", ""),
            "is_verified": current_user.get("is_verified", False),
            "country_code": current_user.get("country_code", 44),
            # Add DOB and gender fields
            "birth_date": current_user.get("birthDate", ""),
            "birth_month": current_user.get("birthMonth", ""),
            "birth_year": current_user.get("birthYear", ""),
            "gender": current_user.get("gender", ""),
            # Add address fields
            "billing_address": current_user.get("billing_address", ""),
            "shipping_address": current_user.get("shipping_address", ""),
        }
    }

@app.put("/api/v1/user/profile")
async def v1_update_profile(request: UpdateProfileRequest, current_user: dict = Depends(verify_token)):
    update_data = {}
    try:
        if request.first_name is not None:
            update_data["firstName"] = request.first_name
        if request.last_name is not None:
            update_data["lastName"] = request.last_name
        # Handle mobile/contact_number (frontend might send either). No format restriction for global users.
        mobile_value = request.mobile or request.contact_number
        if mobile_value is not None and str(mobile_value).strip():
            digits = re.sub(r"\D", "", str(mobile_value))
            update_data["primaryContact"] = int(digits) if digits.isdigit() else (digits or str(mobile_value).strip())
            cc = request.country_code if request.country_code is not None else current_user.get("country_code", 44)
            update_data["international_mobile"] = normalize_mobile(str(mobile_value))
            update_data["country_code"] = int(cc)
        elif request.country_code is not None:
            update_data["country_code"] = int(request.country_code)
        
        # Add DOB and gender
        if request.gender is not None:
            update_data["gender"] = request.gender
        if request.birth_date is not None:
            update_data["birthDate"] = request.birth_date
        if request.birth_month is not None:
            update_data["birthMonth"] = request.birth_month
        if request.birth_year is not None:
            update_data["birthYear"] = request.birth_year
            # Mark profile setup as complete when DOB is provided
            update_data["profileSetupComplete"] = True
        
        # Add address fields
        if request.billing_address is not None:
            update_data["billing_address"] = request.billing_address
        if request.shipping_address is not None:
            update_data["shipping_address"] = request.shipping_address
        if request.address is not None:
            update_data["address"] = request.address
        
        # Add email if provided
        if request.email is not None:
            update_data["email"] = request.email
        
        # Add optional business fields (for future use)
        if request.shop_address is not None:
            update_data["shop_address"] = request.shop_address
        if request.store_id is not None:
            update_data["store_id"] = request.store_id
        if request.retail_shop_name is not None:
            update_data["retail_shop_name"] = request.retail_shop_name
        if request.bank_details is not None:
            update_data["bank_details"] = request.bank_details
        if request.gst_number is not None:
            update_data["gst_number"] = request.gst_number
        if request.pan_number is not None:
            update_data["pan_number"] = request.pan_number

        if update_data:
            users_collection.update_one({"_id": current_user["_id"]}, {"$set": {**update_data, "updateTime": datetime.now(timezone.utc)}})
            updated_user = users_collection.find_one({"_id": current_user["_id"]})
            return {
                "success": True,
                "msg": "Profile updated successfully",
                "data": {
                    "first_name": updated_user.get("firstName", ""),
                    "last_name": updated_user.get("lastName", ""),
                    "email": updated_user.get("email", ""),
                    "mobile": str(updated_user.get("primaryContact", "")),
                    "mobile_international": updated_user.get("international_mobile", ""),
                    "country_code": updated_user.get("country_code", 44),
                }
            }
        return {"success": False, "msg": "No data to update"}
    except HTTPException:
        raise
    except Exception as e:
        print("update_profile error:", e)
        raise HTTPException(status_code=500, detail="Failed to update profile")

# ---------- USER PRESCRIPTIONS ----------
@app.get("/api/v1/user/prescriptions")
async def get_user_prescriptions(current_user: dict = Depends(verify_token)):
    """Get all saved prescriptions for the current user or guest."""
    if not db_connected:
        raise HTTPException(status_code=503, detail="Database not connected")
    
    try:
        is_guest = current_user.get("is_guest") is True
        if is_guest:
            guest_id = str(current_user["_id"])
            guest_rx_collection = db["guest_prescriptions"]
            doc = guest_rx_collection.find_one({"_id": guest_id})
            prescriptions = (doc.get("prescriptions", []) if doc else [])
            logger.info(f"[RX] Fetching prescriptions for guest {guest_id}: found {len(prescriptions)}")
            # Sort guest prescriptions latest first
            def _rx_created_at(p):
                raw = p.get("created_at") or (p.get("data") or {}).get("created_at") or p.get("createdAt") or ""
                if not raw:
                    return ""
                return raw if isinstance(raw, str) else str(raw)
            prescriptions = sorted(prescriptions, key=_rx_created_at, reverse=True)
        else:
            user_id = current_user["_id"]
            # Always fetch from DB so we have the latest prescriptions (user doc from token may not include full array)
            user_doc = users_collection.find_one({"_id": user_id}, {"prescriptions": 1})
            prescriptions = (user_doc.get("prescriptions", []) if user_doc else [])
            logger.info(f"[RX] Fetching prescriptions for user {user_id}: found {len(prescriptions)}")
        
        # Return latest first (sort by created_at descending) so product/cart pages show newest
        def _rx_created_at(p):
            raw = p.get("created_at") or (p.get("data") or {}).get("created_at") or p.get("createdAt") or ""
            if not raw:
                return ""
            return raw if isinstance(raw, str) else str(raw)
        prescriptions = sorted(prescriptions, key=_rx_created_at, reverse=True)
        
        for i, pres in enumerate(prescriptions):
            logger.info(f"   Prescription {i+1}: type={pres.get('type')}, has_image={bool(pres.get('image_url'))}, name={pres.get('name')}")
        
        return {
            "success": True,
            "data": prescriptions
        }
    except Exception as e:
        logger.error(f"Error fetching prescriptions: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch prescriptions")

# ---------- PRESCRIPTION IMAGE UPLOAD TO GCS ----------
@app.post("/api/v1/prescriptions/upload-image")
async def upload_prescription_image(
    file: UploadFile = File(...),
    user_id: Optional[str] = Form(None),
    guest_id: Optional[str] = Form(None),
    product_id: Optional[str] = Form(None),  # NEW: Link prescription to product
    request: Request = None
):
    """
    Upload prescription image to Google Cloud Storage
    Returns the public URL of the uploaded image
    
    If product_id is provided, stores prescription as pending for that product
    (will be automatically included when adding product to cart)
    """
    try:
        logger.info(f"[UPLOAD] Prescription upload request - File: {file.filename}, Content-Type: {file.content_type}, User ID: {user_id}, Guest ID: {guest_id}")
        
        # Validate file type
        allowed_types = ["image/jpeg", "image/jpg", "image/png", "image/gif", "image/webp", "application/pdf"]
        if file.content_type not in allowed_types:
            logger.error(f"[ERR] Invalid file type: {file.content_type}")
            raise HTTPException(status_code=400, detail=f"Invalid file type '{file.content_type}'. Allowed: {', '.join(allowed_types)}")
        
        # Generate unique filename
        file_extension = file.filename.split('.')[-1] if '.' in file.filename else 'jpg'
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        unique_id = str(uuid.uuid4())[:8]
        identifier = user_id if user_id else guest_id if guest_id else unique_id
        
        filename = f"{timestamp}_{unique_id}.{file_extension}"
        gcs_path = f"prescriptions/{identifier}/{filename}"
        
        logger.info(f"[GCS] Generated GCS path: {gcs_path}")
        
        # Initialize GCS client
        gcs_credentials_path = os.path.join(os.path.dirname(__file__), "gcs-service-account.json")
        logger.info(f"[GCS] Looking for credentials at: {gcs_credentials_path}")
        
        if not os.path.exists(gcs_credentials_path):
            logger.error(f"[ERR] GCS credentials file not found at: {gcs_credentials_path}")
            raise HTTPException(status_code=500, detail="GCS credentials not found. Please contact support.")
        
        logger.info(f"[OK] GCS credentials file found")
        
        try:
            storage_client = storage.Client.from_service_account_json(gcs_credentials_path)
            logger.info(f"[OK] GCS client initialized")
        except Exception as gcs_error:
            logger.error(f"[ERR] Failed to initialize GCS client: {str(gcs_error)}")
            raise HTTPException(status_code=500, detail=f"Failed to initialize cloud storage: {str(gcs_error)}")
        
        bucket = storage_client.bucket("myapp-image-bucket-001")
        blob = bucket.blob(gcs_path)
        
        # Upload file
        logger.info(f"[GCS] Uploading file to GCS...")
        file_content = await file.read()
        file_size = len(file_content)
        logger.info(f"[GCS] File size: {file_size} bytes ({file_size / 1024:.2f} KB)")
        
        if file_size == 0:
            logger.error(f"[ERR] File is empty")
            raise HTTPException(status_code=400, detail="Uploaded file is empty")
        
        blob.upload_from_string(file_content, content_type=file.content_type)
        logger.info(f"[OK] File uploaded to GCS successfully")
        
        # Generate public URL
        public_url = f"https://storage.googleapis.com/myapp-image-bucket-001/{gcs_path}"
        
        logger.info(f"[OK] Prescription image uploaded successfully: {public_url}")
        
        # If product_id provided and user is authenticated, store as pending prescription
        response_data = {
            "success": True,
            "url": public_url,
            "filename": filename,
            "path": gcs_path
        }
        
        # Determine which user ID to use (authenticated user takes priority)
        final_user_id = None
        authenticated_user = None
        
        # Try to get authenticated user from token (optional)
        try:
            auth_header = request.headers.get("Authorization") if request else None
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]
                payload = decode_jwt_token(token)
                email = payload.get("email")
                if email and db_connected:
                    authenticated_user = users_collection.find_one({"email": email})
                    if authenticated_user:
                        final_user_id = str(authenticated_user['_id'])
                        logger.info(f"[OK] Using authenticated user ID: {final_user_id}")
        except Exception as e:
            # Auth is optional for this endpoint
            logger.debug(f"Optional auth check failed: {e}")
        
        if not final_user_id and user_id:
            final_user_id = user_id
            logger.info(f"[OK] Using form user_id: {final_user_id}")
        
        if product_id and final_user_id and db_connected:
            try:
                prescription_data = {
                    'mode': 'upload',
                    'gcs_url': public_url,
                    'blob_name': gcs_path,
                    'fileName': file.filename,
                    'fileType': file.content_type,
                    'fileSize': file_size,
                    'uploadedAt': datetime.now(timezone.utc).isoformat()
                }
                
                # Convert user_id to ObjectId if it's a string
                try:
                    user_obj_id = ObjectId(final_user_id) if isinstance(final_user_id, str) else final_user_id
                except:
                    # If conversion fails, try to find user by email or other identifier
                    logger.warning(f"[WARN] Could not convert {final_user_id} to ObjectId")
                    user_obj_id = final_user_id
                
                # Store as pending prescription for this product
                update_result = users_collection.update_one(
                    {"_id": user_obj_id},
                    {
                        "$set": {
                            f"pending_prescriptions.{product_id}": prescription_data,
                            "updateTime": datetime.now(timezone.utc)
                        }
                    }
                )
                
                if update_result.matched_count > 0:
                    logger.info(f"[OK] Prescription stored as pending for product {product_id}")
                    response_data["message"] = "Prescription uploaded and will be included when adding to cart"
                else:
                    logger.warning(f"[WARN] User not found, prescription uploaded but not linked to product")
            except Exception as e:
                logger.warning(f"[WARN] Failed to store pending prescription: {e}")
        
        return response_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[ERR] Unexpected error uploading prescription image: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Failed to upload image: {str(e)}")

class SavePrescriptionRequest(BaseModel):
    type: str  # 'upload', 'photo', 'manual'
    data: Union[Dict[str, Any], List[Any]]  # prescription details (OD/OS, reading power, etc.)
    name: str = "My Prescription"
    image_url: Optional[str] = None
    guest_id: Optional[str] = None

def _sanitize_for_bson(obj: Any) -> Any:
    """Recursively ensure dict/list values are BSON-serializable (no NaN, Infinity, etc.)."""
    if obj is None:
        return None
    if isinstance(obj, dict):
        return {str(k): _sanitize_for_bson(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_for_bson(v) for v in obj]
    if isinstance(obj, float) and (obj != obj or abs(obj) == float("inf")):  # NaN or Inf
        return None
    return obj


@app.post("/api/v1/user/prescriptions")
async def save_user_prescription(request: SavePrescriptionRequest, current_user: dict = Depends(verify_token)):
    """Save a new prescription to user's profile (or guest_prescriptions when guest)."""
    if not db_connected:
        raise HTTPException(status_code=503, detail="Database not connected")
    
    try:
        data_to_store = request.data if isinstance(request.data, dict) else {"items": request.data}
        data_to_store = _sanitize_for_bson(data_to_store) or {}
        prescription = {
            "type": str(request.type),
            "data": data_to_store,
            "name": str(request.name),
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        if request.image_url:
            prescription["image_url"] = str(request.image_url)

        # When updating: remove old prescriptions for the same product/cart so only the new one is kept
        assoc = data_to_store.get("associatedProduct") if isinstance(data_to_store, dict) else {}
        if not isinstance(assoc, dict):
            assoc = {}
        product_sku = assoc.get("productSku")
        cart_id = assoc.get("cartId")
        pull_conditions = []
        if product_sku is not None and str(product_sku).strip() != "":
            pull_conditions.append({"data.associatedProduct.productSku": str(product_sku)})
            pull_conditions.append({"associatedProduct.productSku": str(product_sku)})
        if cart_id is not None and str(cart_id).strip() != "":
            pull_conditions.append({"data.associatedProduct.cartId": str(cart_id)})
            pull_conditions.append({"associatedProduct.cartId": str(cart_id)})

        is_guest = current_user.get("is_guest") is True
        if is_guest:
            guest_id = str(current_user["_id"])
            guest_rx_collection = db["guest_prescriptions"]
            # Do $pull and $push in separate ops to avoid driver/BSON issues with combined update
            if pull_conditions:
                try:
                    # Only pull if document exists and has prescriptions (avoid error on missing doc)
                    guest_rx_collection.update_one(
                        {"_id": guest_id, "prescriptions": {"$exists": True}},
                        {"$pull": {"prescriptions": {"$or": pull_conditions}}, "$set": {"updated_at": datetime.now(timezone.utc)}}
                    )
                except Exception as pull_err:
                    logger.warning(f"[RX] Guest pull old prescriptions failed (continuing with push): {pull_err}")
            result = guest_rx_collection.update_one(
                {"_id": guest_id},
                {"$push": {"prescriptions": prescription}, "$set": {"updated_at": datetime.now(timezone.utc)}},
                upsert=True,
            )
            if not result.acknowledged:
                raise RuntimeError("Guest prescription update was not acknowledged by MongoDB")
            logger.info(f"[OK] Prescription saved for guest {guest_id}: type={request.type}, has_image={bool(request.image_url)} (replaced same product/cart)")
        else:
            user_id = current_user["_id"]
            # Ensure user document has prescriptions array (some accounts may not)
            users_collection.update_one(
                {"_id": user_id, "prescriptions": {"$exists": False}},
                {"$set": {"prescriptions": [], "updateTime": datetime.now(timezone.utc)}}
            )
            update_op = {"$push": {"prescriptions": prescription}, "$set": {"updateTime": datetime.now(timezone.utc)}}
            if pull_conditions:
                update_op["$pull"] = {"prescriptions": {"$or": pull_conditions}}
            result = users_collection.update_one(
                {"_id": user_id},
                update_op
            )
            if result.matched_count == 0:
                logger.warning(f"[RX] User {user_id} not found for prescription save, upserting prescriptions array")
                users_collection.update_one(
                    {"_id": user_id},
                    {"$set": {"prescriptions": [prescription], "updateTime": datetime.now(timezone.utc)}},
                    upsert=False
                )
            logger.info(f"[OK] Prescription saved for user {user_id}: type={request.type}, has_image={bool(request.image_url)} (replaced same product/cart)")
        
        return {
            "success": True,
            "message": "Prescription saved successfully",
            "data": prescription
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error saving prescription: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        err_msg = (str(e).strip() or "(no message)") if e else "Failed to save prescription"
        detail = f"{type(e).__name__}: {err_msg}"
        raise HTTPException(status_code=500, detail=detail)

# ---------- CART ENDPOINTS (INTEGRATED!) ----------
@app.get("/api/v1/cart")
async def get_cart(current_user: dict = Depends(verify_token)):
    print(f"DEBUG: app.py - get_cart called for user {current_user['_id']}")
    print(f"DEBUG: app.py - get_cart called for user {current_user['_id']}")
    if not cart_service:
        print("DEBUG: app.py - cart_service is None")
        raise HTTPException(status_code=503, detail="Cart service unavailable")
    
    print(f"DEBUG: app.py - calling cart_service.get_cart_summary")
    result = cart_service.get_cart_summary(str(current_user['_id']))
    print(f"DEBUG: app.py - result: {result}")
    return result

@app.post("/api/v1/cart/add")
async def add_to_cart(request: Request, current_user: dict = Depends(verify_token)):
    if not cart_service:
        raise HTTPException(status_code=503, detail="Cart service unavailable")
    data = await request.json()
    
    # Check if there's a pending prescription for this product_id
    product_id = data.get('product_id') or data.get('product', {}).get('products', {}).get('skuid') or data.get('product', {}).get('products', {}).get('id')
    if product_id and db_connected:
        # Check user document for pending prescription with this product_id
        user = users_collection.find_one({"_id": current_user['_id']})
        if user:
            pending_prescriptions = user.get('pending_prescriptions', {})
            # Try both string and ObjectId key formats
            prescription_data = pending_prescriptions.get(str(product_id)) or pending_prescriptions.get(product_id)
            
            if prescription_data:
                logger.info(f"[RX] Found pending prescription for product {product_id}, including in cart item")
                # Include prescription in cart item data (only if not already present)
                if 'prescription' not in data or not data.get('prescription'):
                    data['prescription'] = prescription_data
                    logger.info(f"[OK] Added pending prescription to cart item")
                
                # Clear pending prescription after adding to cart
                users_collection.update_one(
                    {"_id": current_user['_id']},
                    {"$unset": {f"pending_prescriptions.{product_id}": ""}}
                )
                logger.info(f"[OK] Cleared pending prescription for product {product_id}")
    
    return cart_service.add_to_cart(str(current_user['_id']), data)

@app.put("/api/v1/cart/quantity")
async def update_quantity(cart_id: int, quantity: int, current_user: dict = Depends(verify_token)):
    if not cart_service:
        raise HTTPException(status_code=503, detail="Cart service unavailable")
    if quantity < 1:
        raise HTTPException(status_code=400, detail="Quantity must be at least 1")
    return cart_service.update_quantity(str(current_user['_id']), cart_id, quantity)

@app.delete("/api/v1/cart/item/{cart_id}")
async def remove_item(cart_id: str, current_user: dict = Depends(verify_token)):
    if not cart_service:
        raise HTTPException(status_code=503, detail="Cart service unavailable")
    try:
        cid = int(cart_id)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid cart_id")
    return cart_service.remove_item(str(current_user['_id']), cid)

@app.delete("/api/v1/cart/clear")
async def clear_cart(current_user: dict = Depends(verify_token)):
    if not cart_service:
        raise HTTPException(status_code=503, detail="Cart service unavailable")
    return cart_service.clear_cart(str(current_user['_id']))

class ApplyCouponRequest(BaseModel):
    code: str

class UpdateShippingRequest(BaseModel):
    method_id: str

@app.post("/api/v1/cart/coupon")
async def apply_coupon(request: ApplyCouponRequest, current_user: dict = Depends(verify_token)):
    if not cart_service:
        raise HTTPException(status_code=503, detail="Cart service unavailable")
    return cart_service.apply_coupon(str(current_user['_id']), request.code)

@app.delete("/api/v1/cart/coupon")
async def remove_coupon(current_user: dict = Depends(verify_token)):
    if not cart_service:
        raise HTTPException(status_code=503, detail="Cart service unavailable")
    return cart_service.remove_coupon(str(current_user['_id']))

@app.put("/api/v1/cart/shipping")
async def update_shipping(request: UpdateShippingRequest, current_user: dict = Depends(verify_token)):
    if not cart_service:
        raise HTTPException(status_code=503, detail="Cart service unavailable")
    return cart_service.update_shipping_method(str(current_user['_id']), request.method_id)

class UpdateLensRequest(BaseModel):
    cart_id: int
    lens_data: Dict[str, Any]

class UpdatePrescriptionRequest(BaseModel):
    cart_id: int
    prescription_data: Dict[str, Any]

@app.put("/api/v1/cart/lens")
async def update_cart_lens(request: UpdateLensRequest, current_user: dict = Depends(verify_token)):
    if not cart_service:
        raise HTTPException(status_code=503, detail="Cart service unavailable")
    return cart_service.update_lens(str(current_user['_id']), request.cart_id, request.lens_data)

@app.put("/api/v1/cart/prescription")
async def update_cart_prescription(
    request: Request,
    cart_id: int = Form(...),
    mode: str = Form("upload"),
    prescription_data: Optional[str] = Form(None),
    current_user: dict = Depends(verify_token)
):
    """
    Update cart with prescription - supports both file upload and manual entry
    
    For file upload (mode='upload'):
        - prescription_file: File to upload
        - Uploads to GCS and stores URL
    
    For manual entry (mode='manual'):
        - prescription_data: JSON string with prescription details
    """
    if not cart_service:
        raise HTTPException(status_code=503, detail="Cart service unavailable")
    
    try:
        from prescription_gcs_service import upload_prescription_to_gcs
        
        # Handle file upload mode
        if mode == "upload":
            # Get file from request
            form_data = await request.form()
            file = form_data.get('prescription_file')
            
            if not file:
                raise HTTPException(status_code=400, detail="No prescription file provided")
            
            # Upload to GCS
            upload_result = upload_prescription_to_gcs(
                file.file,
                str(current_user['_id']),
                cart_id,
                file.filename  # Pass filename explicitly
            )
            
            if not upload_result['success']:
                raise HTTPException(
                    status_code=500,
                    detail=upload_result.get('error', 'Failed to upload prescription')
                )
            
            # Prepare prescription data with GCS URL
            prescription_dict = {
                'mode': 'upload',
                'gcs_url': upload_result['gcs_url'],
                'blob_name': upload_result['blob_name'],
                'fileName': file.filename,
                'fileType': upload_result['format'],
                'fileSize': upload_result['size'],
                'uploadedAt': upload_result['uploaded_at']
            }
            
            # Update cart
            result = cart_service.update_prescription(
                str(current_user['_id']),
                cart_id,
                prescription_dict
            )
            
            # Add GCS URL to response
            if result.get('success'):
                result['gcs_url'] = upload_result['gcs_url']
            
            return result
            
        elif mode == "manual":
            # Handle manual prescription entry, or remove prescription (empty / "{}")
            import json
            if not prescription_data or (isinstance(prescription_data, str) and prescription_data.strip() in ("", "{}", "null")):
                prescription_dict = {}
            else:
                prescription_dict = json.loads(prescription_data) if isinstance(prescription_data, str) else prescription_data
                prescription_dict['mode'] = 'manual'
            
            return cart_service.update_prescription(
                str(current_user['_id']),
                cart_id,
                prescription_dict
            )
        else:
            raise HTTPException(status_code=400, detail=f"Invalid mode: {mode}")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating prescription: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Failed to update prescription: {str(e)}")


class MergeGuestCartRequest(BaseModel):
    guest_id: str

@app.post("/api/v1/cart/merge-guest-cart")
async def merge_guest_cart(request: MergeGuestCartRequest, current_user: dict = Depends(verify_token)):
    """
    Merge guest cart items into authenticated user's cart after login.
    This endpoint is called by the frontend after successful authentication.
    """
    if not cart_service:
        raise HTTPException(status_code=503, detail="Cart service unavailable")
    
    try:
        logger.info(f"[MERGE] Merging guest cart {request.guest_id} into user {current_user['_id']}")
        
        # Get guest cart items
        guest_cart = cart_service.get_cart_summary(request.guest_id)
        
        if not guest_cart.get('success') or not guest_cart.get('cart'):
            logger.info(f"[OK] No items in guest cart {request.guest_id} to merge")
            return {"success": True, "message": "No items to merge", "items_merged": 0}
        
        guest_items = guest_cart['cart']  # Changed from 'items' to 'cart'
        user_id = str(current_user['_id'])
        items_merged = 0
        
        logger.info(f"[MERGE] Found {len(guest_items)} items in guest cart to merge")
        
        # Add each guest item to user's cart
        for item in guest_items:
            try:
                # Prepare item data for adding to cart
                item_data = {
                    'product_id': item.get('product', {}).get('products', {}).get('skuid') or item.get('product', {}).get('products', {}).get('id'),
                    'name': item.get('product', {}).get('products', {}).get('name'),
                    'image': item.get('product', {}).get('products', {}).get('image'),
                    'price': item.get('product', {}).get('products', {}).get('list_price', 0),
                    'quantity': item.get('quantity', 1),
                    'product': item.get('product'),
                    'lens': item.get('lens'),
                    'prescription': item.get('prescription'),
                    'flag': item.get('flag', 'normal')
                }
                
                logger.info(f"   Adding item: {item_data.get('name')} (qty: {item_data.get('quantity')})")
                cart_service.add_to_cart(user_id, item_data)
                items_merged += 1
            except Exception as e:
                logger.error(f"[ERR] Failed to merge item: {e}")
                continue
        
        # Clear guest cart after successful merge
        try:
            cart_service.clear_cart(request.guest_id)
            logger.info(f"[OK] Cleared guest cart {request.guest_id}")
        except Exception as e:
            logger.warning(f"[WARN] Failed to clear guest cart: {e}")
        
        logger.info(f"[OK] Successfully merged {items_merged} items from guest cart")
        return {
            "success": True,
            "message": f"Successfully merged {items_merged} items",
            "items_merged": items_merged
        }
        
    except Exception as e:
        logger.error(f"[ERR] Error merging guest cart: {e}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Failed to merge cart: {str(e)}")


# ---------- ORDER ENDPOINTS ----------
class CreateOrderRequest(BaseModel):
    cart_items: List[Dict[str, Any]]
    payment_data: Dict[str, Any]
    shipping_address: str
    billing_address: str
    metadata: Optional[Dict[str, Any]] = None
    prescriptions: Optional[List[Dict[str, Any]]] = None  # Full prescriptions (photo/manual with image_url) from frontend

@app.post("/api/v1/orders")
async def create_order(request: CreateOrderRequest, current_user: dict = Depends(verify_token)):
    """
    Create a new order
    
    Request body:
    {
        "cart_items": [...],  # Cart items from cart service
        "payment_data": {...},
        "shipping_address": "...",
        "billing_address": "...",
        "metadata": {},  # Optional; may contain prescriptions
        "prescriptions": []  # Optional; full prescriptions (type, image_url, data) - merged into metadata for DB
    }
    """
    if not order_service:
        raise HTTPException(status_code=503, detail="Order service unavailable")
    
    try:
        user_id = str(current_user['_id'])
        user_email = current_user.get('email', '')
        
        # Merge prescriptions from body so camera/upload prescription (image_url) is stored in order
        metadata = dict(request.metadata) if request.metadata else {}
        if request.prescriptions is not None:
            metadata["prescriptions"] = request.prescriptions
            logger.info(f"[ORDER] Using {len(request.prescriptions)} prescription(s) from request (photo/manual with image_url)")
        
        # Get discount and shipping from cart
        discount_amount = 0.0
        shipping_cost = 0.0
        if cart_service:
            cart_res = cart_service.get_cart_summary(user_id)
            if cart_res.get('success'):
                discount_amount = float(cart_res.get('discount_amount', 0))
                shipping_cost = float(cart_res.get('shipping_cost', 0))
        
        result = order_service.create_order(
            user_id=user_id,
            user_email=user_email,
            cart_items=request.cart_items,
            payment_data=request.payment_data,
            shipping_address=request.shipping_address,
            billing_address=request.billing_address,
            discount_amount=discount_amount,
            shipping_cost=shipping_cost,
            metadata=metadata
        )
        
        # Send order confirmation email (after booking via POST /api/v1/orders)
        if not result.get('success'):
            print("[ORDER EMAIL] Not sent: order creation did not succeed.")
        elif not notification_service:
            print("[ORDER EMAIL] Not sent: notification_service is not loaded (check MSG91 config).")
        else:
            try:
                user_name = f"{current_user.get('firstName', '')} {current_user.get('lastName', '')}".strip() or "Customer"
                order_id = result.get('order_id', 'N/A')
                total = sum(item.get('total_price', 0) for item in request.cart_items)
                total_str = f"£{total:.2f}"
                email_result = notification_service.send_order_confirmation(
                    user_email, order_id, total_str, user_name
                )
                if email_result.get("success"):
                    print(f"[ORDER EMAIL] SENT to {user_email} for order {order_id} (total {total_str}).")
                else:
                    print(f"[ORDER EMAIL] NOT SENT to {user_email}: {email_result.get('msg', 'unknown error')}")
            except Exception as e:
                print(f"[ORDER EMAIL] NOT SENT: exception - {e}")
                logger.warning(f"Failed to send order confirmation email: {e}")
        
        return result
        
    except Exception as e:
        logger.error(f"[ERR] Error creating order: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Failed to create order: {str(e)}")

@app.get("/api/v1/orders")
async def get_user_orders(current_user: dict = Depends(verify_token)):
    """
    Get all orders for the authenticated user
    """
    if not order_service:
        raise HTTPException(status_code=503, detail="Order service unavailable")
    
    try:
        user_id = str(current_user['_id'])
        result = order_service.get_user_orders(user_id)
        return result
        
    except Exception as e:
        logger.error(f"[ERR] Error fetching orders: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch orders: {str(e)}")

@app.get("/api/v1/orders/{order_id}")
async def get_order_details(order_id: str, current_user: dict = Depends(verify_token)):
    """
    Get details for a specific order
    """
    if not order_service:
        raise HTTPException(status_code=503, detail="Order service unavailable")
    
    try:
        user_id = str(current_user['_id'])
        result = order_service.get_order_by_id(order_id, user_id)
        
        if not result.get('success'):
            raise HTTPException(status_code=404, detail="Order not found")
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[ERR] Error fetching order {order_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch order: {str(e)}")


@app.patch("/api/v1/orders/{order_id}")
async def update_order_with_cart(order_id: str, body: UpdateOrderWithCartRequest, current_user: dict = Depends(verify_token)):
    """
    Update order with cart and totals (called from payment-success page to fix £0 order).
    """
    if not order_service:
        raise HTTPException(status_code=503, detail="Order service unavailable")
    result = order_service.update_order_with_cart(
        order_id=order_id,
        cart_items=body.cart_items,
        subtotal=body.subtotal,
        discount_amount=body.discount_amount,
        shipping_cost=body.shipping_cost,
        total_payable=body.total_payable,
    )
    if not result.get("success"):
        raise HTTPException(status_code=404 if result.get("message") == "Order not found" else 500, detail=result.get("message") or result.get("error"))
    return result


@app.get("/api/v1/orders/thank-you/{order_id}")
async def get_thank_you_data(order_id: str, current_user: dict = Depends(verify_token)):
    """
    Get order data for thank you page
    This endpoint is used by OrderView.tsx
    """
    if not order_service:
        raise HTTPException(status_code=503, detail="Order service unavailable")
    
    try:
        user_id = str(current_user['_id'])
        result = order_service.get_order_by_id(order_id, user_id)
        
        if not result.get('success'):
            raise HTTPException(status_code=404, detail="Order not found")
        
        # Return in the format expected by frontend
        return {
            "status": True,
            "order": result.get('order'),
            "shipping_address": result.get('order', {}).get('shipping_address'),
            "billing_address": result.get('order', {}).get('billing_address')
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[ERR] Error fetching thank you data for order {order_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch order data: {str(e)}")


# ---------- PAYMENT ENDPOINTS ----------

@app.post("/api/v1/payment/create-session")
async def create_payment_session(request: CreatePaymentSessionRequest, current_user: dict = Depends(verify_token)):
    """
    Create Stripe Checkout Session AND Create Pending Order
    
    Request:
    - order_id: str (Frontend generated, will be replaced/mapped to backend ID)
    - amount: float
    - metadata: dict (contains address, customer_id, etc.)
    """
    if not payment_service or not order_service:
        raise HTTPException(status_code=503, detail="Payment or Order service unavailable")
    
    try:
        user_id = str(current_user['_id'])
        user_email = current_user.get('email', '')
        
        # 1. Prepare Order Data
        # Parse items from metadata if possible, otherwise use empty list (simulated)
        # Ideally frontend should send items, but CreatePaymentSessionRequest might not have them
        # We'll try to get items from cart service if not in metadata
        
        items = []
        discount_amount = 0.0
        shipping_cost = 0.0
        subtotal_from_cart = None
        total_payable_from_cart = None
        # Prefer frontend payload so order has correct cart/totals even if backend cart is empty
        if getattr(request, "cart_items", None) and len(request.cart_items) > 0:
            items = request.cart_items
            discount_amount = float(request.discount_amount or 0)
            shipping_cost = float(request.shipping_cost or 0)
            if request.subtotal is not None:
                subtotal_from_cart = float(request.subtotal)
            if request.total_payable is not None:
                total_payable_from_cart = float(request.total_payable)
            logger.info(f"[CART] Using frontend cart_items ({len(items)} items) and totals")
        elif cart_service:
             logger.info(f"[CART] Fetching cart for user {user_id}")
             cart_res = cart_service.get_cart_summary(user_id)
             logger.info(f"[CART] Cart response success: {cart_res.get('success')}")
             if cart_res.get('success'):
                 items = cart_res.get('cart', [])
                 discount_amount = float(cart_res.get('discount_amount', 0))
                 shipping_cost = float(cart_res.get('shipping_cost', 0))
                 logger.info(f"[CART] Cart items count: {len(items)}")
                 logger.info(f"[CART] Cart pricing - Discount: £{discount_amount}, Shipping: £{shipping_cost}")
                 
                 # Warn if shipping or discount are zero
                 if shipping_cost == 0:
                     logger.warning(f"[WARN] Shipping cost is £0 for user {user_id}")
                     logger.warning(f"   Cart has shipping_method: {cart_res.get('shipping_method')}")
                     logger.warning(f"   Subtotal: £{cart_res.get('subtotal', 0)} (Free shipping threshold: £75)")
                     if cart_res.get('subtotal', 0) > 75:
                         logger.info(f"   [OK] Free shipping applied (subtotal > £75)")
                 
                 if discount_amount == 0:
                     logger.warning(f"[WARN] Discount is £0 for user {user_id}")
                     logger.warning(f"   Cart has coupon: {cart_res.get('coupon')}")
                     if not cart_res.get('coupon'):
                         logger.info(f"   [INFO] No coupon applied - this is normal if user didn't enter a code")
                 
                 # Log each cart item's pricing details
                 for idx, item in enumerate(items):
                     logger.info(f"  Item {idx + 1}: {item.get('product', {}).get('products', {}).get('name', 'Unknown')}")
                     logger.info(f"    Frame Price: £{item.get('product', {}).get('products', {}).get('list_price', 0)}")
                     logger.info(f"    Lens Price: £{item.get('lens', {}).get('selling_price', 0)}")
                     logger.info(f"    Tint Price: £{item.get('lens', {}).get('tint_price', 0)}")
                     logger.info(f"    Coating Price: £{item.get('lens', {}).get('coating_price', 0)}")
                     logger.info(f"    Quantity: {item.get('quantity', 1)}")
        
        # Parse address
        import json
        address_shipping = ""
        address_billing = ""
        metadata = request.metadata or {}
        
        if 'address' in metadata:
            try:
                addr_data = json.loads(metadata['address']) if isinstance(metadata['address'], str) else metadata['address']
                # Format address string
                if isinstance(addr_data, dict):
                    parts = [
                        addr_data.get('addressLine'),
                        addr_data.get('city'),
                        addr_data.get('state'),
                        addr_data.get('zip'),
                        addr_data.get('country')
                    ]
                    address_shipping = ", ".join([p for p in parts if p])
                    address_billing = address_shipping # Assume same for now
            except:
                pass
        
        logger.info(f"[ADDR] Shipping Address: {address_shipping}")
        logger.info(f"[ADDR] Billing Address: {address_billing}")
                
        # Merge prescriptions from frontend into metadata
        if getattr(request, "prescriptions", None):
            metadata = {**(metadata or {}), "prescriptions": request.prescriptions}

        # 2. Create Order in Database (Status: Pending) - use frontend order_id so payment-success PATCH finds it
        logger.info(f"[ORDER] Creating order with {len(items)} items, discount: £{discount_amount}, shipping: £{shipping_cost}")
        order_res = order_service.create_order(
            user_id=user_id,
            user_email=user_email,
            cart_items=items,
            payment_data={
                "pay_mode": "Stripe / Online",
                "payment_status": "Pending",
                "is_partial": False
            },
            shipping_address=address_shipping,
            billing_address=address_billing,
            discount_amount=discount_amount,
            shipping_cost=shipping_cost,
            metadata=metadata,
            order_id_override=request.order_id,
            subtotal_override=subtotal_from_cart,
            total_payable_override=total_payable_from_cart,
        )

        if not order_res.get('success'):
            raise HTTPException(status_code=500, detail="Failed to create pending order")

        backend_order_id = order_res['order_id']
        
        # 3. Create Stripe Session (include customer_email in metadata for webhook fallback)
        session_res = payment_service.create_checkout_session(
            order_id=backend_order_id,
            amount=request.amount,
            user_email=user_email,
            user_id=user_id,
            metadata={
                **metadata,
                "backend_order_id": backend_order_id,
                "customer_email": user_email or "",
            }
        )
        
        return session_res
        
    except Exception as e:
        logger.error(f"[ERR] Error creating payment session: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Failed to create session: {str(e)}")


# ---------- WEBHOOK ----------
@app.post("/api/v1/payment/webhook")
async def stripe_webhook(request: Request):
    if not payment_service:
        raise HTTPException(status_code=503, detail="Payment service unavailable")
    import stripe
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, config.STRIPE_WEBHOOK_SECRET)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")

    if event.type == "checkout.session.completed":
        session = event.data.object
        if session.payment_status == "paid":
            # Pass cart_service so order can be created from cart if it wasn't created at create-session
            confirm_result = payment_service.confirm_payment(session.id, cart_service=cart_service)
            # Send order confirmation email after successful payment
            if not confirm_result.get("success"):
                print("[ORDER EMAIL] Not sent: payment confirm failed.")
                logger.warning("[ORDER EMAIL] Not sent: payment confirm failed.")
            elif not notification_service:
                print("[ORDER EMAIL] Not sent: notification_service is not loaded (check MSG91 config).")
                logger.warning("[ORDER EMAIL] Not sent: notification_service is not loaded.")
            else:
                try:
                    order_id = confirm_result.get("order_id")
                    order_doc = payment_service.orders_collection.find_one({"order_id": order_id})
                    if not order_doc:
                        print(f"[ORDER EMAIL] Not sent: order {order_id} not found in DB after confirm_payment.")
                        logger.warning(f"[WEBHOOK] Order {order_id} not found in DB after confirm_payment, skipping email")
                    else:
                        user_email = order_doc.get("customer_email") or getattr(session, "customer_email", None) or (session.metadata or {}).get("customer_email") or ""
                        if not user_email:
                            print(f"[ORDER EMAIL] Not sent: no customer_email for order {order_id}.")
                            logger.warning(f"[WEBHOOK] No customer_email for order {order_id}, skipping order confirmation email")
                        else:
                            total = order_doc.get("total_payable") or order_doc.get("order_total") or confirm_result.get("amount_total") or 0
                            total_str = f"£{float(total):.2f}"
                            user_name = "Customer"
                            user_id = order_doc.get("user_id") or (session.metadata or {}).get("user_id")
                            if user_id:
                                try:
                                    accounts_coll = payment_service.db[config.COLLECTION_NAME]
                                    user = accounts_coll.find_one({"_id": ObjectId(user_id)})
                                    if not user and user_id:
                                        user = accounts_coll.find_one({"_id": user_id})
                                    if user:
                                        user_name = f"{user.get('firstName', '')} {user.get('lastName', '')}".strip() or user.get("firstName") or user.get("name") or "Customer"
                                except Exception:
                                    pass
                            email_result = notification_service.send_order_confirmation(user_email, order_id, total_str, user_name)
                            if email_result.get("success"):
                                print(f"[ORDER EMAIL] SENT to {user_email} for order {order_id} (total {total_str}).")
                                logger.info(f"Order confirmation email sent to {user_email} for order {order_id}")
                            else:
                                print(f"[ORDER EMAIL] NOT SENT to {user_email}: {email_result.get('msg', 'unknown error')}")
                                logger.warning(f"Order confirmation email failed: {email_result.get('msg', 'unknown')}")
                except Exception as e:
                    print(f"[ORDER EMAIL] NOT SENT: exception - {e}")
                    logger.exception(f"Failed to send order confirmation email after Stripe webhook: {e}")
    elif event.type == "checkout.session.expired":
        session = event.data.object
        payment_service.payments_collection.update_one(
            {"session_id": session.id},
            {"$set": {"status": "expired", "expired_at": datetime.now(timezone.utc)}}
        )
    return {"success": True}

# ---------- DELIVERY ENDPOINTS ----------
@app.post("/api/v1/delivery/check-pincode")
async def check_pincode(request: CheckPincodeRequest):
    if not delivery_service:
        raise HTTPException(status_code=503, detail="Delivery service unavailable")
    
    return delivery_service.bluedart.check_pincode_serviceability(request.pincode)

@app.post("/api/v1/delivery/create-shipment")
async def create_shipment(request: CreateShipmentRequest, current_user: dict = Depends(verify_token)):
    if not delivery_service:
        raise HTTPException(status_code=503, detail="Delivery service unavailable")
        
    # Ideally verify order ownership here
    
    return delivery_service.create_shipment(request.order_id, request.customer_details)

@app.get("/api/v1/delivery/track/{awb_number}")
async def track_shipment(awb_number: str):
    if not delivery_service:
        raise HTTPException(status_code=503, detail="Delivery service unavailable")
    return delivery_service.get_shipment_status(awb_number)

# ---------- PRODUCT ENDPOINTS ----------
class Product(BaseModel):
    skuid: str
    name: str
    brand: Optional[str] = None
    style: Optional[str] = None
    size: Optional[str] = None
    price: float
    color_names: List[str] = []
    primary_category: Optional[str] = None
    secondary_category: Optional[str] = None
    material: Optional[str] = None
    gender: Optional[str] = None
    comfort: List[str] = []
    description: Optional[str] = None
    image: Optional[str] = None
    is_active: bool = True

class ProductCreate(BaseModel):
    """Model for creating/updating products"""
    skuid: str
    name: str
    naming_system: Optional[str] = None
    brand: Optional[str] = None
    price: float
    list_price: Optional[float] = None
    description: Optional[str] = None
    image: Optional[str] = None
    images: Optional[List[str]] = []
    colors: Optional[List[str]] = []
    color_names: Optional[List[str]] = []
    framecolor: Optional[str] = None
    style: Optional[str] = None
    gender: Optional[str] = None
    size: Optional[str] = None
    material: Optional[str] = None
    shape: Optional[str] = None
    features: Optional[List[str]] = []
    variants: Optional[List[Dict[str, Any]]] = []
    sizes: Optional[List[str]] = []
    primary_category: Optional[str] = None
    secondary_category: Optional[str] = None
    comfort: Optional[List[str]] = []
    is_active: bool = True

@app.get("/api/v1/products")
async def get_products(
    page: int = 1, 
    limit: int = 20, 
    category: Optional[str] = None,
    brand: Optional[str] = None,
    gender: Optional[str] = None,
    search: Optional[str] = None,
    material: Optional[str] = None,  # NEW: Filter by material
    style: Optional[str] = None,  # NEW: Filter by style (Full Frame, Half Frame, Rimless)
    comfort: Optional[str] = None,  # NEW: Filter by comfort features
    size: Optional[str] = None,  # NEW: Filter by size
    min_price: Optional[float] = None,  # NEW: Minimum price
    max_price: Optional[float] = None,  # NEW: Maximum price
    frame_color: Optional[str] = None,  # NEW: Filter by frame color
    shape: Optional[str] = None,  # NEW: Filter by shape
):
    if not db_connected:
        raise HTTPException(status_code=503, detail="Database unavailable")

    
    query = {"is_active": True}
    
    # Existing filters
    if category:
        query["primary_category"] = {"$regex": category, "$options": "i"}
    if brand:
        query["brand"] = {"$regex": brand, "$options": "i"}
    if gender:
        query["gender"] = {"$regex": gender, "$options": "i"}
    
    # NEW: Material filter
    if material:
        query["material"] = {"$regex": material, "$options": "i"}
    
    # NEW: Style filter
    if style:
        query["style"] = {"$regex": style, "$options": "i"}
    
    # NEW: Comfort filter (array field)
    if comfort:
        query["comfort"] = {"$in": [comfort]}
    
    # NEW: Size filter
    if size:
        query["size"] = {"$regex": size, "$options": "i"}
    
    # NEW: Price range filter
    if min_price is not None or max_price is not None:
        price_query = {}
        if min_price is not None:
            price_query["$gte"] = min_price
        if max_price is not None:
            price_query["$lte"] = max_price
        if price_query:
            query["price"] = price_query
    
    # NEW: Frame color filter
    if frame_color:
        query["frame_color"] = {"$regex": frame_color, "$options": "i"}
    
    # NEW: Shape filter (exact match for better accuracy)
    if shape:
        query["shape"] = shape
    
    # Search query
    if search:
        query["$or"] = [
            {"name": {"$regex": search, "$options": "i"}},
            {"skuid": {"$regex": search, "$options": "i"}},
            {"brand": {"$regex": search, "$options": "i"}},
            {"naming_system": {"$regex": search, "$options": "i"}}
        ]
        
    products_collection = db['products']
    total = products_collection.count_documents(query)
    cursor = products_collection.find(query).skip((page - 1) * limit).limit(limit)
    
    products = []
    for doc in cursor:
        doc["_id"] = str(doc["_id"])
        products.append(doc)
        
    return {
        "success": True,
        "data": products,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "pages": (total + limit - 1) // limit
        }
    }

@app.get("/api/v1/products/{product_id}")
async def get_product_by_id(product_id: str):
    if not db_connected:
        raise HTTPException(status_code=503, detail="Database unavailable")
        
    try:
        products_collection = db['products']
        product = products_collection.find_one({"_id": ObjectId(product_id)})
        if not product:
            raise HTTPException(status_code=404, detail="Product not found")
            
        product["_id"] = str(product["_id"])
        return {"success": True, "data": product}
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid product ID")

@app.get("/api/v1/products/sku/{sku}")
async def get_product_by_sku(sku: str):
    if not db_connected:
        raise HTTPException(status_code=503, detail="Database unavailable")
        
    products_collection = db['products']
    product = products_collection.find_one({"skuid": sku})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
        
    product["_id"] = str(product["_id"])
    return {"success": True, "data": product}

@app.post("/api/v1/products/create")
async def create_product(product: ProductCreate, current_user: dict = Depends(verify_token)):
    """
    Create or update a product in the database.
    Uses upsert - will create new product or update existing one with same SKU.
    Requires authentication.
    """
    if not db_connected:
        raise HTTPException(status_code=503, detail="Database unavailable")
    
    try:
        products_collection = db['products']
        
        # Prepare product data
        product_data = {
            "skuid": product.skuid,
            "name": product.name,
            "naming_system": product.naming_system or product.skuid,
            "brand": product.brand or "",
            "price": float(product.price),
            "list_price": float(product.list_price) if product.list_price else None,
            "description": product.description or "",
            "image": product.image or "",
            "images": product.images or [],
            "colors": product.colors or [],
            "color_names": product.color_names or [],
            "framecolor": product.framecolor or "",
            "style": product.style or "",
            "gender": product.gender or "",
            "size": product.size or "",
            "material": product.material or "",
            "shape": product.shape or "",
            "features": product.features or [],
            "variants": product.variants or [],
            "sizes": product.sizes or [],
            "primary_category": product.primary_category or "",
            "secondary_category": product.secondary_category or "",
            "comfort": product.comfort or [],
            "is_active": product.is_active
        }
        
        # Remove None values
        product_data = {k: v for k, v in product_data.items() if v is not None}
        
        # Upsert product (create if doesn't exist, update if exists)
        result = products_collection.update_one(
            {"skuid": product.skuid},
            {"$set": product_data},
            upsert=True
        )
        
        # Get the created/updated product
        created_product = products_collection.find_one({"skuid": product.skuid})
        if created_product:
            created_product["_id"] = str(created_product["_id"])
        
        if result.upserted_id:
            logger.info(f"[OK] Created new product: {product.skuid}")
            return {
                "success": True,
                "message": "Product created successfully",
                "data": created_product
            }
        else:
            logger.info(f"[OK] Updated existing product: {product.skuid}")
            return {
                "success": True,
                "message": "Product updated successfully",
                "data": created_product
            }
            
    except Exception as e:
        logger.error(f"[ERR] Error creating product: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create product: {str(e)}")

@app.get("/api/v1/public/products")
async def get_public_products(
    page: int = 1,
    limit: int = 100,
    category: Optional[str] = None,
    brand: Optional[str] = None,
    gender: Optional[str] = None,
    search: Optional[str] = None
):
    return await get_products(page, limit, category, brand, gender, search)

@app.get("/retailer/product-inventory")
async def get_product_inventory(
    page: int = 1, 
    limit: int = 20, 
    category: Optional[str] = None,
    brand: Optional[str] = None,
    gender: Optional[str] = None, # Added gender filter
    search: Optional[str] = None,
    material: Optional[str] = None,
    style: Optional[str] = None,
    comfort: Optional[str] = None,
    size: Optional[str] = None,
    min_price: Optional[float] = None,
    max_price: Optional[float] = None,
    frame_color: Optional[str] = None,
    shape: Optional[str] = None,  # NEW: Shape filter
):
    # Enhanced to support all filter parameters
    return await get_products(
        page, limit, category, brand, gender, search,
        material, style, comfort, size, min_price, max_price, frame_color, shape
    )


# ---------- FILTER OPTIONS ENDPOINT ----------
@app.get("/api/v1/products/filters/options")
async def get_filter_options():
    """
    Get all available filter options from the database
    Returns unique values for each filterable field
    """
    if not db_connected:
        raise HTTPException(status_code=503, detail="Database unavailable")
    
    products_collection = db['products']
    
    # Get unique values for each filter field
    brands = products_collection.distinct("brand")
    genders = products_collection.distinct("gender")
    materials = products_collection.distinct("material")
    styles = products_collection.distinct("style")
    sizes = products_collection.distinct("size")
    frame_colors = products_collection.distinct("frame_color")
    
    # Get all unique comfort features (since it's an array field)
    comfort_pipeline = [
        {"$unwind": "$comfort"},
        {"$group": {"_id": "$comfort"}},
        {"$sort": {"_id": 1}}
    ]
    comfort_results = list(products_collection.aggregate(comfort_pipeline))
    comfort_options = [r["_id"] for r in comfort_results if r["_id"]]
    
    # Get price range
    price_pipeline = [
        {"$group": {
            "_id": None,
            "min_price": {"$min": "$price"},
            "max_price": {"$max": "$price"}
        }}
    ]
    price_result = list(products_collection.aggregate(price_pipeline))
    price_range = price_result[0] if price_result else {"min_price": 0, "max_price": 500}
    
    return {
        "success": True,
        "data": {
            "brands": sorted([b for b in brands if b]),
            "genders": sorted([g for g in genders if g]),
            "materials": sorted([m for m in materials if m]),
            "styles": sorted([s for s in styles if s]),
            "sizes": sorted([sz for sz in sizes if sz]),
            "frame_colors": sorted([fc for fc in frame_colors if fc]),
            "comfort": sorted(comfort_options),
            "price_range": {
                "min": price_range.get("min_price", 0),
                "max": price_range.get("max_price", 500)
            }
        }
    }

# ---------- PIN AUTHENTICATION ----------
class RequestPinRequest(BaseModel):
    email: EmailStr

class LoginWithPinRequest(BaseModel):
    email: EmailStr
    pin: str

@app.post("/api/v1/auth/request-pin")
async def request_pin(request: RequestPinRequest):
    if not db_connected:
        raise HTTPException(status_code=503, detail="Database unavailable")
    
    user = users_collection.find_one({"email": request.email})
    if not user:
        # For security, don't reveal if user exists, but for now we'll return success
        # In a real app, we might want to send a generic "If your email is registered..."
        return {"success": True, "msg": "If your email is registered, a PIN has been sent."}
    
    # Generate 6-digit PIN
    import random
    pin = str(random.randint(100000, 999999))
    print(f"DEBUG: Generated PIN for {request.email}: {pin}")
    
    # Store PIN with expiry (e.g., 15 minutes)
    expiry = datetime.now(timezone.utc) + timedelta(minutes=15)
    
    users_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"pin": pin, "pin_expiry": expiry}}
    )
    
    # Send PIN via MSG91
    if notification_service:
        user_name = f"{user.get('firstName', '')} {user.get('lastName', '')}".strip() or None
        notification_service.send_login_pin(request.email, pin, user_name)
        print(f"DEBUG: Sent PIN via MSG91 to {request.email}")
    else:
        print(f"DEBUG: MSG91 not configured. Generated PIN for {request.email}: {pin}")
    
    return {"success": True, "msg": "PIN sent successfully"}

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    email: EmailStr
    pin: str
    new_password: str

@app.post("/api/v1/auth/forgot-password")
async def forgot_password(request: ForgotPasswordRequest):
    if not db_connected:
        raise HTTPException(status_code=503, detail="Database unavailable")
    
    # Normalize email
    email = request.email.lower().strip()
    
    user = users_collection.find_one({"email": email})
    if not user:
        # Return success to prevent email enumeration
        return {"success": True, "msg": "If your email is registered, a reset PIN has been sent."}
    
    # Generate 6-digit PIN
    import random
    pin = str(random.randint(100000, 999999))
    
    # Store PIN with expiry
    expiry = datetime.now(timezone.utc) + timedelta(minutes=15)
    
    # Update with verification
    result = users_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {
            "reset_pin": pin, 
            "reset_pin_expiry": expiry,
            "reset_pin_created_at": datetime.now(timezone.utc)
        }}
    )
    
    # Log the update result
    print(f"DEBUG: Update result for {email} - matched: {result.matched_count}, modified: {result.modified_count}")
    
    # Verify the PIN was stored
    updated_user = users_collection.find_one({"_id": user["_id"]})
    if updated_user.get("reset_pin"):
        print(f"DEBUG: Successfully stored reset_pin for {email}")
    else:
        print(f"ERROR: Failed to store reset_pin for {email}")
        raise HTTPException(status_code=500, detail="Failed to generate reset code")
    
    # Send PIN via MSG91 with error handling
    try:
        if notification_service:
            user_name = f"{user.get('firstName', '')} {user.get('lastName', '')}".strip() or None
            notification_service.send_password_reset_pin(email, pin, user_name)
            print(f"DEBUG: Sent Reset PIN via MSG91 to {email}")
        else:
            print(f"DEBUG: MSG91 not configured. Generated Reset PIN for {email}: {pin}")
    except Exception as e:
        print(f"ERROR: Failed to send notification to {email}: {e}")
        # Don't fail the request - PIN is still stored in DB
    
    return {"success": True, "msg": "Reset instructions sent successfully"}


@app.post("/api/v1/auth/reset-password")
async def reset_password(request: ResetPasswordRequest):
    if not db_connected:
        raise HTTPException(status_code=503, detail="Database unavailable")
    
    # Normalize email
    email = request.email.lower().strip()
    
    user = users_collection.find_one({"email": email})
    if not user:
        print(f"DEBUG: User not found for email: {email}")
        raise HTTPException(status_code=400, detail={"success": False, "msg": "Invalid credentials"})
    
    stored_pin = user.get("reset_pin")
    pin_expiry = user.get("reset_pin_expiry")
    
    # Enhanced debugging
    print(f"DEBUG: Reset attempt for {email}")
    print(f"DEBUG: Has reset_pin: {bool(stored_pin)}")
    print(f"DEBUG: Has pin_expiry: {bool(pin_expiry)}")
    print(f"DEBUG: User ID: {user['_id']}")
    
    if not stored_pin or not pin_expiry:
        print(f"ERROR: Missing PIN data for {email}")
        print(f"DEBUG: All user fields: {list(user.keys())}")
        raise HTTPException(
            status_code=400, 
            detail={
                "success": False, 
                "msg": "No reset requested or PIN expired. Please request a new reset PIN."
            }
        )
    
    # Ensure pin_expiry is timezone-aware
    if pin_expiry.tzinfo is None:
        pin_expiry = pin_expiry.replace(tzinfo=timezone.utc)
    
    current_time = datetime.now(timezone.utc)
    print(f"DEBUG: Current time: {current_time}, PIN expiry: {pin_expiry}")
    
    if current_time > pin_expiry:
        print(f"ERROR: PIN expired for {email}")
        raise HTTPException(
            status_code=400, 
            detail={
                "success": False, 
                "msg": "PIN expired. Please request a new reset PIN."
            }
        )
    
    if stored_pin != request.pin:
        print(f"ERROR: Invalid PIN provided for {email}")
        raise HTTPException(
            status_code=400, 
            detail={
                "success": False, 
                "msg": "Invalid PIN"
            }
        )
    
    # Update password and clear PIN
    hashed_password = hash_password(request.new_password)
    users_collection.update_one(
        {"_id": user["_id"]},
        {
            "$set": {
                "password": hashed_password, 
                "updateTime": datetime.now(timezone.utc)
            },
            "$unset": {
                "reset_pin": "", 
                "reset_pin_expiry": "",
                "reset_pin_created_at": ""
            }
        }
    )
    
    print(f"DEBUG: Password reset successful for {email}")
    
    return {"success": True, "msg": "Password reset successfully. Please login."}


# Optional: Add endpoint to check reset status (for debugging)
@app.get("/api/v1/auth/debug/reset-status/{email}")
async def debug_reset_status(email: str):
    """Debug endpoint - remove in production"""
    if not db_connected:
        raise HTTPException(status_code=503, detail="Database unavailable")
    
    email = email.lower().strip()
    user = users_collection.find_one({"email": email})
    
    if not user:
        return {"found": False}
    
    return {
        "found": True,
        "has_reset_pin": bool(user.get("reset_pin")),
        "has_reset_expiry": bool(user.get("reset_pin_expiry")),
        "pin_expired": datetime.now(timezone.utc) > user.get("reset_pin_expiry", datetime.min.replace(tzinfo=timezone.utc)) if user.get("reset_pin_expiry") else None,
        "fields": list(user.keys())
    }

    
@app.post("/api/v1/auth/login-with-pin")
async def login_with_pin(request: LoginWithPinRequest):
    if not db_connected:
        raise HTTPException(status_code=503, detail="Database unavailable")
        
    user = users_collection.find_one({"email": request.email})
    if not user:
        raise HTTPException(status_code=400, detail={"success": False, "msg": "Invalid credentials"})
        
    stored_pin = user.get("pin")
    pin_expiry = user.get("pin_expiry")
    
    if not stored_pin or not pin_expiry:
        raise HTTPException(status_code=400, detail={"success": False, "msg": "No PIN requested or PIN expired"})
        
    # Ensure pin_expiry is timezone-aware
    if pin_expiry.tzinfo is None:
        pin_expiry = pin_expiry.replace(tzinfo=timezone.utc)
        
    if datetime.now(timezone.utc) > pin_expiry:
        raise HTTPException(status_code=400, detail={"success": False, "msg": "PIN expired"})
        
    if stored_pin != request.pin:
        raise HTTPException(status_code=400, detail={"success": False, "msg": "Invalid PIN"})
        
    # Clear PIN after successful login
    users_collection.update_one(
        {"_id": user["_id"]},
        {"$unset": {"pin": "", "pin_expiry": ""}, "$set": {"updateTime": datetime.now(timezone.utc)}}
    )
    
    token = generate_jwt_token(str(user["_id"]), user["email"])
    return {
        "success": True,
        "status": 200,
        "msg": "Login successful",
        "data": {
            "first_name": user.get("firstName", ""),
            "last_name": user.get("lastName", ""),
            "email": user["email"],
            "mobile": str(user.get("primaryContact", "")),
            "mobile_international": user.get("international_mobile", ""),
            "is_verified": user.get("is_verified", False),
            "refer_code": user.get("my_code", ""),
            "id": str(user["_id"]),
            "token": token,
            "is_new_user": False
        }
    }

# ---------- NEWSLETTER SUBSCRIPTION (public, no auth) ----------
NEWSLETTER_SUBSCRIPTIONS_COLLECTION_NAME = "newsletter_subscriptions"

class NewsletterSubscribeRequest(BaseModel):
    email: EmailStr

@app.post("/api/v1/newsletter/subscribe")
async def newsletter_subscribe(request: NewsletterSubscribeRequest):
    """
    Save newsletter subscription to MongoDB collection 'newsletter_subscriptions'
    and send one email to admin (CONTACT_FORM_TO_EMAIL / SMTP_EMAIL). No auth.
    """
    ensure_db()
    if not db_connected or db is None:
        raise HTTPException(
            status_code=503,
            detail="Database not connected. Set MONGO_URI in newbackend/.env.",
        )
    try:
        collection = db[NEWSLETTER_SUBSCRIPTIONS_COLLECTION_NAME]
        email_lower = request.email.strip().lower()
        doc = {
            "email": email_lower,
            "created_at": datetime.now(timezone.utc),
        }
        result = collection.insert_one(doc)
        logger.info("[NEWSLETTER] Saved subscription id=%s email=%s", result.inserted_id, email_lower)

        notify_to = (getattr(config, "CONTACT_FORM_TO_EMAIL", None) or "").strip() or (getattr(config, "SMTP_EMAIL", None) or "").strip()
        if notify_to and notification_service:
            logger.info("[NEWSLETTER] Sending notification to %s", notify_to)
            try:
                res = notification_service.send_newsletter_subscription_notification(to_email=notify_to, subscriber_email=email_lower)
                if not res.get("success"):
                    logger.warning("[NEWSLETTER] Email send failed: %s", res.get("msg", "unknown"))
            except Exception as mail_err:
                logger.warning("[NEWSLETTER] Email notification failed (subscription still saved): %s", mail_err)
        else:
            if not notify_to:
                logger.warning("[NEWSLETTER] No CONTACT_FORM_TO_EMAIL or SMTP_EMAIL in .env - skipping email")

        return {
            "success": True,
            "message": "Thanks for subscribing to our newsletter.",
            "id": str(result.inserted_id),
        }
    except Exception as e:
        logger.error("[NEWSLETTER] Error: %s", e)
        raise HTTPException(status_code=500, detail="Failed to subscribe")

# ---------- CONTACT FORM (public, no auth) ----------
CONTACT_SUBMISSIONS_COLLECTION_NAME = "contact_submissions"

class ContactSubmitRequest(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    phone: str
    comment: str

@app.post("/api/v1/contact")
async def submit_contact(request: ContactSubmitRequest):
    """
    Save contact form submission to MongoDB collection 'contact_submissions'.
    No authentication required.
    """
    ensure_db()
    if not db_connected or db is None:
        raise HTTPException(
            status_code=503,
            detail="Database not connected. Set MONGO_URI in newbackend/.env to your MongoDB Atlas URI (not localhost).",
        )
    try:
        collection = db[CONTACT_SUBMISSIONS_COLLECTION_NAME]
        doc = {
            "first_name": request.first_name.strip(),
            "last_name": request.last_name.strip(),
            "email": request.email.strip().lower(),
            "phone": request.phone.strip(),
            "comment": request.comment.strip(),
            "created_at": datetime.now(timezone.utc),
        }
        result = collection.insert_one(doc)
        logger.info("[CONTACT] Saved submission id=%s email=%s", result.inserted_id, request.email)

        # Send contact form details to your email (if SMTP configured)
        notify_to = (getattr(config, "CONTACT_FORM_TO_EMAIL", None) or "").strip() or (getattr(config, "SMTP_EMAIL", None) or "").strip()
        if notify_to and notification_service:
            logger.info("[CONTACT] Sending email notification to %s", notify_to)
            try:
                res = notification_service.send_contact_form_notification(
                    to_email=notify_to,
                    first_name=doc["first_name"],
                    last_name=doc["last_name"],
                    sender_email=doc["email"],
                    phone=doc["phone"],
                    comment=doc["comment"],
                )
                if not res.get("success"):
                    logger.warning("[CONTACT] Email send failed: %s", res.get("msg", "unknown"))
            except Exception as mail_err:
                logger.warning("[CONTACT] Email notification failed (submission still saved): %s", mail_err)
        else:
            if not notify_to:
                logger.warning("[CONTACT] No CONTACT_FORM_TO_EMAIL or SMTP_EMAIL in .env - skipping email")
            elif not notification_service:
                logger.warning("[CONTACT] notification_service not loaded - skipping email")

        return {
            "success": True,
            "message": "Thank you for contacting us. We will get back to you shortly.",
            "id": str(result.inserted_id),
        }
    except Exception as e:
        logger.error("[CONTACT] Error saving submission: %s", e)
        raise HTTPException(status_code=500, detail="Failed to submit contact form")

# ---------- HEALTH ----------
@app.get("/api/health")
@app.get("/health")
async def health_check():
    user_count = users_collection.count_documents({}) if db_connected else None
    out = {
        "success": True,
        "message": "API is running",
        "mongodb": "connected" if db_connected else "disconnected",
        "total_users": user_count,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if not db_connected and mongo_connection_error:
        out["mongodb_error"] = mongo_connection_error
    return out


@app.get("/api/why-disconnected")
async def why_disconnected():
    """Returns the exact reason MongoDB is disconnected."""
    return {
        "mongodb": "connected" if db_connected else "disconnected",
        "reason": mongo_connection_error if (not db_connected and mongo_connection_error) else None,
    }

# ---------- RECENTLY VIEWED ----------
class RecentlyViewedRequest(BaseModel):
    product_id: str

@app.get("/api/v1/products/recently-viewed")
async def get_recently_viewed(token: str = Depends(security)):
    if not db_connected:
        raise HTTPException(status_code=503, detail="Database unavailable")
    
    try:
        payload = jwt.decode(token.credentials, config.SECRET_KEY, algorithms=["HS256"])
        user_email = payload.get("sub")
        
        user = users_collection.find_one({"email": user_email})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
            
        recently_viewed_ids = user.get("recently_viewed", [])
        
        # Fetch product details (Mocking product fetch for now as product collection structure isn't fully defined in context)
        # In a real scenario, you would query the products collection
        # products = db.products.find({"skuid": {"$in": recently_viewed_ids}})
        
        return {
            "success": True, 
            "data": recently_viewed_ids # Returning IDs for now, frontend can fetch details or we can expand this
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        print(f"Error fetching recently viewed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/products/recently-viewed")
async def add_recently_viewed(request: RecentlyViewedRequest, token: str = Depends(security)):
    if not db_connected:
        raise HTTPException(status_code=503, detail="Database unavailable")
        
    try:
        payload = jwt.decode(token.credentials, config.SECRET_KEY, algorithms=["HS256"])
        user_email = payload.get("sub")
        
        # Add to set to avoid duplicates, keep only last 10
        users_collection.update_one(
            {"email": user_email},
            {
                "$addToSet": {"recently_viewed": request.product_id}
            }
        )
        
        # Optional: Limit to last 10 (requires more complex query or pull)
        
        return {"success": True, "msg": "Added to recently viewed"}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception as e:
        print(f"Error adding recently viewed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    
    logger.info("=" * 80)
    logger.info("[START] STARTING FASTAPI SERVER")
    logger.info("=" * 80)
    
    # Print all registered routes
    logger.info("[ROUTES] Registered Routes:")
    for route in app.routes:
        if hasattr(route, 'methods') and hasattr(route, 'path'):
            logger.info(f"   {route.path} [{','.join(route.methods)}]")
    
    if db_connected:
        user_count = users_collection.count_documents({})
        logger.info(f"[DB] {config.DATABASE_NAME} | Collection: {config.COLLECTION_NAME} | Users: {user_count}")
    
    logger.info("[OK] Routes enabled: /simple-register/, /login/, /unified, /auth/")
    logger.info("[OK] Registration: mobile accepted in any format (global users, no UK restriction)")
    logger.info("[OK] Cart Routes enabled: /api/v1/cart/*")
    logger.info("[OK] Delivery Routes enabled: /api/v1/delivery/*")
    logger.info("=" * 80)
    logger.info(f"[OK] Server starting on http://{getattr(config, 'HOST', '0.0.0.0')}:{getattr(config, 'PORT', 5000)}")
    logger.info("=" * 80)
    
    uvicorn.run(
        app,
        host=getattr(config, "HOST", "0.0.0.0"),
        port=getattr(config, "PORT", 5000),
        log_level="info"
    )

