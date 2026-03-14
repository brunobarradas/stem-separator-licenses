from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, Integer, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
import stripe
import os
import uuid

# ─────────────────────────────────────────
# CONFIGURAÇÃO
# ─────────────────────────────────────────
SECRET_KEY = os.getenv("SECRET_KEY", "changeme-secret-key-123")
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
TRIAL_LIMIT = 3

STRIPE_PRICES = {
    "monthly":   os.getenv("STRIPE_PRICE_MONTHLY", "price_1TAcQ5RU38iMYmcGLUHDFIja"),
    "quarterly": os.getenv("STRIPE_PRICE_QUARTERLY", "price_1TAcRMRU38iMYmcGUYaGPxdu"),
    "yearly":    os.getenv("STRIPE_PRICE_YEARLY", "price_1TAcRVRU38iMYmcG6Hf6icuf"),
}

stripe.api_key = STRIPE_SECRET_KEY

# ─────────────────────────────────────────
# BASE DE DADOS
# ─────────────────────────────────────────
DATABASE_URL = "sqlite:///./licenses.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    is_subscribed = Column(Boolean, default=False)
    plan = Column(String, nullable=True)  # monthly, quarterly, yearly
    songs_used = Column(Integer, default=0)
    stripe_customer_id = Column(String, nullable=True)
    subscription_end = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# ─────────────────────────────────────────
# APP
# ─────────────────────────────────────────
app = FastAPI(title="Stem Separator License Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_token(email: str) -> str:
    expire = datetime.utcnow() + timedelta(days=30)
    return jwt.encode({"sub": email, "exp": expire}, SECRET_KEY, algorithm="HS256")

def get_current_user(authorization: str = Header(...), db: Session = Depends(get_db)) -> User:
    try:
        token = authorization.replace("Bearer ", "")
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        email = payload.get("sub")
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

# ─────────────────────────────────────────
# MODELOS
# ─────────────────────────────────────────
class RegisterRequest(BaseModel):
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

class CheckoutRequest(BaseModel):
    plan: str  # monthly, quarterly, yearly
    success_url: str
    cancel_url: str

# ─────────────────────────────────────────
# ENDPOINTS
# ─────────────────────────────────────────

@app.post("/register")
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == req.email).first():
        raise HTTPException(status_code=400, detail="Email já registado")

    user = User(
        email=req.email,
        password_hash=pwd_context.hash(req.password),
    )
    db.add(user)
    db.commit()
    token = create_token(req.email)
    return {"token": token, "email": req.email}

@app.post("/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user or not pwd_context.verify(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Email ou password incorretos")

    token = create_token(req.email)
    return {"token": token, "email": req.email}

@app.get("/license")
def get_license(user: User = Depends(get_current_user)):
    # Verifica se subscrição expirou
    if user.is_subscribed and user.subscription_end:
        if datetime.utcnow() > user.subscription_end:
            user.is_subscribed = False

    if user.is_subscribed:
        return {
            "status": "pro",
            "plan": user.plan,
            "songs_used": user.songs_used,
            "songs_remaining": None,
            "subscription_end": user.subscription_end.isoformat() if user.subscription_end else None,
        }
    else:
        remaining = max(0, TRIAL_LIMIT - user.songs_used)
        return {
            "status": "trial" if remaining > 0 else "expired",
            "plan": "trial",
            "songs_used": user.songs_used,
            "songs_remaining": remaining,
            "subscription_end": None,
        }

@app.post("/use")
def use_song(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not user.is_subscribed and user.songs_used >= TRIAL_LIMIT:
        raise HTTPException(status_code=403, detail="Trial expirado. Subscreve para continuar.")

    db_user = db.query(User).filter(User.email == user.email).first()
    db_user.songs_used += 1
    db.commit()

    return {"songs_used": db_user.songs_used}

@app.post("/create-checkout")
def create_checkout(req: CheckoutRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Stripe não configurado")

    price_id = STRIPE_PRICES.get(req.plan)
    if not price_id:
        raise HTTPException(status_code=400, detail="Plano inválido. Use: monthly, quarterly ou yearly")

    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user.stripe_customer_id:
        customer = stripe.Customer.create(email=user.email)
        db_user.stripe_customer_id = customer.id
        db.commit()

    session = stripe.checkout.Session.create(
        customer=db_user.stripe_customer_id,
        payment_method_types=["card"],
        line_items=[{"price": price_id, "quantity": 1}],
        mode="subscription",
        success_url=req.success_url,
        cancel_url=req.cancel_url,
        metadata={"plan": req.plan, "email": user.email},
    )

    return {"url": session.url, "plan": req.plan}

@app.post("/webhook")
async def stripe_webhook(request: dict):
    event_type = request.get("type")

    if event_type == "customer.subscription.created" or event_type == "customer.subscription.updated":
        obj = request["data"]["object"]
        customer_id = obj["customer"]
        end_timestamp = obj["current_period_end"]
        end_date = datetime.fromtimestamp(end_timestamp)
        plan_name = obj.get("metadata", {}).get("plan", "monthly")

        db = SessionLocal()
        user = db.query(User).filter(User.stripe_customer_id == customer_id).first()
        if user:
            user.is_subscribed = True
            user.subscription_end = end_date
            user.plan = plan_name
            db.commit()
        db.close()

    elif event_type == "customer.subscription.deleted":
        customer_id = request["data"]["object"]["customer"]
        db = SessionLocal()
        user = db.query(User).filter(User.stripe_customer_id == customer_id).first()
        if user:
            user.is_subscribed = False
            user.plan = None
            db.commit()
        db.close()

    return {"status": "ok"}

@app.get("/plans")
def get_plans():
    return {
        "plans": [
            {"id": "monthly",   "name": "Mensal",    "price": "9.99€",  "period": "mês",       "price_id": STRIPE_PRICES["monthly"]},
            {"id": "quarterly", "name": "Trimestral","price": "19.99€", "period": "3 meses",   "price_id": STRIPE_PRICES["quarterly"]},
            {"id": "yearly",    "name": "Anual",     "price": "49.99€", "period": "ano",       "price_id": STRIPE_PRICES["yearly"]},
        ]
    }

@app.get("/health")
def health():
    return {"status": "ok"}