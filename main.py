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
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import random
import string

# ─────────────────────────────────────────
# CONFIGURAÇÃO
# ─────────────────────────────────────────
SECRET_KEY = os.getenv("SECRET_KEY", "changeme-secret-key-123")
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
GMAIL_USER = os.getenv("GMAIL_USER", "")
GMAIL_PASSWORD = os.getenv("GMAIL_PASSWORD", "")
TRIAL_LIMIT = 3
APP_URL = os.getenv("APP_URL", "https://stem-separator-licenses-production.up.railway.app")

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
    is_verified = Column(Boolean, default=False)
    verification_code = Column(String, nullable=True)
    is_subscribed = Column(Boolean, default=False)
    plan = Column(String, nullable=True)
    songs_used = Column(Integer, default=0)
    stripe_customer_id = Column(String, nullable=True)
    subscription_end = Column(DateTime, nullable=True)
    mac_address = Column(String, nullable=True)
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
            raise HTTPException(status_code=401, detail="Utilizador não encontrado")
        return user
    except Exception:
        raise HTTPException(status_code=401, detail="Token inválido")

def generate_code() -> str:
    return ''.join(random.choices(string.digits, k=6))

async def send_verification_email(email: str, code: str):
    if not GMAIL_USER or not GMAIL_PASSWORD:
        print("EMAIL ERROR: Gmail credentials not configured")
        return
    try:
        print(f"Sending email to {email} with code {code}")
        msg = MIMEMultipart('alternative')
        msg['Subject'] = 'Confirma o teu email — Stem Separator'
        msg['From'] = f'Stem Separator <{GMAIL_USER}>'
        msg['To'] = email

        html = f"""
        <div style="font-family: Arial, sans-serif; max-width: 400px; margin: 0 auto;">
            <h2 style="color: #6C63FF;">Stem Separator</h2>
            <p>Olá! O teu código de verificação é:</p>
            <div style="background: #1A1A2E; color: #6C63FF; font-size: 36px; font-weight: bold;
                        text-align: center; padding: 20px; border-radius: 12px; letter-spacing: 8px;">
                {code}
            </div>
            <p style="color: #666;">Este código expira em 15 minutos.</p>
        </div>
        """
        msg.attach(MIMEText(html, 'html'))

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(GMAIL_USER, GMAIL_PASSWORD)
            server.sendmail(GMAIL_USER, email, msg.as_string())
            print(f"Email sent successfully to {email}")
    except Exception as e:
        print(f"EMAIL ERROR: {e}")

# ─────────────────────────────────────────
# MODELOS
# ─────────────────────────────────────────
class RegisterRequest(BaseModel):
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

class VerifyRequest(BaseModel):
    email: str
    code: str

class MacRequest(BaseModel):
    mac_address: str

class CheckoutRequest(BaseModel):
    plan: str
    success_url: str
    cancel_url: str

# ─────────────────────────────────────────
# ENDPOINTS
# ─────────────────────────────────────────

@app.post("/register")
async def register(req: RegisterRequest, db: Session = Depends(get_db)):
    if len(req.password) > 72:
        raise HTTPException(status_code=400, detail="Password demasiado longa (máximo 72 caracteres)")

    if db.query(User).filter(User.email == req.email).first():
        raise HTTPException(status_code=400, detail="Email já registado")

    code = generate_code()
    user = User(
        email=req.email,
        password_hash=pwd_context.hash(req.password),
        verification_code=code,
        is_verified=False,
    )
    db.add(user)
    db.commit()

    await send_verification_email(req.email, code)

    return {"message": "Conta criada! Verifica o teu email para ativar a conta.", "email": req.email}

@app.post("/verify")
def verify_email(req: VerifyRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Utilizador não encontrado")

    if user.verification_code != req.code:
        raise HTTPException(status_code=400, detail="Código incorreto")

    user.is_verified = True
    user.verification_code = None
    db.commit()

    token = create_token(req.email)
    return {"token": token, "email": req.email, "message": "Email verificado com sucesso!"}

@app.post("/resend-code")
async def resend_code(email: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Utilizador não encontrado")

    code = generate_code()
    user.verification_code = code
    db.commit()

    await send_verification_email(email, code)
    return {"message": "Código reenviado!"}

@app.post("/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user or not pwd_context.verify(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Email ou password incorretos")

    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Email não verificado. Verifica o teu email.")

    token = create_token(req.email)
    return {"token": token, "email": req.email}

@app.post("/register-mac")
def register_mac(req: MacRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()

    # Verifica se o MAC já está registado noutro utilizador
    existing = db.query(User).filter(
        User.mac_address == req.mac_address,
        User.email != user.email
    ).first()

    if existing:
        # PC já foi usado antes — esgota o trial imediatamente
        if not db_user.is_subscribed:
            db_user.songs_used = TRIAL_LIMIT

    # Verifica se este utilizador já tem outro MAC registado
    if db_user.mac_address and db_user.mac_address != req.mac_address:
        raise HTTPException(
            status_code=403,
            detail="Esta licença já está registada noutro computador. Contacta o suporte para transferir."
        )

    db_user.mac_address = req.mac_address
    db.commit()
    return {"message": "Computador registado com sucesso!"}

@app.get("/license")
def get_license(user: User = Depends(get_current_user)):
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
            "mac_registered": user.mac_address is not None,
        }
    else:
        remaining = max(0, TRIAL_LIMIT - user.songs_used)
        return {
            "status": "trial" if remaining > 0 else "expired",
            "plan": "trial",
            "songs_used": user.songs_used,
            "songs_remaining": remaining,
            "subscription_end": None,
            "mac_registered": user.mac_address is not None,
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
        raise HTTPException(status_code=400, detail="Plano inválido")

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

    if event_type in ["customer.subscription.created", "customer.subscription.updated"]:
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
            {"id": "monthly",   "name": "Mensal",     "price": "9.99€",  "period": "mês"},
            {"id": "quarterly", "name": "Trimestral", "price": "19.99€", "period": "3 meses"},
            {"id": "yearly",    "name": "Anual",      "price": "49.99€", "period": "ano"},
        ]
    }

@app.get("/health")
def health():
    return {"status": "ok"}