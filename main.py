from datetime import datetime, timedelta, timezone
from typing import Annotated
from sqlalchemy import Column, Float, String, Text
from sqlalchemy.ext.declarative import declarative_base
import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import Column, String, Boolean, Integer, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy import create_engine

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

DATABASE_URL = "postgresql+psycopg2://anotaton:bea25sof1v4l3@localhost:5432/anotaton"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ========================
# MODELOS DE BASE DE DATOS
# ========================

class UserDB(Base):
    __tablename__ = "users"
    username = Column(String, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="anotador")  # Puede ser 'staff' o 'anotador'

class Response(Base):
    __tablename__ = "responses"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    response = Column(Text, nullable=False)
    translation = Column(Text, nullable=False)
    human = Column(Text, nullable=False)
    conversation_id = Column(String(255), nullable=True)
    tutor_identity = Column(String(255), nullable=True)
    
class Conversation(Base):
    __tablename__ = "conversations"
    conversation_id = Column(String(255), primary_key=True, index=True)
    conversation_history = Column(Text, nullable=False)
    translation = Column(Text, nullable=False)
    
class Entropy(Base):
    __tablename__ = "entropies"
    conversation_id = Column(String(255), primary_key=True, index=True)
    tutor_identity = Column(String(255), nullable=True)
    entropy = Column(Float, nullable=False)
    assigned = Column(Boolean, default=False)
    annotated = Column(Boolean, default=False)

Base.metadata.create_all(bind=engine)

# ========================
# MODELOS Pydantic
# ========================

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None

class User(BaseModel):
    username: str
    role: str

class UserInDB(User):
    hashed_password: str

class UserCreate(BaseModel):
    username: str
    password: str
    role: str

class ResponseEntryCreate(BaseModel):
    response: str
    translation: str
    human: str
    conversation_id: str | None = None
    tutor_identity: str | None = None

class ResponseEntryRead(ResponseEntryCreate):
    id: int
    
class ResponseCreate(BaseModel):
    conversation_id: str
    tutor_identity: str
    response: str
    translation: str
    human: str

class ResponseRead(ResponseCreate):
    pass  # No necesita campos adicionales
    
class ConversationCreate(BaseModel):
    conversation_id: str
    conversation_history: str
    translation: str

class ConversationRead(ConversationCreate):
    pass  # No necesita campos adicionales

class EntropyCreate(BaseModel):
    conversation_id: str
    tutor_identity: str | None = None
    entropy: float
    assigned: bool = False
    annotated: bool = False

class EntropyRead(EntropyCreate):
    pass  # No necesita campos adicionales

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

# ========================
# DEPENDENCIAS
# ========================

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db: Session, username: str):
    return db.query(UserDB).filter(UserDB.username == username).first()

def authenticate_user(db: Session, username: str, password: str):
    user = get_user(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ========================
# ENDPOINTS AUTENTICACIÓN
# ========================

@app.post("/register")
async def register_user(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(UserDB).filter(UserDB.username == user.username).first()
    
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    hashed_password = get_password_hash(user.password)
    new_user = UserDB(username=user.username, hashed_password=hashed_password, role=user.role)

    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return {"msg": "User registered successfully"}

@app.post("/token")
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return Token(access_token=access_token, token_type="bearer")

@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: Annotated[User, Depends(lambda token: get_user(SessionLocal(), jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM]).get("sub")))]):
    if current_user is None:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# ========================
# CRUD Conversations
# ========================


@app.post("/conversations/", response_model=ConversationRead)
async def create_conversation(conversation: ConversationCreate, db: Session = Depends(get_db)):
    db_conversation = Conversation(**conversation.dict())
    db.add(db_conversation)
    db.commit()
    db.refresh(db_conversation)
    return db_conversation

@app.get("/conversations/{conversation_id}", response_model=ConversationRead)
async def get_conversation(conversation_id: str, db: Session = Depends(get_db)):
    conversation = db.query(Conversation).filter(Conversation.conversation_id == conversation_id).first()
    if not conversation:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return conversation

@app.get("/conversations/", response_model=list[ConversationRead])
async def list_conversations(db: Session = Depends(get_db)):
    return db.query(Conversation).all()

@app.put("/conversations/{conversation_id}", response_model=ConversationRead)
async def update_conversation(conversation_id: str, conversation: ConversationCreate, db: Session = Depends(get_db)):
    db_conversation = db.query(Conversation).filter(Conversation.conversation_id == conversation_id).first()
    if not db_conversation:
        raise HTTPException(status_code=404, detail="Conversation not found")
    
    for key, value in conversation.dict().items():
        setattr(db_conversation, key, value)
    
    db.commit()
    db.refresh(db_conversation)
    return db_conversation

@app.delete("/conversations/{conversation_id}")
async def delete_conversation(conversation_id: str, db: Session = Depends(get_db)):
    db_conversation = db.query(Conversation).filter(Conversation.conversation_id == conversation_id).first()
    if not db_conversation:
        raise HTTPException(status_code=404, detail="Conversation not found")
    
    db.delete(db_conversation)
    db.commit()
    return {"msg": "Conversation deleted successfully"}

# ========================
# CRUD Response
# ========================

@app.post("/responses/", response_model=ResponseRead)
async def create_response(response: ResponseCreate, db: Session = Depends(get_db)):
    db_response = Response(**response.dict())
    db.add(db_response)
    db.commit()
    db.refresh(db_response)
    return db_response

@app.get("/responses/{conversation_id}/{tutor_identity}", response_model=ResponseRead)
async def get_response(conversation_id: str, tutor_identity: str, db: Session = Depends(get_db)):
    response = db.query(Response).filter(
        Response.conversation_id == conversation_id,
        Response.tutor_identity == tutor_identity
    ).first()
    
    if not response:
        raise HTTPException(status_code=404, detail="Response not found")
    return response

@app.get("/responses/", response_model=list[ResponseRead])
async def list_responses(db: Session = Depends(get_db)):
    return db.query(Response).all()

@app.put("/responses/{conversation_id}/{tutor_identity}", response_model=ResponseRead)
async def update_response(conversation_id: str, tutor_identity: str, response: ResponseCreate, db: Session = Depends(get_db)):
    db_response = db.query(Response).filter(
        Response.conversation_id == conversation_id,
        Response.tutor_identity == tutor_identity
    ).first()

    if not db_response:
        raise HTTPException(status_code=404, detail="Response not found")
    
    for key, value in response.dict().items():
        setattr(db_response, key, value)
    
    db.commit()
    db.refresh(db_response)
    return db_response

@app.delete("/responses/{conversation_id}/{tutor_identity}")
async def delete_response(conversation_id: str, tutor_identity: str, db: Session = Depends(get_db)):
    db_response = db.query(Response).filter(
        Response.conversation_id == conversation_id,
        Response.tutor_identity == tutor_identity
    ).first()
    
    if not db_response:
        raise HTTPException(status_code=404, detail="Response not found")
    
    db.delete(db_response)
    db.commit()
    return {"msg": "Response deleted successfully"}

# ========================
# CRUD Entropy
# ========================

@app.post("/entropies/", response_model=EntropyRead)
async def create_entropy(entropy: EntropyCreate, db: Session = Depends(get_db)):
    db_entropy = Entropy(**entropy.dict())
    db.add(db_entropy)
    db.commit()
    db.refresh(db_entropy)
    return db_entropy

@app.get("/entropies/{conversation_id}/{tutor_identity}", response_model=EntropyRead)
async def get_entropy(conversation_id: str, tutor_identity: str, db: Session = Depends(get_db)):
    entropy = db.query(Entropy).filter(
        Entropy.conversation_id == conversation_id,
        Entropy.tutor_identity == tutor_identity
    ).first()
    
    if not entropy:
        raise HTTPException(status_code=404, detail="Entropy entry not found")
    return entropy

@app.get("/entropies/", response_model=list[EntropyRead])
async def list_entropies(db: Session = Depends(get_db)):
    return db.query(Entropy).all()

@app.put("/entropies/{conversation_id}/{tutor_identity}", response_model=EntropyRead)
async def update_entropy(conversation_id: str, tutor_identity: str, entropy: EntropyCreate, db: Session = Depends(get_db)):
    db_entropy = db.query(Entropy).filter(
        Entropy.conversation_id == conversation_id,
        Entropy.tutor_identity == tutor_identity
    ).first()

    if not db_entropy:
        raise HTTPException(status_code=404, detail="Entropy entry not found")
    
    for key, value in entropy.dict().items():
        setattr(db_entropy, key, value)
    
    db.commit()
    db.refresh(db_entropy)
    return db_entropy

@app.delete("/entropies/{conversation_id}/{tutor_identity}")
async def delete_entropy(conversation_id: str, tutor_identity: str, db: Session = Depends(get_db)):
    db_entropy = db.query(Entropy).filter(
        Entropy.conversation_id == conversation_id,
        Entropy.tutor_identity == tutor_identity
    ).first()
    
    if not db_entropy:
        raise HTTPException(status_code=404, detail="Entropy entry not found")
    
    db.delete(db_entropy)
    db.commit()
    return {"msg": "Entropy entry deleted successfully"}

@app.get("/entropies/highest/", response_model=EntropyRead)
async def get_highest_entropy(db: Session = Depends(get_db)):
    # Get the highest entropy entry that is not assigned
    highest_entropy = (
        db.query(Entropy)
        .filter(Entropy.assigned == False)
        .order_by(Entropy.entropy.desc())
        .first()
    )

    if not highest_entropy:
        raise HTTPException(status_code=404, detail="No available entropy entry")

    # Mark it as assigned
    highest_entropy.assigned = True
    db.commit()
    db.refresh(highest_entropy)

    return highest_entropy