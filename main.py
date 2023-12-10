from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt

app = FastAPI()

# Ключ для подписи токена
SECRET_KEY = "your-secret-key"
# Время истечения срока действия токена (5 минут)
ACCESS_TOKEN_EXPIRE_MINUTES = 5

# Определение класса User
class User:
    def __init__(self, username: str, hashed_password: str, disabled: bool):
        self.username = username
        self.hashed_password = hashed_password
        self.disabled = disabled

# Фейковая база данных пользователей
fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "password": "123",
        "hashed_password": "$2b$12$2BrM2Iu.diU8y/F6K309FuWnvSHkig9HjmbDpAeiZTH95bE4Y9Gn.",
        "disabled": False,
    },
    "pavel": {
        "username": "pavel",
        "password": "123",
        "hashed_password": "$2b$12$2BrM2Iu.diU8y/F6K309FuWnvSHkig9HjmbDpAeiZTH95bE4Y9Gn.",
        "disabled": False,
    },
}

# Контекст для проверки паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Генерация JWT-токена
def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")
    return encoded_jwt

# Проверка пароля
def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

# Получение пользователя из базы данных
def get_user(username: str, password: str):
    user_data = fake_users_db.get(username)
    if user_data and verify_password(password, user_data["hashed_password"]):
        return User(username=user_data["username"], hashed_password=user_data["hashed_password"], disabled=user_data["disabled"])
    return None

# Создание схемы для аутентификации
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# Получение токена доступа
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Неверные имя пользователя или пароль")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me")
async def read_users_me(current_user: str = Depends(oauth2_scheme)):
    return {"username": current_user}

# Обновление токена доступа
@app.post("/token/refresh")
async def refresh_token(form_data: OAuth2PasswordRequestForm = Depends()):
    # Получаем access токен из запроса
    token = form_data.refresh_token
    try:
        # Расшифровываем access токен и проверяем его подлинность
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = decoded_token.get("sub")

        # Получаем пользователя из базы данных
        user = get_user(username, "")

        if user:
            # Генерируем новый access токен
            access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            new_access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)

            # Возвращаем новый access токен
            return {"access_token": new_access_token, "token_type": "bearer"}

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Токен доступа истек")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Неверный токен доступа")

    # Если не удалось обновить токен, возвращаем ошибку
    raise HTTPException(status_code=401, detail="Невозможно обновить токен")    
