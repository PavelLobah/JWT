# Пример аутентификации с использованием JWT в FastAPI

Это пример проекта, демонстрирующего, как реализовать аутентификацию с использованием JWT в приложении на FastAPI.

## Предварительные требования

Убедитесь, что у вас установлены следующие компоненты:

- Python 3.7+
- Фреймворк FastAPI
- Библиотека passlib для хеширования паролей
- Библиотека python-jose для работы с JSON Web Tokens (JWT)

## Установка

1. Клонируйте репозиторий:
```
git@github.com:PavelLobah/JWT.git
```


2. Установите зависимости:
```
pip install -r requirements.txt
```

## Использование

1. Установите секретный ключ в файле `main.py`:

```python
SECRET_KEY = "your-secret-key"
```

2. Запустите приложение:
```
uvicorn main:app --port 8000 --reload
```
или
```
Make
```

3. Используйте следующие конечные точки для взаимодействия с приложением:
**POST /token:** Эта конечная точка используется для получения токена доступа, предоставив имя пользователя и пароль в теле запроса.
**GET /users/me:** Эта конечная точка требует аутентификации и возвращает имя аутентифицированного пользователя.
**POST /token/refresh:** Эта конечная точка используется для обновления истекшего токена доступа, предоставив refresh токен в теле запроса.

## Примечания
Словарь *fake_users_db* служит фиктивной базой данных пользователей для демонстрационных целей. В реальном проекте вы замените его своей собственной базой данных пользователей.
Объект *pwd_context* используется для хеширования паролей. Вы можете настроить алгоритм и параметры хеширования в соответствии с вашими потребностями.
Функция *create_access_token* используется для генерации JWT токена доступа. Вы можете изменить время истечения срока действия и данные токена по своему усмотрению.
Функция *verify_password* используется для проверки предоставленного пароля на соответствие хешированному паролю.
Объект *oauth2_scheme* используется для внедрения зависимостей в конечной точке *read_users_me* для обеспечения аутентификации.