import flet as ft
from flet import IconButton, Page, Row, TextField, icons
import hashlib
import hmac
import base64
import string


def main(page: Page):
    page.title = "Paroleum - password manager"
    page.vertical_alignment = "center"

    master_password_field = TextField(label="Master Password", width=200, password=True, can_reveal_password=True)
    login_account_field = TextField(label="Login", width=200)
    account_name_field = TextField(label="Service Name", width=200)

    generated_password_field = TextField(label="Generated password", read_only=True, width=350)

    def generate_password(e):
        master_password = master_password_field.value
        login_account = login_account_field.value
        account_name = account_name_field.value
        generated_password = generate_password_function(master_password, login_account, account_name)
        generated_password_field.value = generated_password
        page.update()

    page.add(
        Row([
            master_password_field,
            login_account_field,
            account_name_field,
            IconButton(icons.PASSWORD, on_click=generate_password),
            generated_password_field
        ], alignment="center")
    )


def generate_password_function(master_password, login_account, account_name):
    # Здесь вы можете реализовать вашу функцию генерации пароля
    # Например, используя какой-то алгоритм хеширования

    master_password_bytes = master_password.encode('utf-8')
    login_account_bytes = login_account.encode('utf-8')
    account_name_bytes = account_name.encode('utf-8')

    # Генерируем соль, используя имя сервиса
    salt = hashlib.sha256(account_name_bytes + login_account_bytes).digest()

    # Используем PBKDF2 для вычисления ключа
    key = hashlib.pbkdf2_hmac('sha512', master_password_bytes, salt, 262144)

    # Используем HMAC для генерации пароля
    hmac_digest = hmac.new(key, account_name_bytes, hashlib.sha512).digest()

    # Возвращаем пароль в виде base64 строки (20 символов)
    generated_password = base64.b64encode(hmac_digest).decode('utf-8')[:20]

    while not (any(c.isupper() for c in generated_password) and
               any(c.islower() for c in generated_password) and
               any(c.isdigit() for c in generated_password) and
               any(c in string.punctuation for c in generated_password)):
        # Если какого-то из условий не выполняется, генерируем новый пароль
        key = hashlib.pbkdf2_hmac('sha512', key, salt, 262144)
        hmac_digest = hmac.new(key, account_name_bytes, hashlib.sha512).digest()
        generated_password = base64.b64encode(hmac_digest).decode('utf-8')[:20]

    return generated_password


ft.app(target=main, view=ft.AppView.WEB_BROWSER)
