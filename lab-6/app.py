from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime, timezone, timedelta
import re
import requests
import os
from dotenv import load_dotenv
import pyotp
import qrcode
from io import BytesIO
import base64

load_dotenv()

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-please-change')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['RECAPTCHA_SITE_KEY'] = os.getenv('RECAPTCHA_SITE_KEY')
app.config['RECAPTCHA_SECRET_KEY'] = os.getenv('RECAPTCHA_SECRET_KEY')

app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

app.config['GITHUB_CLIENT_ID'] = os.getenv('GITHUB_CLIENT_ID')
app.config['GITHUB_CLIENT_SECRET'] = os.getenv('GITHUB_CLIENT_SECRET')
app.config['GITHUB_AUTHORIZE_URL'] = 'https://github.com/login/oauth/authorize'
app.config['GITHUB_TOKEN_URL'] = 'https://github.com/login/oauth/access_token'
app.config['GITHUB_API_BASE_URL'] = 'https://api.github.com/'

db = SQLAlchemy(app)
mail = Mail(app)

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 15 

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # для обмеження спроб входу
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    
    # це для 2FA
    two_fa_secret = db.Column(db.String(32), nullable=True)
    two_fa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    
    #  для OAuth
    github_id = db.Column(db.String(100), unique=True, nullable=True)
    oauth_provider = db.Column(db.String(20), nullable=True)

    def __repr__(self):
        return f'<User {self.username}>'

class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    user_agent = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(20), nullable=False)  # success, failed, blocked
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    failure_reason = db.Column(db.String(100), nullable=True)

    def __repr__(self):
        return f'<LoginLog {self.username} - {self.status}>'


def log_login_attempt(username, status, failure_reason=None):
    """Логує спробу входу в систему"""
    log_entry = LoginLog(
        username=username,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        status=status,
        failure_reason=failure_reason
    )
    db.session.add(log_entry)
    db.session.commit()

# для 2FA
def generate_2fa_secret():
    """Генерує секретний ключ для 2FA"""
    return pyotp.random_base32()

def get_2fa_uri(username, secret):
    """Генерує URI для QR-коду"""
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name='User Management System'
    )

def verify_2fa_code(secret, code):
    """Перевіряє код 2FA"""
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)

def generate_qr_code(data):
    """Генерує QR-код як base64 зображення"""
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return f"data:image/png;base64,{img_str}"

def is_user_locked(user):
    """Перевіряє чи заблокований користувач"""
    if user.locked_until:

        locked_until = user.locked_until
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        
        now = datetime.now(timezone.utc)
        
        if locked_until > now:
            return True, locked_until
    
    return False, None

def reset_failed_attempts(user):
    """Скидає лічильник невдалих спроб"""
    user.failed_login_attempts = 0
    user.locked_until = None
    db.session.commit()

def increment_failed_attempts(user):
    """Збільшує лічильник невдалих спроб і блокує при перевищенні"""
    user.failed_login_attempts += 1
    
    if user.failed_login_attempts >= MAX_LOGIN_ATTEMPTS:
        user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_DURATION)
        flash(f'Акаунт заблоковано на {LOCKOUT_DURATION} хвилин через перевищення кількості невдалих спроб входу', 'danger')
    
    db.session.commit()

def validate_password(password):
    """
    Перевіряє пароль на відповідність політиці безпеки
    """
    if len(password) < 8:
        return False, "Пароль повинен містити мінімум 8 символів"
    
    if not re.search(r'[A-Z]', password):
        return False, "Пароль повинен містити хоча б одну велику літеру"
    
    if not re.search(r'[a-z]', password):
        return False, "Пароль повинен містити хоча б одну малу літеру"
    
    if not re.search(r'\d', password):
        return False, "Пароль повинен містити хоча б одну цифру"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Пароль повинен містити хоча б один спеціальний символ (!@#$%^&* тощо)"
    
    return True, "Пароль відповідає всім вимогам"

def generate_activation_token(email):
    """Генерує токен для активації акаунту"""
    return serializer.dumps(email, salt='email-activation-salt')

def verify_activation_token(token, expiration=3600):
    try:
        email = serializer.loads(token, salt='email-activation-salt', max_age=expiration)
        return email
    except:
        return None

def send_activation_email(user_email, activation_link):
    """Відправляє email з посиланням для активації"""
    msg = Message(
        subject='Активація облікового запису',
        recipients=[user_email]
    )
    
    msg.html = f"""
    <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h2 style="color: #2c3e50;">Вітаємо!</h2>
            <p>Дякуємо за реєстрацію в нашій системі управління обліковими записами.</p>
            <p>Будь ласка, натисніть на кнопку нижче, щоб активувати ваш обліковий запис:</p>
            <p style="margin: 30px 0;">
                <a href="{activation_link}" 
                   style="background-color: #007bff; 
                          color: white; 
                          padding: 12px 30px; 
                          text-decoration: none; 
                          border-radius: 5px;
                          display: inline-block;">
                    Активувати акаунт
                </a>
            </p>
            <p style="color: #7f8c8d; font-size: 0.9em;">
                Або скопіюйте це посилання в браузер:<br>
                <a href="{activation_link}">{activation_link}</a>
            </p>
            <p style="color: #7f8c8d; font-size: 0.9em; margin-top: 30px;">
                Посилання дійсне протягом 1 години.
            </p>
            <hr style="border: none; border-top: 1px solid #ecf0f1; margin: 30px 0;">
            <p style="color: #95a5a6; font-size: 0.8em;">
                Якщо ви не реєструвалися в нашій системі, просто ігноруйте цей лист.
            </p>
        </body>
    </html>
    """
    
    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Помилка відправки email: {e}")
        return False


def generate_reset_token(email):
    """Генерує токен для скидання пароля"""
    return serializer.dumps(email, salt='password-reset-salt')

def verify_reset_token(token, expiration=3600):
    """
    Перевіряє токен скидання пароля
    expiration в секундах (за замовчуванням 1 година)
    """
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=expiration)
        return email
    except:
        return None


def send_reset_password_email(user_email, reset_link):
    """Відправляє email з посиланням для скидання пароля"""

    test_domains = ['toaik.com', 'tempmail.com', '10minutemail', 'guerrillamail', 'mailinator']
    is_test_email = any(domain in user_email for domain in test_domains)
    
    if is_test_email:

        print("\n" + "="*80)
        print("📧 PASSWORD RESET EMAIL (TEST MODE)")
        print(f"To: {user_email}")
        print(f"Reset Link: {reset_link}")
        print("="*80 + "\n")
        return True
    
    msg = Message(
        subject='Відновлення пароля',
        recipients=[user_email]
    )
    
    msg.html = f"""
    <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h2 style="color: #2c3e50;">Відновлення пароля</h2>
            <p>Ви отримали цей лист, оскільки запросили відновлення пароля для вашого облікового запису.</p>
            <p>Будь ласка, натисніть на кнопку нижче, щоб скинути ваш пароль:</p>
            <p style="margin: 30px 0;">
                <a href="{reset_link}" 
                   style="background-color: #dc3545; 
                          color: white; 
                          padding: 12px 30px; 
                          text-decoration: none; 
                          border-radius: 5px;
                          display: inline-block;">
                    Скинути пароль
                </a>
            </p>
            <p style="color: #7f8c8d; font-size: 0.9em;">
                Або скопіюйте це посилання в браузер:<br>
                <a href="{reset_link}">{reset_link}</a>
            </p>
            <p style="color: #7f8c8d; font-size: 0.9em; margin-top: 30px;">
                Посилання дійсне протягом 1 години.
            </p>
            <hr style="border: none; border-top: 1px solid #ecf0f1; margin: 30px 0;">
            <p style="color: #95a5a6; font-size: 0.8em;">
                Якщо ви не запитували відновлення пароля, просто ігноруйте цей лист. 
                Ваш пароль залишиться без змін.
            </p>
        </body>
    </html>
    """
    
    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Помилка відправки email: {e}")
        return False

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        recaptcha_response = request.form.get('g-recaptcha-response')

        if not recaptcha_response:
            flash('Будь ласка, підтвердіть, що ви не робот', 'danger')
            return render_template('register.html', site_key=app.config['RECAPTCHA_SITE_KEY'])
        verify_url = 'https://www.google.com/recaptcha/api/siteverify'
        verify_data = {
            'secret': app.config['RECAPTCHA_SECRET_KEY'],
            'response': recaptcha_response,
            'remoteip': request.remote_addr
        }
        
        verify_response = requests.post(verify_url, data=verify_data)
        result = verify_response.json()
        
        if not result.get('success'):
            flash('Перевірка reCAPTCHA не пройдена. Спробуйте ще раз', 'danger')
            return render_template('register.html', site_key=app.config['RECAPTCHA_SITE_KEY'])

        if not username or not email or not password:
            flash('Будь ласка, заповніть всі поля', 'danger')
            return render_template('register.html', site_key=app.config['RECAPTCHA_SITE_KEY'])

        if password != confirm_password:
            flash('Паролі не співпадають', 'danger')
            return render_template('register.html', site_key=app.config['RECAPTCHA_SITE_KEY'])

        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, 'danger')
            return render_template('register.html', site_key=app.config['RECAPTCHA_SITE_KEY'])

        if User.query.filter_by(username=username).first():
            flash('Користувач з таким ім\'ям вже існує', 'danger')
            return render_template('register.html', site_key=app.config['RECAPTCHA_SITE_KEY'])
        
        if User.query.filter_by(email=email).first():
            flash('Користувач з такою email адресою вже існує', 'danger')
            return render_template('register.html', site_key=app.config['RECAPTCHA_SITE_KEY'])

        password_hash = generate_password_hash(password, method='pbkdf2:sha256')

        new_user = User(username=username, email=email, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()

        token = generate_activation_token(email)
        activation_link = url_for('activate', token=token, _external=True)

        if send_activation_email(email, activation_link):
            flash('Реєстрація успішна! Перевірте вашу пошту для активації акаунту', 'success')
        else:
            flash('Реєстрація успішна, але виникла помилка з відправкою email. Зверніться до адміністратора', 'warning')
        
        return redirect(url_for('login'))
    
    return render_template('register.html', site_key=app.config['RECAPTCHA_SITE_KEY'])

@app.route('/activate/<token>')
def activate(token):
    """Активація облікового запису"""
    email = verify_activation_token(token)
    
    if not email:
        flash('Посилання для активації недійсне або застаріле', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.filter_by(email=email).first()
    
    if not user:
        flash('Користувача не знайдено', 'danger')
        return redirect(url_for('login'))
    
    if user.is_active:
        flash('Акаунт вже активовано. Ви можете увійти', 'info')
        return redirect(url_for('login'))

    user.is_active = True
    db.session.commit()
    
    flash('Акаунт успішно активовано! Тепер ви можете увійти', 'success')
    return redirect(url_for('login'))


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Запит на відновлення пароля"""
    if request.method == 'POST':
        email = request.form.get('email')
        
        if not email:
            flash('Будь ласка, введіть email адресу', 'danger')
            return render_template('forgot_password.html')

        user = User.query.filter_by(email=email).first()
        
        # навіть якщо користувача не існує, то всерівно буде показувати успішне повідомлення (для безпеки)
        flash('Якщо акаунт з такою email адресою існує, ви отримаєте лист з інструкціями', 'info')
        
        if user:

            token = generate_reset_token(email)
            reset_link = url_for('reset_password', token=token, _external=True)

            send_reset_password_email(email, reset_link)
        
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Скидання пароля за токеном"""

    email = verify_reset_token(token)
    
    if not email:
        flash('Посилання для скидання пароля недійсне або застаріле', 'danger')
        return redirect(url_for('forgot_password'))

    user = User.query.filter_by(email=email).first()
    
    if not user:
        flash('Користувача не знайдено', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not password or not confirm_password:
            flash('Будь ласка, заповніть всі поля', 'danger')
            return render_template('reset_password.html', token=token)

        if password != confirm_password:
            flash('Паролі не співпадають', 'danger')
            return render_template('reset_password.html', token=token)

        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, 'danger')
            return render_template('reset_password.html', token=token)
        
        user.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        
        user.failed_login_attempts = 0
        user.locked_until = None
        
        db.session.commit()
        
        flash('Пароль успішно змінено! Тепер ви можете увійти з новим паролем', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        two_fa_code = request.form.get('two_fa_code')
        
        # тут ідентифікується користувач
        user = User.query.filter_by(username=username).first()
        
        if not user:
            log_login_attempt(username, 'failed', 'user_not_found')
            flash('Користувача не знайдено. Будь ласка, зареєструйтесь', 'warning')
            return redirect(url_for('register'))
        
        # перевірка чи заблокований акаунт
        is_locked, locked_until = is_user_locked(user)
        if is_locked:
            now = datetime.now(timezone.utc)
            if locked_until.tzinfo is None:
                locked_until = locked_until.replace(tzinfo=timezone.utc)
            
            remaining_time = (locked_until - now).total_seconds() / 60
            log_login_attempt(username, 'blocked', 'account_locked')
            flash(f'Акаунт заблоковано. Спробуйте через {int(remaining_time)} хвилин', 'danger')
            return render_template('login.html')
        
        # перевірка чи активований акаунт
        if not user.is_active:
            log_login_attempt(username, 'failed', 'not_activated')
            flash('Акаунт не активовано. Перевірте вашу пошту для активації', 'warning')
            return render_template('login.html')
        
        # перевірка хеша пароля
        if not check_password_hash(user.password_hash, password):

            increment_failed_attempts(user)
            log_login_attempt(username, 'failed', 'wrong_password')
            
            remaining_attempts = MAX_LOGIN_ATTEMPTS - user.failed_login_attempts
            if remaining_attempts > 0:
                flash(f'Невірний пароль. Залишилось спроб: {remaining_attempts}', 'danger')
            
            return render_template('login.html')

        if user.two_fa_enabled:
            if not two_fa_code:

                return render_template('login_2fa.html', username=username, password=password)

            if not verify_2fa_code(user.two_fa_secret, two_fa_code):
                log_login_attempt(username, 'failed', '2fa_code_invalid')
                flash('Невірний код двофакторної аутентифікації', 'danger')
                return render_template('login_2fa.html', username=username, password=password)

        reset_failed_attempts(user)
        log_login_attempt(username, 'success')
        
        session['user_id'] = user.id
        session['username'] = user.username
        flash(f'Вітаємо, {user.username}!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Спочатку увійдіть в систему', 'warning')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user)

@app.route('/2fa/setup')
def setup_2fa():
    """Сторінка налаштування 2FA"""
    if 'user_id' not in session:
        flash('Спочатку увійдіть в систему', 'warning')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        flash('Сесія застаріла. Будь ласка, увійдіть знову', 'warning')
        return redirect(url_for('login'))
    
    # Якщо 2FA вже увімкнено
    if user.two_fa_enabled:
        flash('Двофакторна аутентифікація вже увімкнена', 'info')
        return redirect(url_for('dashboard'))
    
    # Генерувати новий секрет
    secret = generate_2fa_secret()
    session['temp_2fa_secret'] = secret
    
    # Генерувати QR-код
    uri = get_2fa_uri(user.username, secret)
    qr_code = generate_qr_code(uri)
    
    return render_template('setup_2fa.html', qr_code=qr_code, secret=secret)

@app.route('/2fa/enable', methods=['POST'])
def enable_2fa():
    """Увімкнути 2FA після підтвердження"""
    if 'user_id' not in session:
        flash('Спочатку увійдіть в систему', 'warning')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        flash('Сесія застаріла. Будь ласка, увійдіть знову', 'warning')
        return redirect(url_for('login'))
    
    verification_code = request.form.get('verification_code')
    temp_secret = session.get('temp_2fa_secret')
    
    if not temp_secret:
        flash('Секретний ключ не знайдено. Спробуйте ще раз', 'danger')
        return redirect(url_for('setup_2fa'))
    
    # перевірити код
    if verify_2fa_code(temp_secret, verification_code):
        user.two_fa_secret = temp_secret
        user.two_fa_enabled = True
        db.session.commit()
        
        session.pop('temp_2fa_secret', None)
        flash('Двофакторна аутентифікація успішно увімкнена!', 'success')
        return redirect(url_for('dashboard'))
    else:
        flash('Невірний код підтвердження. Спробуйте ще раз', 'danger')
        return redirect(url_for('setup_2fa'))

@app.route('/2fa/disable', methods=['POST'])
def disable_2fa():
    """Вимкнути 2FA"""
    if 'user_id' not in session:
        flash('Спочатку увійдіть в систему', 'warning')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        flash('Сесія застаріла. Будь ласка, увійдіть знову', 'warning')
        return redirect(url_for('login'))
    
    user.two_fa_enabled = False
    user.two_fa_secret = None
    db.session.commit()
    
    flash('Двофакторна аутентифікація вимкнена', 'info')
    return redirect(url_for('dashboard'))


@app.route('/auth/github')
def github_login():
    """Перенаправлення на GitHub для авторизації"""
    github_client_id = app.config['GITHUB_CLIENT_ID']
    redirect_uri = url_for('github_callback', _external=True)

    state = serializer.dumps({'redirect': 'github_auth'})
    session['oauth_state'] = state
    
    github_auth_url = (
        f"{app.config['GITHUB_AUTHORIZE_URL']}"
        f"?client_id={github_client_id}"
        f"&redirect_uri={redirect_uri}"
        f"&scope=user:email"
        f"&state={state}"
    )
    
    return redirect(github_auth_url)

@app.route('/auth/github/callback')
def github_callback():
    """Callback після авторизації GitHub"""

    state = request.args.get('state')
    if state != session.get('oauth_state'):
        flash('Помилка авторизації: невірний state', 'danger')
        return redirect(url_for('login'))

    code = request.args.get('code')
    if not code:
        flash('Помилка авторизації GitHub', 'danger')
        return redirect(url_for('login'))

    token_data = {
        'client_id': app.config['GITHUB_CLIENT_ID'],
        'client_secret': app.config['GITHUB_CLIENT_SECRET'],
        'code': code
    }
    
    token_response = requests.post(
        app.config['GITHUB_TOKEN_URL'],
        data=token_data,
        headers={'Accept': 'application/json'}
    )
    
    token_json = token_response.json()
    access_token = token_json.get('access_token')
    
    if not access_token:
        flash('Не вдалося отримати токен доступу від GitHub', 'danger')
        return redirect(url_for('login'))

    headers = {
        'Authorization': f'token {access_token}',
        'Accept': 'application/json'
    }
    
    user_response = requests.get(
        f"{app.config['GITHUB_API_BASE_URL']}user",
        headers=headers
    )
    
    user_data = user_response.json()

    email_response = requests.get(
        f"{app.config['GITHUB_API_BASE_URL']}user/emails",
        headers=headers
    )
    
    emails = email_response.json()
    primary_email = next((email['email'] for email in emails if email['primary']), None)
    
    if not primary_email:
        primary_email = user_data.get('email')
    
    github_id = str(user_data.get('id'))
    username = user_data.get('login')

    user = User.query.filter_by(github_id=github_id).first()
    
    if not user:
    
        existing_user = User.query.filter_by(email=primary_email).first()
        if existing_user:
            flash('Користувач з такою email адресою вже існує', 'warning')
            return redirect(url_for('login'))

        user = User(
            username=username,
            email=primary_email,
            github_id=github_id,
            oauth_provider='github',
            is_active=True,
            password_hash=None 
        )
        db.session.add(user)
        db.session.commit()
        
        flash(f'Акаунт створено через GitHub! Вітаємо, {username}!', 'success')
    else:
        flash(f'Вітаємо, {user.username}!', 'success')

    session['user_id'] = user.id
    session['username'] = user.username
    session.pop('oauth_state', None)
    
    log_login_attempt(user.username, 'success', 'oauth_github')
    
    return redirect(url_for('dashboard'))


@app.route('/admin/logs')
def admin_logs():
    """Сторінка перегляду логів входу (тільки для адміністратора)"""
    if 'user_id' not in session:
        flash('Спочатку увійдіть в систему', 'warning')
        return redirect(url_for('login'))

    logs = LoginLog.query.order_by(LoginLog.timestamp.desc()).limit(100).all()
    
    return render_template('admin_logs.html', logs=logs)

@app.route('/logout')
def logout():
    session.clear()
    flash('Ви успішно вийшли з системи', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)