from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime, timezone, timedelta
import re
import requests
import os
from dotenv import load_dotenv

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

db = SQLAlchemy(app)
mail = Mail(app)

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 15 

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

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
    """
    Перевіряє токен активації
    expiration в секундах (за замовчуванням 1 година)
    """
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        
        if not user:
            log_login_attempt(username, 'failed', 'user_not_found')
            flash('Користувача не знайдено. Будь ласка, зареєструйтесь', 'warning')
            return redirect(url_for('register'))

        is_locked, locked_until = is_user_locked(user)
        if is_locked:
            remaining_time = (locked_until - datetime.now(timezone.utc)).total_seconds() / 60
            log_login_attempt(username, 'blocked', 'account_locked')
            flash(f'Акаунт заблоковано. Спробуйте через {int(remaining_time)} хвилин', 'danger')
            return render_template('login.html')

        if not user.is_active:
            log_login_attempt(username, 'failed', 'not_activated')
            flash('Акаунт не активовано. Перевірте вашу пошту для активації', 'warning')
            return render_template('login.html')

        if check_password_hash(user.password_hash, password):
            reset_failed_attempts(user)
            log_login_attempt(username, 'success')
            
            session['user_id'] = user.id
            session['username'] = user.username
            flash(f'Вітаємо, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            increment_failed_attempts(user)
            log_login_attempt(username, 'failed', 'wrong_password')
            
            remaining_attempts = MAX_LOGIN_ATTEMPTS - user.failed_login_attempts
            if remaining_attempts > 0:
                flash(f'Невірний пароль. Залишилось спроб: {remaining_attempts}', 'danger')
            
            return render_template('login.html')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Спочатку увійдіть в систему', 'warning')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user)

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