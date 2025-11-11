from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
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

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<User {self.username}>'

def validate_password(password):
    """
    Перевіряє пароль на відповідність політиці безпеки:
    - Мінімум 8 символів
    - Містить великі та малі літери
    - Містить цифру
    - Містить спеціальний символ
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
        
        flash('Реєстрація успішна! Тепер ви можете увійти', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', site_key=app.config['RECAPTCHA_SITE_KEY'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        
        if not user:
            flash('Користувача не знайдено. Будь ласка, зареєструйтесь', 'warning')
            return redirect(url_for('register'))

        if check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash(f'Вітаємо, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Невірний пароль', 'danger')
            return render_template('login.html')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Спочатку увійдіть в систему', 'warning')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user)

@app.route('/logout')
def logout():
    session.clear()
    flash('Ви успішно вийшли з системи', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)