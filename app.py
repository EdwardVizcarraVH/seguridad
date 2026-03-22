import re
import pyotp
import requests
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from functools import wraps
from models import db, User, AuditLog

app = Flask(__name__)


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///seguridad.db'
app.config['SECRET_KEY'] = 'umsa_informatica_ultra_secret'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


API_KEY = "871220fc4b1070bcb1572f73fb50d5d9d9735736c427ece46c485ac4bae9bd54"
BASE_URL = "https://api.thegamesdb.net/v1/"


db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def role_required(*roles):
    def wrapper(f):
        @wraps(f)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                log = AuditLog(user_id=current_user.id if current_user.is_authenticated else None, 
                               action="ACCESO DENEGADO (RBAC)", ip_address=request.remote_addr)
                db.session.add(log)
                db.session.commit()
                abort(403)
            return f(*args, **kwargs)
        return decorated_view
    return wrapper


@app.route('/')
def index():
    query = request.args.get('name')
    games_list = []
    base_img_url = "" 

    if query:
        url = f"{BASE_URL}Games/ByGameName?apikey={API_KEY}&name={query}&fields=description&include=boxart"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                games_list = data.get('data', {}).get('games', [])
                include = data.get('include', {})
                if 'boxart' in include:
                    
                    base_dict = include['boxart'].get('base_url', {})
                    base_img_url = base_dict.get('large', "") 
                    
                    boxarts = include['boxart'].get('data', {})
                    for game in games_list:
                        game_id = str(game.get('id'))
                        if game_id in boxarts:
                            images = boxarts[game_id]
                            front_img = next((img.get('filename') for img in images if img.get('side') == 'front'), None)
                            game['image_path'] = front_img
        except Exception as e:
            print(f"Error API: {e}")
    
    return render_template('index.html', games=games_list, base_img=base_img_url)

@app.route('/checkout', methods=['POST'])
def checkout():
    if not current_user.is_authenticated:
        flash("🔒 Seguridad: Debes iniciar sesión para procesar tu compra.", "warning")
        return redirect(url_for('login'))
    
    nueva_accion = AuditLog(user_id=current_user.id, action="COMPRA REALIZADA", ip_address=request.remote_addr)
    db.session.add(nueva_accion)
    db.session.commit()
    flash("🎮 ¡Compra exitosa! Revisa tu panel.", "success")
    return redirect(url_for('dashboard'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        hashed_pw = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        otp_secret = pyotp.random_base32()
        new_user = User(username=request.form['username'], password_hash=hashed_pw, 
                        role=request.form['role'], otp_secret=otp_secret)
        db.session.add(new_user)
        db.session.commit()
        flash(f'Código MFA: {otp_secret}', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and bcrypt.check_password_hash(user.password_hash, request.form['password']):
            session['pre_2fa_user_id'] = user.id
            return redirect(url_for('verify_2fa'))
        flash('Error en credenciales', 'danger')
    return render_template('login.html')

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pre_2fa_user_id' not in session: return redirect(url_for('login'))
    user = User.query.get(session['pre_2fa_user_id'])
    if request.method == 'POST':
        if pyotp.TOTP(user.otp_secret).verify(request.form['token']):
            login_user(user)
            session.pop('pre_2fa_user_id')
            return redirect(url_for('dashboard'))
    return render_template('verify_2fa.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/admin')
@role_required('ADMIN')
def admin_panel():
    usuarios = User.query.all()
    return render_template('admin_dashboard.html', usuarios=usuarios)

@app.route('/auditoria')
@role_required('ADMIN', 'AUDITOR')
def auditoria():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template('auditoria_logs.html', logs=logs)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)