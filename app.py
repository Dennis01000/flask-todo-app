import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_dance.contrib.google import make_google_blueprint, google
from dotenv import load_dotenv
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

# Load environment variables
load_dotenv()

# Flask setup
app = Flask(__name__, instance_relative_config=True, static_folder='static', template_folder='templates')
secret = os.getenv("FLASK_SECRET_KEY")
if not secret:
    raise RuntimeError("FLASK_SECRET_KEY not set in .env")

app.secret_key = secret
app.config['SESSION_COOKIE_SECURE'] = True

# Mail config
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

mail = Mail(app)

# Token serializer
serializer = URLSafeTimedSerializer(app.secret_key)

# Ensure instance folder exists
os.makedirs(app.instance_path, exist_ok=True)

# SQLite setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'tasks.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200))
    tasks = db.relationship('Task', backref='user', lazy=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    due = db.Column(db.String(100))
    category = db.Column(db.String(50))
    complete = db.Column(db.Boolean, default=False)
    created = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

# Google OAuth
google_bp = make_google_blueprint(
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    redirect_url="/login/google/authorized",
    redirect_to="google_login",
    scope=["profile", "email"]
)
app.register_blueprint(google_bp, url_prefix="/login")

# Context processor
@app.context_processor
def inject_datetime():
    return {'datetime': datetime}

# Routes
@app.route('/')
def index():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    current_user_email = user.username  # Works for both email or normal username

    sort_by = request.args.get('sort')
    tasks = Task.query.filter_by(user_id=user_id)

    if sort_by == 'due':
        tasks = tasks.order_by(Task.due)
    elif sort_by == 'complete':
        tasks = tasks.order_by(Task.complete)
    elif sort_by == 'created':
        tasks = tasks.order_by(Task.created)

    return render_template('index.html', tasks=tasks.all(), sort_by=sort_by, current_user_email=current_user_email)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(username=email).first()
        if user:
            token = serializer.dumps(email, salt='password-reset-salt')
            reset_url = url_for('reset_password_token', token=token, _external=True)
            msg = Message("Password Reset", sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f"Click to reset your password: {reset_url}"
            mail.send(msg)
            flash("Password reset link sent to your email.")
            return redirect(url_for('login'))
        flash("No account found with that email.")
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except Exception as e:
        flash("Invalid or expired token.")
        return redirect(url_for('login'))

    user = User.query.filter_by(username=email).first()
    if not user:
        flash("No user found.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        user.password = generate_password_hash(new_password)
        db.session.commit()
        flash("Password reset successful.")
        return redirect(url_for('login'))

    return render_template('reset_password_token.html', email=email)


@app.route('/add', methods=['POST'])
def add_task():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    title = request.form['title']
    due = request.form.get('due_date')
    category = request.form.get('category')
    new_task = Task(title=title, due=due, category=category, user_id=session['user_id'])
    db.session.add(new_task)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/toggle/<int:id>', methods=['POST'])
def toggle_complete(id):
    task = Task.query.get_or_404(id)
    if task.user_id != session.get('user_id'):
        return "Unauthorized", 403
    task.complete = not task.complete
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/delete/<int:id>', methods=['POST'])
def delete_task(id):
    task = Task.query.get_or_404(id)
    if task.user_id != session.get('user_id'):
        return "Unauthorized", 403
    db.session.delete(task)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit_task(id):
    task = Task.query.get_or_404(id)
    if task.user_id != session.get('user_id'):
        return "Unauthorized", 403
    if request.method == 'POST':
        task.title = request.form['title']
        task.due = request.form.get('due_date')
        task.category = request.form.get('category')
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('edit_task.html', task=task)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.password and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('index'))
        flash("Invalid username or password.")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        if User.query.filter_by(username=username).first():
            flash("Username already exists.")
            return redirect(url_for('register'))
        user = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()
        flash("Account created. Please login.")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/login/google/authorized')
def google_login():
    try:
        if not google.authorized:
            flash("Google sign-in failed.")
            return redirect(url_for('login'))

        # Make request to Google for user info
        resp = google.get("/oauth2/v2/userinfo")
        if not resp.ok:
            print("❌ Google response error:", resp.text)
            flash("Failed to get user info from Google.")
            return redirect(url_for('login'))

        info = resp.json()
        print("✅ Google user info received:", info)

        email = info.get("email")
        if not email:
            flash("Email not returned from Google.")
            return redirect(url_for('login'))

        # Check if user exists or create one
        user = User.query.filter_by(username=email).first()
        if not user:
            user = User(username=email, password=None)
            db.session.add(user)
            db.session.commit()
            print("👤 Created new user:", email)

        session['user_id'] = user.id
        print("✅ Logged in, user_id set to:", user.id)

        return redirect(url_for('index'))

    except Exception as e:
        import traceback
        traceback.print_exc()  # 🔥 Print full error to logs
        return f"Internal Server Error: {str(e)}"



# Init DB
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
