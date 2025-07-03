import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_dance.contrib.google import make_google_blueprint, google
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__, instance_relative_config=True)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "supersecretkey")

# Ensure instance folder exists
os.makedirs(app.instance_path, exist_ok=True)

# Configure SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'tasks.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ==================== MODELS ====================

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

# ==================== GOOGLE AUTH ====================


google_bp = make_google_blueprint(
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    redirect_url="/login/google/authorized",
    redirect_to="google_login"
)
app.register_blueprint(google_bp, url_prefix="/login")


# ==================== CONTEXT ====================
@app.context_processor
def inject_datetime():
    return {'datetime': datetime}

# ==================== ROUTES ====================

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    sort_by = request.args.get('sort')
    tasks = Task.query.filter_by(user_id=session['user_id'])

    if sort_by == 'due':
        tasks = tasks.order_by(Task.due)
    elif sort_by == 'complete':
        tasks = tasks.order_by(Task.complete)
    elif sort_by == 'created':
        tasks = tasks.order_by(Task.created)

    return render_template('index.html', tasks=tasks.all(), sort_by=sort_by)

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
        if user and check_password_hash(user.password, password):
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

# ==================== GOOGLE LOGIN HANDLER ====================

@app.route('/login/google/authorized')
def google_login():
    if not google.authorized:
        flash("Google sign-in failed.")
        return redirect(url_for('login'))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash("Failed to fetch user info from Google.")
        return redirect(url_for('login'))

    info = resp.json()
    username = info["email"]
    user = User.query.filter_by(username=username).first()
    if not user:
        user = User(username=username, password="")  # No password, Google only
        db.session.add(user)
        db.session.commit()
    session['user_id'] = user.id
    return redirect(url_for('index'))

# ==================== INIT DB ====================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("✅ Database tables created.")
    app.run(debug=True)
