import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_dance.contrib.google import make_google_blueprint, google
from datetime import datetime
from sqlalchemy.orm import relationship

app = Flask(__name__)
app.secret_key = 'super-secret-key'

# Force SQLite DB in Render instance folder
os.makedirs(app.instance_path, exist_ok=True)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'tasks.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Google OAuth config
import os

google_bp = make_google_blueprint(
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    redirect_url="https://todol-3l9l.onrender.com/login/google/authorized",
    redirect_to="google_login"
)



# ---------- MODELS ----------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(200))
    google_email = db.Column(db.String(100), unique=True)
    tasks = db.relationship('Task', backref='user', lazy=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    due = db.Column(db.String(100))
    category = db.Column(db.String(50))
    complete = db.Column(db.Boolean, default=False)
    created = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

@app.context_processor
def inject_datetime():
    return {'datetime': datetime}


# ---------- ROUTES ----------
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    tasks = Task.query.filter_by(user_id=session['user_id']).all()
    sort_by = request.args.get('sort')
    if sort_by == 'due':
        tasks.sort(key=lambda t: t.due or "")
    elif sort_by == 'complete':
        tasks.sort(key=lambda t: t.complete)
    elif sort_by == 'created':
        tasks.sort(key=lambda t: t.created)
    return render_template('index.html', tasks=tasks, sort_by=sort_by)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists')
        else:
            new_user = User(username=username, password_hash=hashed_pw)
            db.session.add(new_user)
            db.session.commit()
            flash('Registered! Please log in.')
            return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            return redirect(url_for('index'))
        flash('Invalid login credentials')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.')
    return redirect(url_for('login'))


@app.route('/login/google/authorized')
def google_login():
    if not google.authorized:
        return redirect(url_for("google.login"))
    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash("Google login failed")
        return redirect(url_for('login'))

    info = resp.json()
    email = info["email"]
    user = User.query.filter_by(google_email=email).first()
    if not user:
        user = User(google_email=email, username=email)
        db.session.add(user)
        db.session.commit()
    session['user_id'] = user.id
    return redirect(url_for('index'))


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
        return redirect(url_for('index'))
    task.complete = not task.complete
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/delete/<int:id>', methods=['POST'])
def delete_task(id):
    task = Task.query.get_or_404(id)
    if task.user_id != session.get('user_id'):
        return redirect(url_for('index'))
    db.session.delete(task)
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit_task(id):
    task = Task.query.get_or_404(id)
    if task.user_id != session.get('user_id'):
        return redirect(url_for('index'))
    if request.method == 'POST':
        task.title = request.form['title']
        task.due = request.form.get('due_date')
        task.category = request.form.get('category')
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('edit_task.html', task=task)


# ---------- INIT DB ----------
with app.app_context():
    db.create_all()


# ---------- LOCAL SERVER ----------
if __name__ == '__main__':
    app.run(debug=True)
