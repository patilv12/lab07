from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import re

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'another_secret_key'  # Required for flash messages
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']
    user = User.query.filter_by(email=email).first()
    if user:
        if check_password_hash(user.password, password):
            return redirect(url_for('secret'))
        else:
            flash('Invalid credentials.')
    else:
        flash('Email not found. Please register.')
    return redirect(url_for('index'))

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/signup', methods=['POST'])
def signup_post():
    email = request.form['email']
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        flash('This email is already registered.')
        return redirect(url_for('signup'))
    
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    password = request.form['password']
    confirm_password = request.form['confirm_password']
    
    if not re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_]).{8,}$', password):
        flash('Password must have at least one special character, one uppercase letter, one lowercase letter, and one number.')
        return redirect(url_for('signup'))

    if password != confirm_password:
        flash('Passwords do not match.')
        return redirect(url_for('signup'))
    
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(first_name=first_name, last_name=last_name, email=email, password=hashed_password)
    
    db.session.add(new_user)
    db.session.commit()
    
    return redirect(url_for('thankyou'))

@app.route('/secret')
def secret():
    return render_template('secretPage.html')

@app.route('/thankyou')
def thankyou():
    return render_template('thankyou.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
