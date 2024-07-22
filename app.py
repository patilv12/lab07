from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import re

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key'  # Required for flashing messages
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(150), nullable=False)
    lastname = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')
    user = User.query.filter_by(email=email).first()
    if user:
        if check_password_hash(user.password, password):
            return redirect(url_for('secret'))
        else:
            flash('Invalid credentials')
    else:
        flash('Email does not exist. Please register first.')
    return redirect(url_for('home'))

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email')
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        flash('Email address already exists')
        return redirect(url_for('signup'))
    
    firstname = request.form.get('firstname')
    lastname = request.form.get('lastname')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    
    # Check password strength
    if not re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_]).{8,}$', password):
        flash('Password must contain at least one special character, one capital letter, one small letter, and one number.')
        return redirect(url_for('signup'))

    if password != confirm_password:
        flash('Passwords do not match')
        return redirect(url_for('signup'))
    
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(firstname=firstname, lastname=lastname, email=email, password=hashed_password)
    
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
