from flask import Flask,render_template, redirect, request, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, LoginManager, login_required, current_user,login_user, logout_user #to manage use session
from customClass import customClass

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ewuaeirhnew849329423048ldsfnsfh323247'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///oop_project.db'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# object of custom class
customClass = customClass()

@login_manager.user_loader
def load_user(user_id):
    # since the user_id is just the primary key of our user table, use it in the query for the user
    return User.query.get(int(user_id))
class User(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(100))
    latitude = db.Column(db.String(100),  nullable=True)
    longitude = db.Column(db.String(100),  nullable=True)
    ip_address = db.Column(db.String(100),  nullable=True)
    distance = db.Column(db.String(100),  nullable=True)
    ip_status = db.Column(db.Integer,  default=0)
    def __repr__(self):
        return '<User %r>' % self.username

@app.route('/', methods=['get'])
def index():
    return render_template('index.html')

@app.route('/profile', methods=['get'])
@login_required
def profile():
    return render_template('profile.html', name=current_user.username, ip_address=current_user.ip_address, latitude=current_user.latitude, longitude=current_user.longitude, distance=current_user.distance, ip_status=current_user.ip_status)

@app.route('/login', methods=['get'])
def login():
	return render_template('login.html')

@app.route('/signup', methods=['get'])
def signup():
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')
    latitude = request.form.get('latitude')
    longitude = request.form.get('longitude')
    ip_address = request.remote_addr

    user = User.query.filter_by(email=email).first() # if this returns a user, then the email already exists in database

    if user: # if a user is found, we want to redirect back to signup page so user can try again
        flash('Email address already exists')
        return redirect(url_for('signup'))

    # create a new user with the form data. Hash the password so the plaintext version isn't saved.
    new_user = User(email=email, username=name, password=generate_password_hash(password, method='sha256'), latitude=latitude, longitude=longitude, ip_address=ip_address)

    # add the new user to the database
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('login'))

@app.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    latitude = request.form.get('latitude')
    longitude = request.form.get('longitude')
    ip_address = request.remote_addr
    remember = True if request.form.get('remember') else False

    ip_status = 0
    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        return redirect(url_for('login')) # if the user doesn't exist or password is wrong, reload the page
    
    if user.ip_address != ip_address:
        ip_status = 1
    lat2 = float(user.latitude)
    long2 = float(user.longitude)
    distance_km = customClass.calculateDistance(float(latitude), float(longitude),lat2 , long2 )

    user.latitude = latitude
    user.longitude = longitude
    user.distance = distance_km
    user.ip_status = ip_status
    user.ip_address = ip_address
    db.session.commit()
    # if the above check passes, then we know the user has the right credentials
    login_user(user, remember=remember)
    return redirect(url_for('profile'))