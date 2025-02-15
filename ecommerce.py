from flask import Flask, render_template, url_for, request, redirect, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length

# Initialize Flask App
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ecommerce.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'  # Dynamically Generated Secret Key
app.config['DEBUG'] = True

db = SQLAlchemy(app)

# -------------------- Models --------------------
# User Model for Authentication
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)  # Added name field
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Hashed password


# -------------------- Forms --------------------
class RegistrationForm(FlaskForm):
    name = StringField("Full Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo('password', message="Passwords must match.")])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# -------------------- Routes --------------------
@app.route("/")
@app.route("/home")
def home_page():
    return render_template("index.html")

# --------- Register Page ---------
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash("Email already registered. Please log in.", "danger")
            return redirect(url_for('login_page'))

        # hashed_password = generate_password_hash(form.password.data)  # Hash password
        user = User(name=form.name.data, email=form.email.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login_page"))
    
    return render_template('register.html', form=form)


# --------- User Profile Page ---------
@app.route("/user")
def user_page():
    if 'user_id' not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for('login_page'))
    
    user = User.query.get(session['user_id'])
    return render_template("user.html", user=user)

# --------- Login Page ---------
@app.route("/login", methods=['GET', 'POST'])
def login_page():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user and user.password == password:  # Corrected password check
            session['user_id'] = user.id
            session.permanent = True  # Keep user logged in
            flash("Login successful!", "success")
            return redirect(url_for('home_page'))
        else:
            flash("Invalid email or password.", "danger")

    return render_template("login.html", form=form)



# --------- Logout Route ---------
@app.route("/logout")
def logout():
    session.pop('user_id', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('login_page'))


# -------------------- Run App --------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Ensure database tables are created
    app.run()