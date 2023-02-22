from flask import Flask, render_template, redirect, url_for, request, flash
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email, EqualTo
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from random import randint
from datetime import date
import email_validator
import stripe
import smtplib
import os

API_KEY = "sk_test_51LueCAG0lu41k8edSvtV9F3hnErzPZkaUDdHVGfOhr9uLlttatzqaFlZzEVS45C3QQf48z2kvLSzYmtK1qiG7pyY002ORc0hPo"

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///menu.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

Bootstrap(app)

stripe.api_key = API_KEY
MY_EMAIL = os.environ.get("EMAIL")
PASSWORD = os.environ.get("EMAIL_PASS")

# Databases
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

    def get_reset_token(self, expires_seconds=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_seconds)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)


class Menu(db.Model):
    __tablename__ = "menu"
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(100), nullable=False)
    food_name = db.Column(db.String(100), nullable=False)
    food_image = db.Column(db.String(100), nullable=False)
    food_price = db.Column(db.String(100), nullable=False)
    food_description = db.Column(db.String(100), nullable=False)


#Forms
class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log In")


class ForgotForm(FlaskForm):
    email = StringField("Please enter your email address:", validators=[DataRequired(), Email()])
    submit = SubmitField("Send Email")


class ResetForm(FlaskForm):
    password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField("Reset Password")


db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
def home():
    return render_template("index.html", current_user=current_user)


@app.route("/menu/<category>", methods=["GET", "POST"])
def menu(category):
    requested_menu = Menu.query.filter_by(type=category).all()
    return render_template("menu.html", menu=requested_menu, type=category, current_user=current_user)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = request.form['email']
        password = generate_password_hash(request.form['password'], method="pbkdf2:sha256", salt_length=8)
        if User.query.filter_by(email=request.form.get('email')).first():
            flash("Email already exists. Login instead")
            return redirect(url_for('login'))
        new_user = User(email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('home'))
    return render_template("register.html", form=form, current_user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Email is not registered. Click Sign Up to register.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash("Wrong password. Please try again.")
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('home'))
    return render_template("login.html", form=form, current_user=current_user)


def send_reset_email(user):
    token = user.get_reset_token()
    with smtplib.SMTP("smtp.gmail.com", 587) as connection:
        connection.starttls()
        connection.login(user=MY_EMAIL, password=PASSWORD)
        connection.sendmail(from_addr=MY_EMAIL,
                            to_addrs=MY_EMAIL,
                            msg=f"Subject:Password Reset\n\n"
                                f"To reset your password, click on the following link:\n"
                                f"{url_for('reset_password', token=token, _external=True)}\n"
                                f"If you did not make this request then simply ignore this email.")


@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    form = ForgotForm()
    if form.validate_on_submit():
        email = request.form.get('email')

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("There is no account with that email. Please, register first.")
            return redirect(url_for('forgot'))
        else:
            send_reset_email(user)
            flash("An email has been sent. Follow the instructions to reset your password.", "info")
            return redirect(url_for("login"))
    return render_template("forgot.html", form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token.')
        return redirect(url_for('forgot'))
    form = ResetForm()
    if form.validate_on_submit():
        # password = generate_password_hash(request.form['password'], method="pbkdf2:sha256", salt_length=8)
        user.password = generate_password_hash(request.form['password'], method="pbkdf2:sha256", salt_length=8)
        db.session.commit()
        flash("Your password has been updated, Please log in now.")
        return redirect(url_for('login'))
    return render_template("password-reset.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/order', methods=['GET', 'POST'])
def order():
    breakfast = Menu.query.filter_by(type="Breakfast").all()
    short_orders = Menu.query.filter_by(type="Short Orders").all()
    desserts = Menu.query.filter_by(type="Desserts").all()
    add_ons = Menu.query.filter_by(type="Add-ons").all()

    #If the user clicks submit:
    if request.method == "POST":
        food_list = [food.food_name for food in Menu.query.all()]
        total_price = 0
        selected_foods = []
        order_date = date.today()
        order_num = randint(1, 5000)
        for n in range(len(food_list)):
            requested_food = request.form.get(f"{food_list[n]}")

            quantity = request.form.get(f"{food_list[n]}_quantity")

            #This checks if the certain food's check box is checked.
            if requested_food:
                #The value is "food_price"-"food_name" this gets the price
                food = requested_food.split("-")[0]

                #This gets the food name.
                food_name = requested_food.split("-")[1]

                food_price = float(food) * float(quantity)

                single_food = f"• {quantity}pc/s - {food_name} --------------- ${food_price}"

                total_price += food_price

                selected_foods.append(single_food)

        return render_template("order.html", breakfast=breakfast, short_orders=short_orders, desserts=desserts,
                               add_ons=add_ons, total=total_price, foods=selected_foods, order_num=order_num, order_date=order_date)

    return render_template("order.html", breakfast=breakfast, short_orders=short_orders, desserts=desserts, add_ons=add_ons)


@app.route('/checkout/<float:amount>', methods=['GET', 'POST'])
def check_out(amount):
    final_amount = round(amount * 100)
    print(final_amount)
    products = {
        'name': "Food Ordered",
        'price': final_amount,
    }

    checkout_session = stripe.checkout.Session.create(
        line_items=[
            {
                "price_data": {
                    'product_data': {
                        'name': products['name'],
                    },
                    'unit_amount': products['price'],
                    'currency': "usd",
                },
                'quantity': 1,
            }
        ],
        payment_method_types=['card'],
        mode='payment',
        success_url=request.host_url + '/success',
        cancel_url=request.host_url + '/cancel',
    )
    return redirect(checkout_session.url)


@app.route('/success')
def success():
    return render_template('success.html')


@app.route('/cancel')
def cancel():
    return render_template('cancel.html')


if __name__ == '__main__':
    app.run(debug=True)