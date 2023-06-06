from flask import Flask,render_template,redirect,url_for,get_flashed_messages,flash,request
from flask_bcrypt import Bcrypt
from flask_login import LoginManager,login_user,login_manager,UserMixin,logout_user,login_required,current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField
from wtforms.validators import Length,Email,EqualTo,DataRequired,ValidationError


app=Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"]='sqlite:///market.db'
app.config['SECRET_KEY']='bd92952105de0f3f12e7ec4f'
db=SQLAlchemy(app)
bcrypt=Bcrypt(app)
login_manager=LoginManager(app)
login_manager.login_view='login_page'
login_manager.login_message_category='info'
app.app_context().push()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin,db.Model):
    id=db.Column(db.Integer(),primary_key=True)
    username=db.Column(db.String(length=30),nullable=False,unique=True)
    email_address=db.Column(db.String(length=50),nullable=False,unique=True)
    password_hash=db.Column(db.String(length=60),nullable=False)
    budget=db.Column(db.Integer(),nullable=False,default=100000)
    items=db.relationship("Item",backref="owned_user",lazy=True)

    @property
    def password(self):
        return self.password
    
    @password.setter
    def password(self,plain_text_password):
        self.password_hash=bcrypt.generate_password_hash(plain_text_password).decode("utf-8")

    def check_password_correctness(self,attempted_password):
        return bcrypt.check_password_hash(self.password_hash,attempted_password)
    
    def can_buy(self,itm_obj):
        return self.budget >= itm_obj.price
    
    def can_sell(self,item_obj):
        return item_obj in self.items 

class Item(db.Model):
    id=db.Column(db.Integer(), primary_key=True)
    name=db.Column(db.String(length=50),nullable=False, unique=True)
    barcode=db.Column(db.String(length=12), nullable=False, unique=True)
    price=db.Column(db.Integer(), nullable=False)
    description=db.Column(db.String(length=250), nullable=False, unique=True)
    owner=db.Column(db.Integer(),db.ForeignKey("user.id"))

    def buy(self,user):
        self.owner=user.id
        user.budget-=self.price
        db.session.commit()

    def sell(self,user):
        self.owner=""
        user.budget+=self.price
        db.session.commit()    

    def __repr__(self):
        return '<Name %r>' % self.name
    
class RegisterForm(FlaskForm):
    def validate_username(self,username_to_check):
        user=User.query.filter_by(username=username_to_check.data).first()
        if user:
            raise ValidationError("user name alreay Exists. Please try a different username...")
    def validate_email(self,email_to_check):
        email=User.query.filter_by(email_address=email_to_check.data).first()
        if email:
            raise ValidationError("Email address already registered in this site...")
    username=StringField(label="User Name: ",validators=[Length(min=5,max=30),DataRequired()])
    email=StringField(label="Email Address:",validators=[Email(),DataRequired()])
    password1=PasswordField(label="Password: ",validators=[Length(min=5),DataRequired()])
    password2=PasswordField(label="Confirm Password:",validators=[EqualTo('password1'),DataRequired()])
    submit=SubmitField (label="Register")

class LoginForm(FlaskForm):
    username=StringField(label="User Name: ",validators=[DataRequired()])
    password=PasswordField(label="Password: ",validators=[DataRequired()])
    submit=SubmitField (label="Login")

class purchaseform(FlaskForm):
    submit=SubmitField(label="Purchase!")

class sellform(FlaskForm):
    submit=SubmitField(label="Sell!")



@app.route("/")
@app.route("/Home")
def home_page():
    return render_template("home.html")

@app.route("/Market",methods=["POST","GET"])
@login_required
def market_page():
    purchase_form=purchaseform()
    sell_form=sellform()
    if request.method=="POST":
        purchased_item=request.form.get("purchase_item")
        P_item_obj=Item.query.filter_by(name=purchased_item).first()
        if P_item_obj:
            if current_user.can_buy(P_item_obj):
                P_item_obj.buy(current_user)
                flash(f"You have successfully bought {P_item_obj.name} for {P_item_obj.price}", category="success")
                return redirect(url_for("market_page"))
            else:
                flash(f" Sorry, You have insufficient funds to buy")
        sell_item=request.form.get("sell_item")
        s_item_obj=Item.query.filter_by(name=sell_item).first()
        if s_item_obj:
            if current_user.can_sell(s_item_obj):
                s_item_obj.sell(current_user)
        return redirect(url_for("market_page"))
    if request.method=="GET":
        owned_items=Item.query.filter_by(owner=current_user.id)
        return render_template("market.html",item_details=Item.query.filter_by(owner=''), purchase_form=purchase_form,
                               owned_items=owned_items,sell_form=sell_form)

@app.route("/Register",methods=["POST","GET"])
def register_page():
    form=RegisterForm()
    if form.validate_on_submit():
        user_to_create=User(username=form.username.data,
                            email_address=form.email.data,
                            password=form.password1.data)
        db.session.add(user_to_create)
        db.session.commit()
        return redirect(url_for('market_page'))
    if form.errors !={}:
        for err_msg in form.errors.values():
            flash (f"This is an error while creating this user. The error is {err_msg}",category="danger")
    return render_template("register.html",form=form)

@app.route("/Login",methods=["POST","GET"])
def login_page():
    form=LoginForm()
    if form.validate_on_submit():
        attempted_user=User.query.filter_by(username=form.username.data).first()
        if attempted_user and attempted_user.check_password_correctness(attempted_password=form.password.data):
            login_user(attempted_user)
            flash(f"Loggedin successfully!!! You are loggedin as {attempted_user.username}",category="success")
            return redirect(url_for("market_page"))
        else:
            flash("Username and password not matched. Please try again", category="danger")
    return render_template("login.html",form=form)


@app.route("/Logout")
def logout_page():
    logout_user()
    flash("You have been loggedout successfully", category="info")
    return redirect(url_for("home_page"))






    



if __name__=="__main__":
    app.run(debug=True)