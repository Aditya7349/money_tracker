from flask import *
import uuid
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, or_
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
from flask_jwt_extended import create_access_token,get_jwt,get_jwt_identity, \
                               unset_jwt_cookies, jwt_required, JWTManager
from flask_session import Session
from flask_bcrypt import Bcrypt
from flask_cors import CORS, cross_origin

app = Flask(__name__)
bcrypt = Bcrypt(app)
CORS(app, supports_credentials=True)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydatabase.db'
app.config["JWT_SECRET_KEY"] = "please-remember-to-change-me-masdejdffadkj"
jwt = JWTManager(app)
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
db = SQLAlchemy(app)
Session(app)
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password = db.Column(db.String(128))


class Amount(db.Model):
    __tablename__ = 'amount'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120))
    amount = db.Column(db.String(120))

class samount(db.Model):
    __tablename__ = 'samount'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120))
    semail = db.Column(db.String(120))
    amount = db.Column(db.String(120))
    created_at = db.Column(db.DateTime, default = func.now())

    
    def to_dict(self):
        return {
            'id' : self.id,
            'email' : self.email,
            'semail' : self.semail,
            'amount' : self.amount,
            'created_at': self.created_at
        }


db.init_app(app)
with app.app_context():
    db.create_all()





@app.after_request
def refresh_expiring_jwts(response):
    try:
        exp_timestamp = get_jwt()["exp"]
        now = datetime.now(timezone.utc)
        target_timestamp = datetime.timestamp(now + timedelta(minutes=30))
        if target_timestamp > exp_timestamp:
            access_token = create_access_token(identity=get_jwt_identity())
            data = response.get_json()
            if type(data) is dict:
                data["access_token"] = access_token 
                response.data = json.dumps(data)
        return response
    except (RuntimeError, KeyError):
        # Case where there is not a valid JWT. Just return the original respone
        return response

@app.route('/token', methods=["POST"])
def create_token():
    email = request.json["email"]
    password = request.json["password"]
    user = User.query.filter_by(email=email).first()

    if user is None:
        return jsonify({"error": "Unauthorized"}), 401

    if not check_password_hash(user.password, password):
        return jsonify({"error": "Unauthorized"}), 401
    
    access_token = create_access_token(identity=email)
    response = {"access_token":access_token}
    return response



@app.route('/create-account', methods=["POST"])
def create_account():
    emai = request.json.get("email", None)
    passwor = request.json.get("password", None)
    if emai and passwor:
        user = User( email= emai, password = generate_password_hash(passwor))
        db.session.add(user)
        db.session.commit()
        return {"msg": "Create account succesfully"}, 200
    return {"msg": "Somthing error"}, 401



@app.route("/logout", methods=["POST"])
def logout():
    response = jsonify({"msg": "logout successful"})
    unset_jwt_cookies(response)
    return response

@app.route('/profile')
@jwt_required()
def my_profile():
    email = get_jwt_identity()
    user = User.query.filter_by(email=email).first()
    am = Amount.query.filter_by(email=email).first()
    amm = samount.query.filter(or_(samount.email == email, samount.semail == email)).all()
    print(amm[0])
    if am:
        amount = am.amount
    else:
        amount = '0'
    if amm:
        json_data = json.dumps([row.to_dict() for row in amm])
    else:
        json_data = None
    if json_data:
        json_dat = json_data
    else:
        json_dat = ''
    response_body = {
        "data" : {
            "name": email,
            "amount" : amount
        },
        "amount": {
            "data":  json_dat
        }

    }

    return response_body



    

@app.route('/add-amount', methods=["POST"])
@jwt_required()
def add_amount():
    emai = get_jwt_identity()
    print(emai)
    amoun = request.json.get("amount")
    print(amoun)
    if emai and amoun:
        am = Amount.query.filter_by(email=emai).first()
        if am != None:
            u_am = am.amount
            amountt = int(u_am) + int(amoun)
            userr = Amount.query.get(am.id)
            userr.amount = amountt
            db.session.commit() 
        else:
            user = Amount( email= emai, amount = amoun)
            db.session.add(user)
            db.session.commit()     
        return {"msg": "Add amount succesfully"}, 200
    return {"msg": "Somthing error"}, 401

@app.route('/add-credit', methods=["POST"])
@jwt_required()
def add_credit():
    print(request.headers)
    emaii = get_jwt_identity()
    emai = request.json.get("email")
    amoun = request.json.get("amount")
    print(emai)
    user_a = User.query.filter_by(email=emai).first()
    if user_a:
        return {"msg": "Account Not Found"}, 401

    if emai and amoun:
        am = Amount.query.filter_by(email=emai).first()
        if am != None:
            u_am = am.amount
            amountt = int(u_am) + int(amoun)
            userr = Amount.query.get(am.id)
            userr.amount = amountt
            db.session.commit()
        else:
            u = Amount(email = emai, amount = amoun)
            db.session.add(u)
            db.session.commit()
        amm = Amount.query.filter_by(email=emaii).first()
        u_amm = amm.amount
        amounttt = int(u_amm) - int(amoun)
        userrr = Amount.query.get(amm.id)
        userrr.amount = amounttt
        db.session.commit()
        user = samount( email= emaii, semail = emai,  amount = amoun)
        db.session.add(user)
        db.session.commit()
        return {"msg": "Money added succesfully"}, 200
    return {"msg": "Somthing error"}, 401




if "__name__" == "__main__":
    app.run()