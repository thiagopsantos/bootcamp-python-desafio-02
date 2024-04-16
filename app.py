from flask import Flask, request, jsonify
import bcrypt
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from models.user import User
from models.meal import Meal
from database import db

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:admin123@127.0.0.1:3306/flask-meals'

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)

login_manager.login_view = 'login'

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']

    if username and password:
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.checkpw(str.encode(password), str.encode(user.password)):
            login_user(user)
            return jsonify({"message": "Autenticação realizada com sucesso"})
    return jsonify({"message": "Credenciais inválidas"}), 400

@app.route('/users', methods=['POST'])
def create_user():
    data = request.get_json()
    username = data['username']
    password = data['password']

    if username and password:
        user = User.query.filter_by(username=username).first()

        if not user:
            password_hased = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
            user = User(username=username, password=password_hased, role='user')
            db.session.add(user)
            db.session.commit()
            return jsonify({"message": "Usuário cadastrado com sucesso"}), 201
        return jsonify({"message": "Nome de usuário não disponível"}), 400
    return jsonify({"message": "Dados inválidos"}), 400

if __name__ == '__main__':
    app.run(debug=True)
