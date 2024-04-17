from datetime import datetime
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

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username and password:
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.checkpw(str.encode(password), str.encode(user.password)):
            login_user(user)
            return jsonify({"message": "Autenticação realizada com sucesso"})
    return jsonify({"message": "Credenciais inválidas"}), 400

@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout realizado com sucesso"})

@app.route('/users', methods=['POST'])
def create_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

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

@app.route('/users/<int:user_id>', methods=['GET'])
@login_required
def get_user(user_id):
    if current_user.id == user_id or current_user.role == 'admin':
        user = User.query.get(user_id)
        if user:
            return {
                "id": user.id,
                "username": user.username
            }
        return jsonify({"message": "Usuário não encontrado "}), 404
    return jsonify({"message": "Operação não permitida"}), 403

@app.route('/users/<int:user_id>/meals', methods=['GET'])
@login_required
def get_meals(user_id):
    user = User.query.get(user_id)

    if user:
        if current_user.id == user.id or current_user.role == 'admin':
            return {
                "meals": [meal.to_dict() for meal in user.meals]
            }
        return  jsonify({"message": "Operação não autorizada"}), 403
    return jsonify({"message": "Usuário não encontrado"}), 404

@app.route('/meals', methods=['POST'])
@login_required
def create_meal():
    data = request.get_json()
    name = data.get("name")
    description = data.get("description")
    datetime_str = data.get("datetime")    
    in_the_diet = data.get("in_the_diet", False)

    if name and description and datetime_str:
        meal = Meal(name=name,
                    description=description,
                    datetime=datetime.strptime(datetime_str, "%Y-%m-%dT%H:%M:%S"),
                    in_the_diet=in_the_diet,
                    user=current_user)
        db.session.add(meal)
        db.session.commit()
        return jsonify({"message": "Refeição criada com sucesso"}), 201
    return jsonify({"message": "Dados inválidos"}), 400

@app.route('/meals/<int:meal_id>', methods=['GET'])
@login_required
def get_meal(meal_id):
    meal = Meal.query.get(meal_id)

    if meal:
        if current_user.id == meal.user.id or current_user.role == 'admin':
            return meal.to_dict()
        return  jsonify({"message": "Operação não autorizada"}), 403
    return jsonify({"message": "Refeição não encontrada"}), 404

@app.route('/meals/<int:meal_id>', methods=['PUT'])
@login_required
def update_meal(meal_id):
    data = request.get_json()
    name = data.get("name")
    description = data.get("description")
    datetime_str = data.get("datetime")
    in_the_diet = data.get("in_the_diet", False)
    meal = Meal.query.get(meal_id)

    if meal:
        if current_user.id == meal.user.id or current_user.role == 'admin':
            if name and description and datetime_str:
                meal.name = name
                meal.description = description
                meal.datetime = datetime.strptime(datetime_str, "%Y-%m-%dT%H:%M:%S")
                meal.in_the_diet = in_the_diet
                db.session.commit()
                return jsonify({"message": "Refeição atualizada com sucesso"})
            return jsonify({"message": "Dados inválidos"}), 400
        return  jsonify({"message": "Operação não autorizada"}), 403
    return jsonify({"message": "Refeição não encontrada"}), 404

@app.route('/meals/<int:meal_id>', methods=['DELETE'])
@login_required
def delete_meal(meal_id):    
    meal = Meal.query.get(meal_id)

    if meal:
        if current_user.id == meal.user.id or current_user.role == 'admin':
            db.session.delete(meal)
            db.session.commit()
            return jsonify({"message": f"Refeição {meal.id} foi removida com sucesso"})
        return  jsonify({"message": "Operação não autorizada"}), 403
    return jsonify({"message": "Refeição não encontrada"}), 404

if __name__ == '__main__':
    app.run(debug=True)
