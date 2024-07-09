from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import uuid

#postgresql://hngtaskdb_user:tVCgst69Orv1m5ihkU9MxSCoQIrQAK5e@dpg-cq4ge6g8fa8c73fp18u0-a.oregon-postgres.render.com/hngtaskdb
app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://hngtaskdb_user:tVCgst69Orv1m5ihkU9MxSCoQIrQAK5e@dpg-cq4ge6g8fa8c73fp18u0-a.oregon-postgres.render.com/hngtaskdb'

app.config['JWT_SECRET_KEY'] = 'hfkjoqieawoepidfeurghjdcdx'

db = SQLAlchemy(app)
ma = Marshmallow(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

class User(db.Model):
    user_id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()), unique=True)
    first_name = db.Column(db.String(30), nullable=False)
    last_name = db.Column(db.String(30), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(15))

class Organisation(db.Model):
    org_id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()), unique=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    users = db.relationship('User', secondary='organisation_users', backref='organisations')

organisation_users = db.Table('organisation_users',
    db.Column('user_id', db.String(36), db.ForeignKey('user.user_id'), primary_key=True),
    db.Column('org_id', db.String(36), db.ForeignKey('organisation.org_id'), primary_key=True)
)

class UserSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = User
        load_instance = True

class OrganisationSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Organisation
        load_instance = True

user_schema = UserSchema()
users_schema = UserSchema(many=True)
organisation_schema = OrganisationSchema()
organisations_schema = OrganisationSchema(many=True)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data:
        return jsonify({'status': 'Bad request', 'error': 'No input data provided', 'statusCode': 422}), 422

    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')
    password = data.get('password')
    phone = data.get('phone')

    if not first_name or not last_name or not email or not password:
        return jsonify({'status': 'Bad request', 'error': 'Missing required fields', 'statusCode': 422}), 422

    if User.query.filter_by(email=email).first():
        return jsonify({'status': 'Bad request', 'message': 'Registration unsuccessful', 'statusCode': 400}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(first_name=first_name, last_name=last_name, email=email, password=hashed_password, phone=phone)
    db.session.add(new_user)
    db.session.commit()

    org_name = f"{first_name}'s Organisation"
    new_organisation = Organisation(name=org_name)
    new_organisation.users.append(new_user)
    db.session.add(new_organisation)
    db.session.commit()

    access_token = create_access_token(identity=new_user.user_id)
    return jsonify({
        'status': 'success',
        'message': 'Registration successful',
        'data': {
            'accessToken': access_token,
            'user': user_schema.dump(new_user)
        }
    }), 201

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({'status': 'Bad request', 'message': 'Authentication failed', 'statusCode': 401}), 401

    access_token = create_access_token(identity=user.user_id)
    return jsonify({
        'status': 'success',
        'message': 'Login successful',
        'data': {
            'accessToken': access_token,
            'user': user_schema.dump(user)
        }
    }), 201

@app.route('/api/users/<user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    current_user_id = get_jwt_identity()
    user = User.query.filter_by(user_id=user_id).first()
    if not user or (user.user_id != current_user_id and not Organisation.query.filter(Organisation.users.any(user_id=current_user_id)).first()):
        return jsonify({'status': 'Forbidden', 'message': 'Access denied', 'statusCode': 403}), 403

    return jsonify({
        'status': 'success',
        'message': 'User found',
        'data': user_schema.dump(user)
    }), 200

@app.route('/api/organisations', methods=['GET'])
@jwt_required()
def get_organisations():
    current_user_id = get_jwt_identity()
    organisations = Organisation.query.filter(Organisation.users.any(user_id=current_user_id)).all()
    return jsonify({
        'status': 'success',
        'message': 'Organisations retrieved',
        'data': organisations_schema.dump(organisations)
    }), 200

@app.route('/api/organisations/<org_id>', methods=['GET'])
@jwt_required()
def get_organisation(org_id):
    current_user_id = get_jwt_identity()
    organisation = Organisation.query.filter_by(org_id=org_id).filter(Organisation.users.any(user_id=current_user_id)).first()
    if not organisation:
        return jsonify({'status': 'Not found', 'message': 'Organisation not found', 'statusCode': 404}), 404

    return jsonify({
        'status': 'success',
        'message': 'Organisation found',
        'data': organisation_schema.dump(organisation)
    }), 200

@app.route('/api/organisations', methods=['POST'])
@jwt_required()
def create_organisation():
    data = request.get_json()
    if not data:
        return jsonify({'status': 'Bad request', 'message': 'No input data provided', 'statusCode': 400}), 400

    name = data.get('name')
    description = data.get('description')
    if not name:
        return jsonify({'status': 'Bad request', 'message': 'Name is required', 'statusCode': 400}), 400

    current_user_id = get_jwt_identity()
    new_organisation = Organisation(name=name, description=description)
    user = User.query.filter_by(user_id=current_user_id).first()
    new_organisation.users.append(user)
    db.session.add(new_organisation)
    db.session.commit()

    return jsonify({
        'status': 'success',
        'message': 'Organisation created successfully',
        'data': organisation_schema.dump(new_organisation)
    }), 201

@app.route('/api/organisations/<org_id>/users', methods=['POST'])
@jwt_required()
def add_user_to_organisation(org_id):
    data = request.get_json()
    user_id = data.get('user_id')

    current_user_id = get_jwt_identity()
    organisation = Organisation.query.filter_by(org_id=org_id).filter(Organisation.users.any(user_id=current_user_id)).first()
    if not organisation:
        return jsonify({'status': 'Not found', 'message': 'Organisation not found', 'statusCode': 404}), 404

    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        return jsonify({'status': 'Not found', 'message': 'User not found', 'statusCode': 404}), 404

    organisation.users.append(user)
    db.session.commit()

    return jsonify({
        'status': 'success',
        'message': 'User added to organisation successfully'
    }), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)