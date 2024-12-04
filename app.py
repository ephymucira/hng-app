from flask import Flask, request, jsonify, render_template
import uuid
import bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from supabase import create_client

app = Flask(__name__)

# Supabase configuration
supabase_url = 'https://your-project-id.supabase.co'
supabase_key = ''

supabase = create_client(supabase_url, supabase_key)

# Flask app configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'  # Replace with your actual database URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key_here'

db = SQLAlchemy(app)
ma = Marshmallow(app)
jwt = JWTManager(app)

# Models and Schemas
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    first_name = db.Column(db.String(30), nullable=False)
    last_name = db.Column(db.String(30), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(15))

    organisations = db.relationship('Organisation', secondary='organisation_users', backref='users')

class Organisation(db.Model):
    __tablename__ = 'organisation'
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)

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

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data:
        return jsonify({'status': 'Bad request', 'error': 'No input data provided', 'statusCode': 422})

    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')
    password = data.get('password')
    phone = data.get('phone')

    if not first_name or not last_name or not email or not password:
        return jsonify({'status': 'Bad request', 'error': 'Missing required fields', 'statusCode': 422})

    # Check if the user already exists
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'status': 'Bad request', 'message': 'Registration unsuccessful', 'statusCode': 400})

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Create new user
    new_user = User(first_name=first_name, last_name=last_name, email=email, password=hashed_password, phone=phone)
    db.session.add(new_user)
    db.session.commit()

    # Create an organisation for the user
    org_name = f"{first_name}'s Organisation"
    new_organisation = Organisation(name=org_name)
    new_organisation.users.append(new_user)
    db.session.add(new_organisation)
    db.session.commit()

    # Generate access token
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

    # Retrieve user from database
    user = User.query.filter_by(email=email).first()
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        return jsonify({'status': 'Bad request', 'message': 'Authentication failed', 'statusCode': 401})

    # Generate access token
    access_token = create_access_token(identity=user.user_id)
    
    return jsonify({
        'status': 'success',
        'message': 'Login successful',
        'data': {
            'accessToken': access_token,
            'user': user_schema.dump(user)
        }
    }), 200

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
