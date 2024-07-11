from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_caching import Cache
from flask_profiler import Profiler
import uuid
import bcrypt
import redis
from celery import Celery

app = Flask(__name__)

# Database configuration
db_params = {
    'host': 'SG-hngdb-5711-pgsql-master.servers.mongodirector.com',
    'user': 'sgpostgres',
    'password': 'qcp3D9yPoH_9LCSd',
    'dbname': 'postgres',
    'port': 5432,
}
app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql+psycopg2://{db_params['user']}:{db_params['password']}@{db_params['host']}:{db_params['port']}/{db_params['dbname']}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,
    'max_overflow': 20,
    'pool_timeout': 30,
    'pool_recycle': 1800
}

# JWT configuration
app.config['JWT_SECRET_KEY'] = 'hfkjoqieawoepidfeurghjdcdx'

# Caching configuration
app.config['CACHE_TYPE'] = 'redis'
app.config['CACHE_REDIS_HOST'] = 'localhost'
app.config['CACHE_REDIS_PORT'] = 6379
app.config['CACHE_REDIS_DB'] = 0
app.config['CACHE_REDIS_URL'] = 'redis://localhost:6379/0'

# Celery configuration
app.config.update(
    CELERY_BROKER_URL='redis://localhost:6379/0',
    CELERY_RESULT_BACKEND='redis://localhost:6379/0'
)

db = SQLAlchemy(app)
ma = Marshmallow(app)
jwt = JWTManager(app)
cache = Cache(app)

# Flask-Profiler configuration
app.config["flask_profiler"] = {
    "enabled": app.config["DEBUG"],
    "storage": {
        "engine": "sqlite"
    },
    "basicAuth": {
        "enabled": True,
        "username": "admin",
        "password": "admin"
    },
    "ignore": [
        "^/static/.*"
    ]
}

profiler = Profiler(app)

def make_celery(app):
    celery = Celery(
        app.import_name,
        backend=app.config['CELERY_RESULT_BACKEND'],
        broker=app.config['CELERY_BROKER_URL']
    )
    celery.conf.update(app.config)
    TaskBase = celery.Task

    class ContextTask(TaskBase):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return TaskBase.__call__(self, *args, **kwargs)

    celery.Task = ContextTask
    return celery

celery = make_celery(app)

# Models and Schemas
class User(db.Model):
    __tablename__ = 'user'
    user_id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()), unique=True)
    first_name = db.Column(db.String(30), nullable=False)
    last_name = db.Column(db.String(30), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(15))

    organisations = db.relationship('Organisation', secondary=organisation_users, backref='users')

class Organisation(db.Model):
    __tablename__ = 'organisation'
    org_id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()), unique=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)

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
        return {'status': 'Bad request', 'error': 'No input data provided', 'statusCode': 422}

    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')
    password = data.get('password')
    phone = data.get('phone')

    if not first_name or not last_name or not email or not password:
        return jsonify({'status': 'Bad request', 'error': 'Missing required fields', 'statusCode': 422}), 422

    if User.query.filter_by(email=email).first():
        return jsonify({'status': 'Bad request', 'message': 'Registration unsuccessful', 'statusCode': 400}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
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
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
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
@cache.cached(timeout=60)
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
@cache.cached(timeout=60, key_prefix='organisation_{org_id}')
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
