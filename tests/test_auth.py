import unittest
from app import app, db, User, Organisation
import json

class AuthTests(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def test_register_user_successfully(self):
        response = self.app.post('/auth/register', data=json.dumps({
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'john.doe@example.com',
            'password': 'password',
            'phone': '1234567890'
        }), content_type='application/json')

        self.assertEqual(response.status_code, 201)
        data = json.loads(response.data)
        self.assertIn('accessToken', data['data'])
        self.assertEqual(data['data']['user']['first_name'], 'John')

    def test_login_user_successfully(self):
        self.test_register_user_successfully()  # Register a user first

        response = self.app.post('/auth/login', data=json.dumps({
            'email': 'john.doe@example.com',
            'password': 'password'
        }), content_type='application/json')

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('accessToken', data['data'])

    def test_missing_required_fields(self):
        response = self.app.post('/auth/register', data=json.dumps({
            'first_name': '',
            'last_name': '',
            'email': '',
            'password': '',
            'phone': ''
        }), content_type='application/json')

        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertEqual(data['message'], 'Missing required fields')

    def test_duplicate_email(self):
        self.test_register_user_successfully()  # Register a user first

        response = self.app.post('/auth/register', data=json.dumps({
            'first_name': 'Jane',
            'last_name': 'Doe',
            'email': 'john.doe@example.com',
            'password': 'password',
            'phone': '0987654321'
        }), content_type='application/json')

        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertEqual(data['message'], 'Email already exists')

if __name__ == '__main__':
    unittest.main()