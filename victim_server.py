from flask import Flask, request, jsonify
from flask_restx import Api, Resource, fields
import sqlite3
import jwt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'vuln_secret_key' # Weak secret for JWT vulnerability
api = Api(app, version='1.0', title='Vulnerable Victim API',
          description='A sample API meant to be scanned by API Sentinel',
          doc='/swagger/')

ns = api.namespace('users', description='User operations')

# Simple vulnerable user model
user_model = api.model('User', {
    'id': fields.Integer(readOnly=True, description='The user unique identifier'),
    'username': fields.String(required=True, description='The user username'),
    'email': fields.String(required=True, description='The user email address'),
    'is_admin': fields.Boolean(description='Admin status - BOLA vulnerability')
})

# Setup a dummy DB
def init_db():
    conn = sqlite3.connect('victim.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, is_admin BOOLEAN)''')
    c.execute("INSERT OR IGNORE INTO users (id, username, email, is_admin) VALUES (1, 'admin', 'admin@example.com', 1)")
    c.execute("INSERT OR IGNORE INTO users (id, username, email, is_admin) VALUES (2, 'john', 'john@example.com', 0)")
    conn.commit()
    conn.close()

init_db()


@ns.route('/<int:id>')
@ns.response(404, 'User not found')
@ns.param('id', 'The user identifier')
class UserResource(Resource):
    
    @ns.doc('get_user')
    @ns.marshal_with(user_model)
    def get(self, id):
        '''Fetch a given resource (BOLA VULNERABLE - NO AUTH/AUTHORIZATION)'''
        # Vulnerable to BOLA - anyone can fetch any user ID
        conn = sqlite3.connect('victim.db')
        c = conn.cursor()
        c.execute("SELECT id, username, email, is_admin FROM users WHERE id=?", (id,))
        rv = c.fetchone()
        conn.close()
        
        if rv:
            return {'id': rv[0], 'username': rv[1], 'email': rv[2], 'is_admin': bool(rv[3])}
        api.abort(404, "User {} doesn't exist".format(id))


@ns.route('/search')
class UserSearch(Resource):
    
    @api.doc(params={'query': 'Search query'})
    def get(self):
        '''Search users (SQL INJECTION VULNERABLE)'''
        query_param = request.args.get('query', '')
        conn = sqlite3.connect('victim.db')
        c = conn.cursor()
        
        try:
            # Vulnerable to SQL Injection
            query = f"SELECT id, username FROM users WHERE username LIKE '%{query_param}%'"
            c.execute(query)
            results = [{'id': row[0], 'username': row[1]} for row in c.fetchall()]
            return results
        except sqlite3.Error as e:
            return {'error': str(e)}, 500
        finally:
            conn.close()

@ns.route('/login')
class UserLogin(Resource):
    @api.doc(params={'username': 'Username to login'})
    def post(self):
        '''Login to get JWT (WEAK SECRET AND NO EXPIRATION VULNERABLE)'''
        username = request.json.get('username') if request.json else request.args.get('username')
        if not username:
             return {'message': 'username required'}, 400
             
        # Create token with weak secret and no expiration
        token = jwt.encode({'username': username, 'is_admin': False}, app.config['SECRET_KEY'], algorithm='HS256')
        return {'token': token}

if __name__ == '__main__':
    app.run(debug=True, port=8001)
