from flask import Flask, request
app = Flask(__name__)

@app.route('/api/users', methods=['GET'])
def list_users():
    return []

@app.route('/api/users', methods=['POST'])
def create_user():
    return {}

@app.get('/api/products')
def list_products():
    return []

@app.route('/api/admin')
def admin():
    return {}
