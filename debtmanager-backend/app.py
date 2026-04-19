from flask import Flask, jsonify, request
from flask_cors import CORS
import psycopg2
import psycopg2.extras
import os
import hashlib
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'happywise-secret-key-2024')
CORS(app, supports_credentials=True)

def get_db():
    return psycopg2.connect(
        host=os.environ.get('POSTGRES_HOST'),
        database=os.environ.get('POSTGRES_DB'),
        user=os.environ.get('POSTGRES_USER'),
        password=os.environ.get('POSTGRES_PASSWORD')
    )

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS staff (
            id SERIAL PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            username VARCHAR(50) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            role VARCHAR(20) DEFAULT 'cashier',
            active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS customers (
            id SERIAL PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            phone VARCHAR(20),
            email VARCHAR(100),
            created_at TIMESTAMP DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS debts (
            id SERIAL PRIMARY KEY,
            customer_id INTEGER REFERENCES customers(id),
            description VARCHAR(255),
            total_amount DECIMAL(10,2) NOT NULL,
            amount_paid DECIMAL(10,2) DEFAULT 0,
            due_date DATE,
            status VARCHAR(20) DEFAULT 'unpaid',
            created_by INTEGER REFERENCES staff(id),
            created_at TIMESTAMP DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS payments (
            id SERIAL PRIMARY KEY,
            debt_id INTEGER REFERENCES debts(id),
            amount DECIMAL(10,2) NOT NULL,
            note VARCHAR(255),
            recorded_by INTEGER REFERENCES staff(id),
            paid_at TIMESTAMP DEFAULT NOW()
        );
    ''')
    # Create default owner account if not exists
    cur.execute("SELECT id FROM staff WHERE username = 'owner'")
    if not cur.fetchone():
        cur.execute(
            "INSERT INTO staff (name, username, password, role) VALUES (%s, %s, %s, %s)",
            ('Shop Owner', 'owner', hash_password('happywise2024'), 'owner')
        )
    conn.commit()
    cur.close()
    conn.close()

def require_auth(roles=None):
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        return None
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM staff WHERE password = %s AND active = TRUE", (token,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    if not user:
        return None
    if roles and user['role'] not in roles:
        return None
    return dict(user)

# ── Health ──
@app.route('/health')
def health():
    return jsonify({"status": "healthy", "message": "Happywise Ent API running"})

# ── Auth ──
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "SELECT * FROM staff WHERE username = %s AND password = %s AND active = TRUE",
        (data['username'], hash_password(data['password']))
    )
    user = cur.fetchone()
    cur.close()
    conn.close()
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401
    return jsonify({
        "token": user['password'],
        "user": {
            "id": user['id'],
            "name": user['name'],
            "username": user['username'],
            "role": user['role']
        }
    })

@app.route('/me', methods=['GET'])
def me():
    user = require_auth()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(user)

# ── Staff ──
@app.route('/staff', methods=['GET'])
def get_staff():
    user = require_auth(roles=['owner'])
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id, name, username, role, active, created_at FROM staff ORDER BY created_at DESC")
    staff = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify([dict(s) for s in staff])

@app.route('/staff', methods=['POST'])
def add_staff():
    user = require_auth(roles=['owner'])
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    name = data['name']
    username = data['username']
    password = hash_password(data['password'])
    role = data['role']
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(
            "INSERT INTO staff (name, username, password, role) VALUES (%s, %s, %s, %s) RETURNING id, name, username, role",
            (name, username, password, role)
        )
        staff = cur.fetchone()
        conn.commit()
    except Exception as e:
        cur.close()
        conn.close()
        return jsonify({"error": "Username already exists"}), 400
    cur.close()
    conn.close()
    return jsonify(dict(staff)), 201

@app.route('/staff/<int:staff_id>', methods=['DELETE'])
def delete_staff(staff_id):
    user = require_auth(roles=['owner'])
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE staff SET active = FALSE WHERE id = %s", (staff_id,))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"message": "Staff deactivated"})

# ── Customers ──
@app.route('/customers', methods=['GET'])
def get_customers():
    user = require_auth()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('''
        SELECT c.*,
            COALESCE(SUM(d.total_amount - d.amount_paid), 0) as total_outstanding
        FROM customers c
        LEFT JOIN debts d ON c.id = d.customer_id AND d.status != 'paid'
        GROUP BY c.id
        ORDER BY c.name
    ''')
    customers = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify([dict(c) for c in customers])

@app.route('/customers', methods=['POST'])
def add_customer():
    user = require_auth()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    name = data['name']
    phone = data.get('phone', '')
    email = data.get('email', '')
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        'INSERT INTO customers (name, phone, email) VALUES (%s, %s, %s) RETURNING *',
        (name, phone, email)
    )
    customer = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    return jsonify(dict(customer)), 201

# ── Debts ──
@app.route('/debts', methods=['GET'])
def get_debts():
    user = require_auth()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('''
        SELECT d.*,
            c.name as customer_name,
            c.phone as customer_phone,
            (d.total_amount - d.amount_paid) as balance,
            s.name as created_by_name
        FROM debts d
        JOIN customers c ON d.customer_id = c.id
        LEFT JOIN staff s ON d.created_by = s.id
        ORDER BY d.created_at DESC
    ''')
    debts = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify([dict(d) for d in debts])

@app.route('/debts', methods=['POST'])
def add_debt():
    user = require_auth()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    customer_id = data['customer_id']
    description = data['description']
    total_amount = data['total_amount']
    due_date = data.get('due_date', None)
    created_by = user['id']
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        '''INSERT INTO debts (customer_id, description, total_amount, due_date, created_by)
           VALUES (%s, %s, %s, %s, %s) RETURNING *''',
        (customer_id, description, total_amount, due_date, created_by)
    )
    debt = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    return jsonify(dict(debt)), 201

# ── Payments ──
@app.route('/payments', methods=['POST'])
def make_payment():
    user = require_auth()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    debt_id = data['debt_id']
    amount = data['amount']
    note = data.get('note', '')
    recorded_by = user['id']
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    # Record payment
    cur.execute(
        'INSERT INTO payments (debt_id, amount, note, recorded_by) VALUES (%s, %s, %s, %s) RETURNING *',
        (debt_id, amount, note, recorded_by)
    )
    payment = cur.fetchone()
    # Update debt amount paid
    cur.execute(
        'UPDATE debts SET amount_paid = amount_paid + %s WHERE id = %s RETURNING *',
        (amount, debt_id)
    )
    debt = cur.fetchone()
    # Mark as paid if fully settled
    if float(debt['amount_paid']) >= float(debt['total_amount']):
        cur.execute("UPDATE debts SET status = 'paid' WHERE id = %s", (debt_id,))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify(dict(payment)), 201

@app.route('/payments/<int:debt_id>', methods=['GET'])
def get_payments(debt_id):
    user = require_auth()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('''
        SELECT p.*, s.name as recorded_by_name
        FROM payments p
        LEFT JOIN staff s ON p.recorded_by = s.id
        WHERE p.debt_id = %s
        ORDER BY p.paid_at DESC
    ''', (debt_id,))
    payments = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify([dict(p) for p in payments])

# ── Reports ──
@app.route('/reports', methods=['GET'])
def get_reports():
    user = require_auth(roles=['owner', 'manager'])
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('''
        SELECT
            COUNT(DISTINCT c.id) as total_customers,
            COUNT(d.id) as total_debts,
            COALESCE(SUM(d.total_amount), 0) as total_debt_amount,
            COALESCE(SUM(d.amount_paid), 0) as total_collected,
            COALESCE(SUM(d.total_amount - d.amount_paid), 0) as total_outstanding,
            COUNT(CASE WHEN d.status = 'paid' THEN 1 END) as paid_debts,
            COUNT(CASE WHEN d.status = 'unpaid' THEN 1 END) as unpaid_debts,
            COUNT(CASE WHEN d.due_date < NOW() AND d.status != 'paid' THEN 1 END) as overdue_debts
        FROM customers c
        LEFT JOIN debts d ON c.id = d.customer_id
    ''')
    report = cur.fetchone()
    cur.close()
    conn.close()
    return jsonify(dict(report))

# ── Reminders ──
@app.route('/reminders', methods=['GET'])
def get_reminders():
    user = require_auth(roles=['owner', 'manager'])
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('''
        SELECT d.*,
            c.name as customer_name,
            c.phone as customer_phone,
            (d.total_amount - d.amount_paid) as balance
        FROM debts d
        JOIN customers c ON d.customer_id = c.id
        WHERE d.status != 'paid'
        AND d.due_date <= NOW() + INTERVAL '7 days'
        ORDER BY d.due_date ASC
    ''')
    reminders = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify([dict(r) for r in reminders])

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)