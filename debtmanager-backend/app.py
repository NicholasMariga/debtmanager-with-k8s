from flask import Flask, jsonify, request
from flask_cors import CORS
import psycopg2
import psycopg2.extras
import os
import hashlib
import json
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
    # Core tables
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
    # Migrations: safe to run on every startup
    cur.execute("ALTER TABLE debts ADD COLUMN IF NOT EXISTS debt_date TIMESTAMP")
    cur.execute("UPDATE debts SET debt_date = created_at WHERE debt_date IS NULL")
    cur.execute("ALTER TABLE customers ADD COLUMN IF NOT EXISTS note TEXT")
    cur.execute("ALTER TABLE customers ADD COLUMN IF NOT EXISTS archived BOOLEAN DEFAULT FALSE")
    cur.execute("ALTER TABLE customers ADD COLUMN IF NOT EXISTS credit_limit DECIMAL(10,2)")
    cur.execute("ALTER TABLE debts ADD COLUMN IF NOT EXISTS category VARCHAR(50)")
    cur.execute("ALTER TABLE debts ADD COLUMN IF NOT EXISTS notes TEXT")
    cur.execute("ALTER TABLE write_offs ADD COLUMN IF NOT EXISTS amount DECIMAL(10,2)")
    cur.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id SERIAL PRIMARY KEY,
            action VARCHAR(50) NOT NULL,
            entity_type VARCHAR(50),
            entity_id INTEGER,
            details JSONB,
            performed_by INTEGER REFERENCES staff(id),
            performed_at TIMESTAMP DEFAULT NOW()
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS write_offs (
            id SERIAL PRIMARY KEY,
            debt_id INTEGER REFERENCES debts(id) UNIQUE,
            reason VARCHAR(255) NOT NULL,
            written_off_by INTEGER REFERENCES staff(id),
            written_off_at TIMESTAMP DEFAULT NOW()
        )
    ''')
    # Default owner account
    cur.execute("SELECT id FROM staff WHERE username = 'owner'")
    if not cur.fetchone():
        cur.execute(
            "INSERT INTO staff (name, username, password, role) VALUES (%s, %s, %s, %s)",
            ('Shop Owner', 'owner', hash_password('happywise2024'), 'owner')
        )
    conn.commit()
    cur.close()
    conn.close()

def log_audit(cur, action, entity_type, entity_id, details, performed_by):
    cur.execute(
        'INSERT INTO audit_logs (action, entity_type, entity_id, details, performed_by) VALUES (%s, %s, %s, %s, %s)',
        (action, entity_type, entity_id, psycopg2.extras.Json(details), performed_by)
    )

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
    conn2 = get_db(); cur2 = conn2.cursor()
    log_audit(cur2, 'login', 'staff', user['id'], {'username': user['username']}, user['id'])
    conn2.commit(); cur2.close(); conn2.close()
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
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(
            "INSERT INTO staff (name, username, password, role) VALUES (%s, %s, %s, %s) RETURNING id, name, username, role",
            (data['name'], data['username'], hash_password(data['password']), data['role'])
        )
        staff = cur.fetchone()
        conn.commit()
    except Exception:
        cur.close()
        conn.close()
        return jsonify({"error": "Username already exists"}), 400
    cur.close()
    conn.close()
    return jsonify(dict(staff)), 201

@app.route('/staff/<int:staff_id>', methods=['PUT'])
def update_staff(staff_id):
    user = require_auth(roles=['owner'])
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT name FROM staff WHERE id = %s", (staff_id,))
    s = cur.fetchone()
    staff_name = s['name'] if s else str(staff_id)
    if 'password' in data:
        cur.execute(
            "UPDATE staff SET password = %s WHERE id = %s RETURNING id, name, username, role, active",
            (hash_password(data['password']), staff_id)
        )
        updated = cur.fetchone()
        log_audit(cur, 'staff_password_reset', 'staff', staff_id, {'staff': staff_name}, user['id'])
    elif 'active' in data:
        cur.execute(
            "UPDATE staff SET active = %s WHERE id = %s RETURNING id, name, username, role, active",
            (data['active'], staff_id)
        )
        updated = cur.fetchone()
        action = 'staff_activated' if data['active'] else 'staff_deactivated'
        log_audit(cur, action, 'staff', staff_id, {'staff': staff_name}, user['id'])
    conn.commit()
    cur.close()
    conn.close()
    return jsonify(dict(updated))

@app.route('/staff/<int:staff_id>', methods=['DELETE'])
def delete_staff(staff_id):
    user = require_auth(roles=['owner'])
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT name FROM staff WHERE id = %s", (staff_id,))
    s = cur.fetchone()
    staff_name = s['name'] if s else str(staff_id)
    cur.execute("UPDATE staff SET active = FALSE WHERE id = %s", (staff_id,))
    log_audit(cur, 'staff_deactivated', 'staff', staff_id, {'staff': staff_name}, user['id'])
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
    show_archived = request.args.get('archived') == 'true'
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('''
        SELECT c.*,
            COALESCE(SUM(d.total_amount - d.amount_paid), 0) as total_outstanding
        FROM customers c
        LEFT JOIN debts d ON c.id = d.customer_id AND d.status != 'paid'
        WHERE c.archived = %s
        GROUP BY c.id
        ORDER BY c.name
    ''', (show_archived,))
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
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        'INSERT INTO customers (name, phone, email, credit_limit) VALUES (%s, %s, %s, %s) RETURNING *',
        (data['name'], data.get('phone', ''), data.get('email', ''), data.get('credit_limit') or None)
    )
    customer = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    return jsonify(dict(customer)), 201

@app.route('/customers/<int:customer_id>', methods=['DELETE'])
def archive_customer(customer_id):
    user = require_auth()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE customers SET archived = TRUE WHERE id = %s", (customer_id,))
    log_audit(cur, 'customer_archived', 'customer', customer_id, {}, user['id'])
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"message": "Customer archived"})

@app.route('/customers/<int:customer_id>', methods=['PUT'])
def update_customer(customer_id):
    user = require_auth()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    fields, values = ['note = %s'], [data.get('note')]
    if 'archived' in data:
        fields.append('archived = %s')
        values.append(data['archived'])
    if 'credit_limit' in data:
        fields.append('credit_limit = %s')
        values.append(data['credit_limit'])
    values.append(customer_id)
    cur.execute(
        f'UPDATE customers SET {", ".join(fields)} WHERE id = %s RETURNING *',
        values
    )
    customer = cur.fetchone()
    if 'archived' in data and data['archived'] == False:
        log_audit(cur, 'customer_restored', 'customer', customer_id, {}, user['id'])
    elif 'credit_limit' in data:
        log_audit(cur, 'credit_limit_changed', 'customer', customer_id, {'credit_limit': data.get('credit_limit')}, user['id'])
    conn.commit()
    cur.close()
    conn.close()
    return jsonify(dict(customer))

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
            (d.total_amount - d.amount_paid - COALESCE(wo.amount, 0)) as balance,
            s.name as created_by_name,
            wo.reason as writeoff_reason,
            wo.amount as writeoff_amount,
            wo.written_off_at
        FROM debts d
        JOIN customers c ON d.customer_id = c.id
        LEFT JOIN staff s ON d.created_by = s.id
        LEFT JOIN write_offs wo ON d.id = wo.debt_id
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
    debt_date = data.get('debt_date', None)
    category = data.get('category', None)
    notes = data.get('notes', None)
    created_by = user['id']
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        '''INSERT INTO debts (customer_id, description, total_amount, due_date, debt_date, category, notes, created_by)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING *''',
        (customer_id, description, total_amount, due_date, debt_date, category, notes, created_by)
    )
    debt = cur.fetchone()
    cur.execute('SELECT name FROM customers WHERE id = %s', (customer_id,))
    cust_row = cur.fetchone()
    customer_name = cust_row['name'] if cust_row else str(customer_id)
    log_audit(cur, 'debt_added', 'debt', debt['id'], {'description': description, 'customer': customer_name, 'amount': float(total_amount)}, created_by)
    conn.commit()
    cur.close()
    conn.close()
    return jsonify(dict(debt)), 201

@app.route('/debts/<int:debt_id>', methods=['PUT'])
def update_debt(debt_id):
    user = require_auth()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('SELECT description, total_amount FROM debts WHERE id = %s', (debt_id,))
    old = dict(cur.fetchone())
    cur.execute(
        '''UPDATE debts SET description=%s, total_amount=%s, due_date=%s, debt_date=%s, category=%s, notes=%s
           WHERE id=%s RETURNING *''',
        (data.get('description'), data.get('total_amount'), data.get('due_date'),
         data.get('debt_date'), data.get('category'), data.get('notes'), debt_id)
    )
    debt = cur.fetchone()
    # Re-evaluate paid status
    if float(debt['amount_paid']) >= float(debt['total_amount']):
        cur.execute("UPDATE debts SET status='paid' WHERE id=%s", (debt_id,))
    elif debt['status'] == 'paid':
        cur.execute("UPDATE debts SET status='unpaid' WHERE id=%s", (debt_id,))
    changed = {}
    if old['description'] != data.get('description'):
        changed['description'] = f"{old['description']} -> {data.get('description')}"
    if float(old['total_amount']) != float(data.get('total_amount', 0)):
        changed['amount'] = f"{float(old['total_amount']):.2f} -> {float(data.get('total_amount', 0)):.2f}"
    log_audit(cur, 'debt_edited', 'debt', debt_id, changed or {'description': data.get('description')}, user['id'])
    conn.commit()
    cur.close()
    conn.close()
    return jsonify(dict(debt))

# ── Write-offs ──
@app.route('/writeoffs', methods=['GET'])
def get_writeoffs():
    user = require_auth()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('SELECT * FROM write_offs ORDER BY written_off_at DESC')
    writeoffs = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify([dict(w) for w in writeoffs])

@app.route('/writeoffs', methods=['POST'])
def add_writeoff():
    user = require_auth()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        amount = data.get('amount') or None
        cur.execute(
            'INSERT INTO write_offs (debt_id, reason, amount, written_off_by) VALUES (%s, %s, %s, %s) RETURNING *',
            (data['debt_id'], data['reason'], amount, user['id'])
        )
        writeoff = cur.fetchone()
        log_audit(cur, 'writeoff_added', 'debt', data['debt_id'], {'reason': data['reason'], 'amount': float(amount) if amount else None}, user['id'])
        conn.commit()
    except Exception:
        cur.close()
        conn.close()
        return jsonify({"error": "Already written off"}), 400
    cur.close()
    conn.close()
    return jsonify(dict(writeoff)), 201

@app.route('/writeoffs/<int:debt_id>', methods=['DELETE'])
def delete_writeoff(debt_id):
    user = require_auth()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    conn = get_db()
    cur = conn.cursor()
    cur.execute('DELETE FROM write_offs WHERE debt_id = %s', (debt_id,))
    log_audit(cur, 'writeoff_undone', 'debt', debt_id, {}, user['id'])
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"message": "Write-off removed"})

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
    cur.execute(
        'INSERT INTO payments (debt_id, amount, note, recorded_by) VALUES (%s, %s, %s, %s) RETURNING *',
        (debt_id, amount, note, recorded_by)
    )
    payment = cur.fetchone()
    cur.execute(
        'UPDATE debts SET amount_paid = amount_paid + %s WHERE id = %s RETURNING *',
        (amount, debt_id)
    )
    debt = cur.fetchone()
    if float(debt['amount_paid']) >= float(debt['total_amount']):
        cur.execute("UPDATE debts SET status = 'paid' WHERE id = %s", (debt_id,))
    log_audit(cur, 'payment_recorded', 'debt', debt_id, {'amount': float(amount), 'note': note}, recorded_by)
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
        LEFT JOIN write_offs wo ON d.id = wo.debt_id
        WHERE d.status != 'paid'
        AND d.due_date IS NOT NULL
        AND d.due_date < NOW()
        AND wo.id IS NULL
        ORDER BY d.due_date ASC
    ''')
    reminders = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify([dict(r) for r in reminders])

# ── Audit Log ──
@app.route('/audit', methods=['GET'])
def get_audit():
    user = require_auth(roles=['owner', 'manager'])
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    filters = []
    params = []
    staff_id = request.args.get('staff_id')
    action = request.args.get('action')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    if staff_id:
        filters.append('al.performed_by = %s')
        params.append(staff_id)
    if action:
        filters.append('al.action = %s')
        params.append(action)
    if date_from:
        filters.append('al.performed_at >= %s')
        params.append(date_from)
    if date_to:
        filters.append('al.performed_at <= %s')
        params.append(date_to + ' 23:59:59')
    where = ('WHERE ' + ' AND '.join(filters)) if filters else ''
    cur.execute(f'''
        SELECT al.*, s.name as staff_name
        FROM audit_logs al
        LEFT JOIN staff s ON al.performed_by = s.id
        {where}
        ORDER BY al.performed_at DESC
        LIMIT 500
    ''', params)
    logs = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify([dict(l) for l in logs])

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
