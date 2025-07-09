# InfoGather Demo Credentials

## Web Dashboard Login

Since InfoGather uses a registration system, you'll need to create an account first. Here's how:

### Creating a Demo Account

1. **Go to the login page**: http://localhost:5000/login
2. **Click "Register" or use the registration form**
3. **Fill in the registration details**:
   - Username: `demo` (or any username you prefer)
   - Password: `demo123` (or any secure password)
   - Email: `demo@example.com` (optional)

### Default Demo Account

If you want to use a pre-created account, you can create one quickly:

**Username**: `demo`
**Password**: `demo123`

### Creating the Demo Account Programmatically

Run this command to create a demo account:

```bash
python -c "
from web_dashboard_simple import get_db_connection
from werkzeug.security import generate_password_hash
import uuid

with get_db_connection() as conn:
    cursor = conn.cursor()
    user_id = str(uuid.uuid4())
    password_hash = generate_password_hash('demo123')
    
    cursor.execute('''
        INSERT INTO users (id, username, password_hash, email, created_at)
        VALUES (%s, %s, %s, %s, NOW())
        ON CONFLICT (username) DO NOTHING
    ''', (user_id, 'demo', password_hash, 'demo@example.com'))
    
    conn.commit()
    cursor.close()
    print('Demo account created successfully!')
    print('Username: demo')
    print('Password: demo123')
"
```

### Security Note

These are demo credentials for testing purposes only. In production:
- Use strong, unique passwords
- Enable two-factor authentication
- Regularly rotate credentials
- Monitor access logs

### Accessing the Dashboard

1. Open your browser and go to: http://localhost:5000
2. You'll be redirected to the login page
3. Enter your credentials or register a new account
4. Once logged in, you'll have access to:
   - Dashboard with scan statistics
   - Scan configuration page
   - Scan history
   - Real-time monitoring
   - Health check endpoints

### API Endpoints

Once authenticated, you can also access:
- `/api/dashboard_stats` - Dashboard statistics
- `/api/scan/start` - Start new scans
- `/api/scan/status/<scan_id>` - Check scan status
- `/health` - Health check (no auth required)
- `/health/ready` - Readiness check (no auth required)
- `/health/live` - Liveness check (no auth required)