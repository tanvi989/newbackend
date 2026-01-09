# MongoDB Login API

A minimal, standalone login API built with Flask that connects to the same MongoDB database as the Multifolks Django backend.

## Features

- ✅ User Registration
- ✅ User Login with JWT tokens
- ✅ Protected Profile endpoint
- ✅ MongoDB integration (same database as Django backend)
- ✅ CORS enabled for frontend integration
- ✅ Uses `accounts_login` collection (same as Django)

## Setup

1. **Install dependencies:**
```bash
pip install -r requirements.txt
```

2. **Set MongoDB URI (optional):**
```bash
export MONGO_URI="mongodb://localhost:27017/gaMultilens"
```

If not set, it defaults to `mongodb://localhost:27017/gaMultilens`

3. **Run the server:**
```bash
python app.py
```

The server will start on `http://0.0.0.0:5000`

## Database

- **Database Name:** `gaMultilens` (same as Django backend)
- **Collection:** `accounts_login` (same as Django's Login model)
- **Compatible with:** Multifolks Django backend

## API Endpoints

### 1. Register User
**POST** `/api/register`

**Request Body:**
```json
{
  "first_name": "John",
  "last_name": "Doe",
  "email": "john@example.com",
  "password": "password123",
  "mobile": "9876543210"
}
```

**Response:**
```json
{
  "success": true,
  "message": "User registered successfully",
  "data": {
    "first_name": "John",
    "last_name": "Doe",
    "email": "john@example.com",
    "mobile": "9876543210",
    "id": "507f1f77bcf86cd799439011",
    "token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
  }
}
```

### 2. Login
**POST** `/api/login`

**Request Body:**
```json
{
  "email": "john@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "first_name": "John",
    "last_name": "Doe",
    "email": "john@example.com",
    "mobile": "9876543210",
    "id": "507f1f77bcf86cd799439011",
    "is_verified": true,
    "token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
  }
}
```

### 3. Get Profile (Protected)
**GET** `/api/profile`

**Headers:**
```
Authorization: Bearer <token>
```

**Response:**
```json
{
  "success": true,
  "data": {
    "first_name": "John",
    "last_name": "Doe",
    "email": "john@example.com",
    "mobile": "9876543210",
    "id": "507f1f77bcf86cd799439011",
    "is_verified": true,
    "date_joined": "2025-12-03T19:10:00"
  }
}
```

### 4. Health Check
**GET** `/api/health`

**Response:**
```json
{
  "success": true,
  "message": "Login API is running",
  "mongodb": "connected",
  "database": "gaMultilens",
  "timestamp": "2025-12-03T19:10:00"
}
```

## Testing with cURL

### Register:
```bash
curl -X POST http://localhost:5000/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "first_name": "John",
    "last_name": "Doe",
    "email": "john@example.com",
    "password": "password123",
    "mobile": "9876543210"
  }'
```

### Login:
```bash
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "password123"
  }'
```

### Get Profile:
```bash
curl -X GET http://localhost:5000/api/profile \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

### Health Check:
```bash
curl http://localhost:5000/api/health
```

## User Document Structure

The API creates user documents matching Django's `Login` model:

```json
{
  "_id": ObjectId("..."),
  "firstName": "John",
  "lastName": "Doe",
  "email": "john@example.com",
  "primaryContact": "9876543210",
  "password": "hashed_password",
  "is_verified": true,
  "is_deactivated": false,
  "is_active": true,
  "is_staff": false,
  "is_superuser": false,
  "date_joined": ISODate("..."),
  "last_login": ISODate("...")
}
```

## Notes

- Users created via this API are compatible with the Django backend
- Users created via Django backend can login through this API
- Password hashing is compatible between both systems (Werkzeug)
- Token expires after 24 hours
- Change the `SECRET_KEY` in production
"# multifolks-backend-clean" 
"# multifolks-backend-clean" 
