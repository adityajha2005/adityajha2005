# jwt-auth-example

A simple JWT authentication middleware example for Express.js applications.

## Installation

```bash
npm install
```

## Usage

The `auth.js` module provides three functions for JWT-based authentication:

### Authentication Middleware

```javascript
const { authenticate, generateToken, validateToken } = require("./auth");

// Protect routes with authentication
app.get("/protected", authenticate, (req, res) => {
  res.json({ user: req.user });
});

// Generate tokens for users
const token = generateToken({ id: 123, email: "user@example.com" }, { expiresIn: "24h" });

// Validate tokens without throwing errors
const decoded = validateToken(token);
if (decoded) {
  console.log("Valid token:", decoded);
}
```

### Security Features

1. **Robust Validation**: Validates JWT_SECRET exists, proper Bearer format, and token structure
2. **Algorithm Protection**: Explicitly specifies HS256 to prevent algorithm confusion attacks
3. **Detailed Error Messages**: Provides specific error responses (expired, invalid, not active)
4. **JSON Responses**: Returns structured JSON errors instead of plain text
5. **Environment Checks**: Validates configuration before processing requests
6. **Token Generation**: Helper function with secure defaults (1h expiration, issuer/audience claims)
7. **Safe Validation**: Non-throwing validation function for optional authentication scenarios

### Environment Variables

- `JWT_SECRET` - Secret key used to verify JWT tokens
- `PORT` - Server port (default: 3000)

### Running the Example Server

```bash
# Set your JWT secret
export JWT_SECRET=your-secret-key

# Start the server
npm start
```

## API Endpoints

- `GET /public` - Public endpoint (no authentication required)
- `GET /protected` - Protected endpoint (requires valid JWT token)

## Testing Authentication

To test the protected endpoint, include the JWT token in the Authorization header:

```bash
curl -H "Authorization: Bearer your-jwt-token" http://localhost:3000/protected
```
