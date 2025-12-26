const jwt = require("jsonwebtoken");

/**
 * Authentication middleware for Express.js applications
 * Validates JWT tokens from Authorization header and attaches user data to request
 *
 * Security Features:
 * - Validates JWT_SECRET environment variable exists
 * - Properly extracts and validates Bearer token format
 * - Provides detailed error messages for debugging
 * - Uses constant-time comparison for token verification
 *
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * @returns {void}
 */
function authenticate(req, res, next) {
  // Validate JWT_SECRET is configured
  if (!process.env.JWT_SECRET) {
    console.error("CRITICAL: JWT_SECRET environment variable is not set");
    return res.status(500).json({
      error: "Server configuration error",
      message: "Authentication service is not properly configured"
    });
  }

  // Extract Authorization header
  const authHeader = req.headers.authorization;

  // Validate Authorization header exists
  if (!authHeader) {
    return res.status(401).json({
      error: "Authentication required",
      message: "No authorization header provided"
    });
  }

  // Validate Bearer token format
  if (!authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Invalid authorization format",
      message: "Authorization header must use Bearer scheme"
    });
  }

  // Extract token from "Bearer <token>"
  const token = authHeader.substring(7);

  // Validate token is not empty
  if (!token || token.trim() === "") {
    return res.status(401).json({
      error: "Invalid token",
      message: "Token cannot be empty"
    });
  }

  // Verify JWT token
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      // Security options
      algorithms: ["HS256"], // Explicitly specify allowed algorithms to prevent algorithm confusion attacks
      clockTolerance: 0, // No tolerance for clock skew
      ignoreExpiration: false, // Respect token expiration
      ignoreNotBefore: false // Respect nbf (not before) claim
    });

    // Attach decoded user data to request object
    req.user = decoded;

    // Proceed to next middleware/route handler
    next();
  } catch (error) {
    // Handle specific JWT errors for better debugging
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({
        error: "Token expired",
        message: "Your session has expired. Please login again"
      });
    }

    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({
        error: "Invalid token",
        message: "Token verification failed"
      });
    }

    if (error.name === "NotBeforeError") {
      return res.status(401).json({
        error: "Token not active",
        message: "Token is not yet valid"
      });
    }

    // Generic error fallback
    console.error("JWT verification error:", error);
    return res.status(401).json({
      error: "Authentication failed",
      message: "Unable to verify token"
    });
  }
}

/**
 * Generates a JWT token for a user
 *
 * @param {Object} payload - User data to encode in token (e.g., { id, email, role })
 * @param {Object} options - Token options
 * @param {string} options.expiresIn - Token expiration time (default: "1h")
 * @returns {string} Signed JWT token
 * @throws {Error} If JWT_SECRET is not configured
 *
 * @example
 * const token = generateToken({ id: 123, email: "user@example.com" }, { expiresIn: "24h" });
 */
function generateToken(payload, options = {}) {
  if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET environment variable is not set");
  }

  // Validate payload
  if (!payload || typeof payload !== "object") {
    throw new Error("Payload must be a non-null object");
  }

  // Default options with security best practices
  const defaultOptions = {
    expiresIn: "1h", // Token expires in 1 hour by default
    algorithm: "HS256", // Use HMAC SHA-256
    issuer: "jwt-auth-example", // Token issuer
    audience: "jwt-auth-example" // Token audience
  };

  const tokenOptions = { ...defaultOptions, ...options };

  try {
    return jwt.sign(payload, process.env.JWT_SECRET, tokenOptions);
  } catch (error) {
    console.error("Token generation error:", error);
    throw new Error("Failed to generate token");
  }
}

/**
 * Validates token without throwing errors
 * Useful for optional authentication scenarios
 *
 * @param {string} token - JWT token to validate
 * @returns {Object|null} Decoded token payload or null if invalid
 */
function validateToken(token) {
  if (!token || !process.env.JWT_SECRET) {
    return null;
  }

  try {
    return jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ["HS256"]
    });
  } catch (error) {
    return null;
  }
}

module.exports = {
  authenticate,
  generateToken,
  validateToken
};
