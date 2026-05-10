/**
 * Auth Routes
 *
 * Wires URL paths to controller functions and attaches express-validator
 * validation chains to mutating endpoints. Input sanitization here is the
 * first line of defence against XSS and injection attacks.
 */

const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const authController = require('../controllers/authController');

// ─── Validation chains ────────────────────────────────────────────────────────

// ─── Shared type-coercion guard ───────────────────────────────────────────────
// Rejects any field that is not a plain string (e.g. objects like {"$ne":null}
// sent via JSON body). express-validator runs before the controller, so any
// object value is caught here before it can reach a MongoDB query.
// This closes the NoSQL operator-injection vector on all POST endpoints.
function mustBeString(fieldName) {
  return body(fieldName).custom((value) => {
    if (typeof value !== 'string') {
      throw new Error(`${fieldName} must be a plain string.`);
    }
    return true;
  });
}

const loginValidation = [
  // Reject non-string values before any other check
  mustBeString('identifier'),
  mustBeString('password'),

  body('identifier')
    .trim()
    .notEmpty().withMessage('Email or username is required.')
    .custom((value) => {
      // Accept either a valid email OR a valid username
      const isEmail    = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
      const isUsername = /^[a-zA-Z0-9_]{3,30}$/.test(value);
      if (!isEmail && !isUsername) {
        throw new Error('Enter a valid email address or username (3–30 chars, letters/numbers/underscores).');
      }
      return true;
    }),

  body('password')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters.'),
];

const registerValidation = [
  // Reject non-string values before any other check
  mustBeString('username'),
  mustBeString('email'),
  mustBeString('password'),
  mustBeString('confirmPassword'),

  body('username')
    .trim()
    .isLength({ min: 3, max: 30 }).withMessage('Username must be 3–30 characters.')
    .matches(/^[a-zA-Z0-9_]+$/).withMessage('Username may only contain letters, numbers, and underscores.'),

  body('email')
    .trim()
    .isEmail().withMessage('A valid email address is required.'),
    // normalizeEmail() intentionally omitted — see loginValidation note above.

  body('password')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters.'),

  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Passwords do not match.');
      }
      return true;
    }),
];

// ─── Public routes ────────────────────────────────────────────────────────────

router.get('/', authController.home);

// Login
router.get('/login', authController.showLogin);
router.post('/login', loginValidation, authController.processLogin);

// Registration
router.get('/register', authController.showRegister);
router.post('/register', registerValidation, authController.processRegister);

// Logout
router.get('/logout', authController.logout);

// ─── OAuth 2.0 endpoints ──────────────────────────────────────────────────────

// Step 1: Client redirects user here to start the authorization flow
router.get('/authorize', authController.authorize);

// Step 2: Client POSTs here to exchange an authorization code for a JWT
router.post('/oauth/token', authController.exchangeToken);

// Optional: Client POSTs Bearer token here to retrieve user profile
router.get('/oauth/userinfo', authController.userInfo);

module.exports = router;
