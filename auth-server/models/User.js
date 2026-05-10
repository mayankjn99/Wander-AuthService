/**
 * User Model
 *
 * Stores registered user accounts. Passwords are NEVER stored in plaintext —
 * the authController hashes them with bcrypt before calling user.save().
 *
 * The minlength: 60 constraint on `password` enforces that only bcrypt hashes
 * (which are always 60 chars) can be persisted, providing an extra safety net.
 */

const mongoose = require('mongoose');

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: [true, 'Username is required'],
      unique: true,
      trim: true,
      minlength: [3, 'Username must be at least 3 characters'],
      maxlength: [30, 'Username cannot exceed 30 characters'],
      // Only letters, numbers, and underscores
      match: [/^[a-zA-Z0-9_]+$/, 'Username may only contain letters, numbers, and underscores'],
    },

    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      trim: true,
      lowercase: true,
    },

    // Stores only bcrypt hash — plaintext passwords must never reach here
    password: {
      type: String,
      required: [true, 'Password is required'],
      minlength: [60, 'Password field must contain a bcrypt hash'],
    },
  },
  {
    timestamps: true, // auto-adds createdAt / updatedAt
  }
);

// Strip the password hash from any JSON serialization (e.g. res.json(user))
userSchema.methods.toJSON = function () {
  const obj = this.toObject();
  delete obj.password;
  return obj;
};

module.exports = mongoose.model('User', userSchema);
