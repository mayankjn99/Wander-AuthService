/**
 * server.js — Entry point
 * Loads env, validates required vars, connects to MongoDB, starts listening.
 */

'use strict';

require('dotenv').config();

const mongoose = require('mongoose');
const app      = require('./app');

if (!process.env.SESSION_SECRET) {
  console.error('FATAL: SESSION_SECRET is not set. Refusing to start.');
  process.exit(1);
}

if (!process.env.MONGO_URI) {
  console.error('FATAL: MONGO_URI is not set. Refusing to start.');
  process.exit(1);
}

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log('✓ MongoDB connected');
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
      console.log(`✓ Auth server listening on http://localhost:${PORT}`);
      console.log(`  Environment: ${process.env.NODE_ENV || 'development'}`);
    });
  })
  .catch((err) => {
    console.error('✗ MongoDB connection failed:', err.message);
    process.exit(1);
  });
