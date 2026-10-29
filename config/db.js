const mongoose = require('mongoose');

let isConnected = false;
let dbMode = 'uninitialized';

const connectDB = async () => {
  const uri = process.env.MONGODB_URI;

  // Check if placeholder or missing
  if (!uri || uri.includes('<username>') || uri.includes('user:password')) {
    console.warn('\x1b[33m%s\x1b[0m', '⚠ [MongoDB Atlas] Placeholder or missing MONGODB_URI detected in .env.');
    console.warn('\x1b[36m%s\x1b[0m', 'ℹ [CyberVigil AI] Activating High-Performance In-Memory Data Store fallback mode.');
    console.warn('\x1b[36m%s\x1b[0m', 'ℹ Scans and statistics will be fully logged in memory without requiring a live MongoDB Atlas cluster.');
    dbMode = 'in-memory-fallback';
    return { isConnected: false, mode: dbMode };
  }

  try {
    const conn = await mongoose.connect(uri, {
      serverSelectionTimeoutMS: 5000,
    });
    isConnected = true;
    dbMode = 'mongodb-atlas';
    console.log('\x1b[32m%s\x1b[0m', `✓ [MongoDB Atlas] Connected securely to host: ${conn.connection.host}`);
    return { isConnected: true, mode: dbMode };
  } catch (error) {
    console.error('\x1b[31m%s\x1b[0m', `✗ [MongoDB Atlas Connection Error]: ${error.message}`);
    if (process.env.DB_FALLBACK === 'true') {
      console.warn('\x1b[33m%s\x1b[0m', '⚠ [CyberVigil AI] Falling back gracefully to In-Memory Database store. All endpoints remain 100% operational!');
      dbMode = 'in-memory-fallback';
      return { isConnected: false, mode: dbMode };
    }
    throw error;
  }
};

const getDBStatus = () => {
  return {
    connected: isConnected,
    mode: dbMode,
    client: isConnected ? 'MongoDB Atlas Cloud' : 'CyberVigil Resilient In-Memory Engine'
  };
};

module.exports = { connectDB, getDBStatus };

