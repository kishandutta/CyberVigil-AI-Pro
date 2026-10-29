require('dotenv').config();
const http = require('http');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
const { connectDB, getDBStatus } = require('./config/db');
const scanRoutes = require('./routes/scanRoutes');

const app = express();
const PORT = process.env.PORT || 5000;

// Security Middleware (Relaxed CSP to allow modern Cyber-Command UI, Tailwind CDN, Google Fonts & FontAwesome)
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
  })
);

// CORS & Request Parsing
app.use(cors());
app.use(express.json({ limit: '30mb' }));
app.use(express.urlencoded({ extended: true, limit: '30mb' }));

// Development Logging
if (process.env.NODE_ENV !== 'production') {
  app.use(morgan('dev'));
}

// Serve Frontend Static Assets
app.use(express.static(path.join(__dirname, 'public')));

// Health & Status Probe
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ONLINE',
    system: 'CyberVigil AI Threat Engine',
    timestamp: new Date().toISOString(),
    database: getDBStatus()
  });
});

// Threat Intelligence API Routes
app.use('/api', scanRoutes);

// Dedicated Multi-Page HTML View Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/scanner', (req, res) => {
  res.redirect('/dashboard');
});

app.get('/official-links', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'official-links.html'));
});

app.get('/session-history', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'session-history.html'));
});

app.get('/security-academy', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'security-academy.html'));
});

// Fallback to index.html for undefined routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error('Unhandled Application Exception:', err);
  res.status(500).json({
    success: false,
    error: 'Internal Threat Engine Exception: ' + err.message
  });
});

// Boot Server & Establish Cloud Database Session
const startServer = async () => {
  try {
    await connectDB();

    let currentPort = parseInt(PORT, 10) || 5000;
    const maxPortAttempts = 10;
    let attempts = 0;

    const tryListen = (portToTry) => {
      const server = http.createServer(app);

      server.on('error', (err) => {
        if (err.code === 'EADDRINUSE') {
          attempts++;
          if (attempts < maxPortAttempts) {
            console.warn(`⚠️  [Port Conflict] Port ${portToTry} is occupied by another process.`);
            console.log(`🔄  Auto-switching to alternative port ${portToTry + 1}...`);
            tryListen(portToTry + 1);
          } else {
            console.error(`\n❌ Error: Unable to bind to any port between ${PORT} and ${portToTry}.`);
            console.error(`💡 Tip: Run in PowerShell to terminate process using port 5000:`);
            console.error(`   Stop-Process -Id (Get-NetTCPConnection -LocalPort 5000).OwningProcess -Force\n`);
            process.exit(1);
          }
        } else {
          console.error('Server error:', err);
          process.exit(1);
        }
      });

      server.listen(portToTry, () => {
        console.log('\n=============================================================');
        console.log('   🛡️  CYBERVIGIL AI - ADVANCED THREAT INTELLIGENCE HUB');
        console.log('=============================================================');
        console.log(`📡 Core Server Listening on : http://localhost:${portToTry}`);
        console.log(`🌐 Web Interface Live at   : http://localhost:${portToTry}`);
        console.log(`📊 Health Endpoint          : http://localhost:${portToTry}/api/health`);
        console.log(`💾 Active Database Mode     : ${getDBStatus().client}`);
        if (portToTry !== parseInt(PORT, 10)) {
          console.log(`ℹ️  Note: Port ${PORT} was busy; successfully bound to port ${portToTry}.`);
        }
        console.log('=============================================================\n');
      });
    };

    tryListen(currentPort);
  } catch (err) {
    console.error('Fatal initialization error:', err);
    process.exit(1);
  }
};

startServer();

