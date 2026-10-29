const express = require('express');
const router = express.Router();
const multer = require('multer');
const { scanUrl } = require('../services/urlScanner');
const { scanFile } = require('../services/fileScanner');
const ScanRepository = require('../models/ScanLog');
const { getDBStatus } = require('../config/db');

// Multer memory storage configuration (25MB limit)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 25 * 1024 * 1024 // 25MB max
  }
});

/**
 * @route   POST /api/scan/url
 * @desc    Analyze a suspicious URL with heuristics & domain reputation
 */
router.post('/scan/url', async (req, res) => {
  try {
    const { url } = req.body;
    if (!url || typeof url !== 'string' || url.trim().length === 0) {
      return res.status(400).json({
        success: false,
        error: 'Please enter a valid URL to analyze.'
      });
    }

    const scanResult = scanUrl(url);
    if (!scanResult.success) {
      return res.status(400).json(scanResult);
    }

    // Persist to MongoDB Atlas (or in-memory fallback)
    const logEntry = await ScanRepository.create({
      targetType: 'url',
      target: scanResult.target,
      threatScore: scanResult.threatScore,
      status: scanResult.status,
      verdict: scanResult.verdict,
      riskLevel: scanResult.riskLevel,
      threatAlert: scanResult.threatAlert,
      summary: scanResult.summary,
      indicators: scanResult.indicators,
      hashes: scanResult.hashes,
      metadata: scanResult.metadata,
      heuristics: scanResult.heuristics,
      mitreAttack: scanResult.mitreAttack
    });

    return res.status(200).json({
      ...scanResult,
      id: logEntry._id,
      storageEngine: getDBStatus().client
    });
  } catch (error) {
    console.error('URL Scan Controller Error:', error);
    return res.status(500).json({
      success: false,
      error: 'Internal Threat Engine Exception: ' + error.message
    });
  }
});

/**
 * @route   POST /api/scan/file
 * @desc    Upload & analyze a file payload (scripts, binaries, docs, zips)
 */
router.post('/scan/file', upload.single('payload'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: 'No file received. Please drag and drop or browse a file to inspect.'
      });
    }

    const scanResult = scanFile(req.file);
    if (!scanResult.success) {
      return res.status(400).json(scanResult);
    }

    // Persist to MongoDB Atlas (or in-memory fallback)
    const logEntry = await ScanRepository.create({
      targetType: 'file',
      target: scanResult.target,
      threatScore: scanResult.threatScore,
      status: scanResult.status,
      verdict: scanResult.verdict,
      threatAlert: scanResult.threatAlert,
      riskLevel: scanResult.riskLevel,
      summary: scanResult.summary,
      indicators: scanResult.indicators,
      hashes: scanResult.hashes,
      metadata: scanResult.metadata,
      heuristics: scanResult.heuristics,
      mitreAttack: scanResult.mitreAttack
    });

    return res.status(200).json({
      ...scanResult,
      id: logEntry._id,
      storageEngine: getDBStatus().client
    });
  } catch (error) {
    console.error('File Scan Controller Error:', error);
    return res.status(500).json({
      success: false,
      error: 'Payload Analysis Engine Exception: ' + error.message
    });
  }
});

/**
 * @route   GET /api/scans/history
 * @desc    Retrieve real-time audit trail of past scans
 */
router.get('/scans/history', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit, 10) || 25;
    const { type, status } = req.query;

    const query = {};
    if (type && ['url', 'file'].includes(type)) {
      query.targetType = type;
    }
    if (status && ['CLEAN', 'SUSPICIOUS', 'MALICIOUS'].includes(status)) {
      query.status = status;
    }

    const logs = await ScanRepository.find(query, { limit, sort: { createdAt: -1 } });
    return res.json({
      success: true,
      count: logs.length,
      history: logs,
      dbStatus: getDBStatus()
    });
  } catch (error) {
    console.error('Fetch History Error:', error);
    return res.status(500).json({
      success: false,
      error: 'Failed to retrieve threat telemetry logs.'
    });
  }
});

/**
 * @route   GET /api/scans/stats
 * @desc    Telemetry statistics and live metrics
 */
router.get('/scans/stats', async (req, res) => {
  try {
    const stats = await ScanRepository.getStats();
    return res.json({
      success: true,
      stats,
      dbStatus: getDBStatus()
    });
  } catch (error) {
    console.error('Fetch Stats Error:', error);
    return res.status(500).json({
      success: false,
      error: 'Failed to retrieve telemetry stats.'
    });
  }
});

/**
 * @route   DELETE /api/scans/clear
 * @desc    Clear scan history for testing
 */
router.delete('/scans/clear', async (req, res) => {
  try {
    await ScanRepository.clearAll();
    return res.json({
      success: true,
      message: 'Threat intelligence logs purged successfully.'
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: 'Failed to purge scan logs.'
    });
  }
});

module.exports = router;

