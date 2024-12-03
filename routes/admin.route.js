

/*// routes/admin.js
const express = require('express');
const router = express.Router();
const ActivityLog = require('../models/activityLog.model.js'); // Import the ActivityLog model

// Route to get the activity log
router.get('/activity-log', async (req, res) => {
  try {
    const activityLog = await ActivityLog.find().sort({ timestamp: -1 }); // Fetch and sort by timestamp
    res.json(activityLog);
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch activity log' });
  }
});

module.exports = router;*/