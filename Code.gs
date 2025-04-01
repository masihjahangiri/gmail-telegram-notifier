// Configuration
const CONFIG = {
  WORKER_URL: 'https://your-worker.workers.dev', // Replace with your Cloudflare Worker URL
  ACCESS_KEY: 'your-access-key', // Replace with your access key
  CHECK_INTERVAL_MINUTES: 5,
  LABEL: 'INBOX', // Optional: specify a Gmail label to monitor
  MARK_AS_READ: true, // Whether to mark emails as read after sending notification
};

// Properties to store last check time
const LAST_CHECK_PROPERTY = 'LAST_CHECK_TIME';
const PROCESSED_IDS_PROPERTY = 'PROCESSED_EMAIL_IDS';

function checkNewEmails() {
  const now = new Date();
  const lastCheck = getLastCheckTime();
  const processedIds = getProcessedIds();
  
  // Build search query
  let query = 'is:unread';
  if (CONFIG.LABEL) {
    query += ` in:${CONFIG.LABEL}`;
  }
  if (lastCheck) {
    query += ` after:${Math.floor(lastCheck.getTime() / 1000)}`;
  }
  
  // Get unread messages
  const threads = GmailApp.search(query);
  
  for (const thread of threads) {
    const messages = thread.getMessages();
    
    for (const message of messages) {
      const messageId = message.getId();
      
      // Skip if already processed
      if (processedIds.includes(messageId)) {
        continue;
      }
      
      // Extract email details
      const from = message.getFrom();
      const subject = message.getSubject();
      const snippet = message.getPlainBody().substring(0, 200) + '...';
      
      // Prepare notification message
      const notificationMessage = 
        `📧 New Email\n\n` +
        `From: ${from}\n` +
        `Subject: ${subject}\n` +
        `Snippet: ${snippet}`;
      
      // Send notification
      sendNotification(notificationMessage);
      
      // Mark as read if configured
      if (CONFIG.MARK_AS_READ) {
        message.markRead();
      }
      
      // Add to processed IDs
      processedIds.push(messageId);
    }
  }
  
  // Update last check time and processed IDs
  PropertiesService.getScriptProperties().setProperties({
    [LAST_CHECK_PROPERTY]: now.toISOString(),
    [PROCESSED_IDS_PROPERTY]: JSON.stringify(processedIds.slice(-100)) // Keep last 100 IDs
  });
}

function sendNotification(message) {
  const url = `${CONFIG.WORKER_URL}/?key=${CONFIG.ACCESS_KEY}&message=${encodeURIComponent(message)}`;
  const response = UrlFetchApp.fetch(url);
  
  if (response.getResponseCode() !== 200) {
    console.error('Failed to send notification:', response.getContentText());
  }
}

function getLastCheckTime() {
  const lastCheckStr = PropertiesService.getScriptProperties().getProperty(LAST_CHECK_PROPERTY);
  return lastCheckStr ? new Date(lastCheckStr) : null;
}

function getProcessedIds() {
  const processedIdsStr = PropertiesService.getScriptProperties().getProperty(PROCESSED_IDS_PROPERTY);
  return processedIdsStr ? JSON.parse(processedIdsStr) : [];
}

// Create time-based trigger
function createTrigger() {
  // Delete existing triggers
  const triggers = ScriptApp.getProjectTriggers();
  triggers.forEach(trigger => ScriptApp.deleteTrigger(trigger));
  
  // Create new trigger
  ScriptApp.newTrigger('checkNewEmails')
    .timeBased()
    .everyMinutes(CONFIG.CHECK_INTERVAL_MINUTES)
    .create();
} 