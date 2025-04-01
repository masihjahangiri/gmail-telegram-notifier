# Gmail to Telegram Notifier

A serverless system that sends Telegram notifications for new Gmail messages using Cloudflare Workers and Google Apps Script.

## Features

- Monitors Gmail inbox for new unread messages
- Sends notifications to Telegram via Cloudflare Worker
- Serverless architecture using free services
- Configurable check interval and email filters
- Optional email marking as read after notification
- Duplicate notification prevention

## Prerequisites

1. A Cloudflare account
2. A Google account with Gmail
3. A Telegram bot (create one via [@BotFather](https://t.me/botfather))
4. Node.js and npm installed locally

## Setup Instructions

### 1. Cloudflare Worker Setup

1. Install Wrangler CLI:
   ```bash
   npm install -g wrangler
   ```

2. Login to Cloudflare:
   ```bash
   wrangler login
   ```

3. Install project dependencies:
   ```bash
   npm install
   ```

4. Set up environment variables:
   ```bash
   wrangler secret put TELEGRAM_TOKEN
   wrangler secret put TELEGRAM_CHAT_ID
   wrangler secret put ACCESS_KEY
   ```

5. Deploy the worker:
   ```bash
   npm run deploy
   ```

6. Note down your worker URL (it will be shown after deployment)

### 2. Google Apps Script Setup

1. Go to [Google Apps Script](https://script.google.com)
2. Create a new project
3. Copy the contents of `Code.gs` into the script editor
4. Update the `CONFIG` object in the script:
   - Set `WORKER_URL` to your Cloudflare Worker URL
   - Set `ACCESS_KEY` to match the one you set in Cloudflare
   - Adjust other settings as needed

5. Save the script
6. Run the `createTrigger` function once to set up the time-based trigger
7. Grant necessary permissions when prompted

### 3. Security Considerations

1. Keep your Telegram bot token secure:
   - Never commit it to version control
   - Use Cloudflare Workers secrets
   - Rotate the token if compromised

2. Protect your Cloudflare Worker:
   - Use a strong access key
   - Consider adding rate limiting
   - Monitor worker usage

3. Gmail API permissions:
   - The script only requests necessary permissions
   - Review permissions regularly
   - Use a dedicated Google account if possible

## Testing

1. Send a test email to your Gmail account
2. Wait for the next check interval (default: 5 minutes)
3. You should receive a Telegram notification

## Troubleshooting

1. Check Cloudflare Worker logs:
   ```bash
   wrangler tail
   ```

2. Check Google Apps Script execution logs:
   - View > Execution log in the script editor

3. Common issues:
   - Invalid Telegram token or chat ID
   - Incorrect access key
   - Gmail API permissions not granted
   - Rate limiting from Telegram API

## Contributing

Feel free to submit issues and enhancement requests! 