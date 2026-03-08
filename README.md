# Gmail Telegram Notifier

Cloudflare Workers application that delivers real-time Gmail notifications to Telegram. Connect multiple Gmail accounts and receive instant alerts when new emails arrive.

Built as a serverless solution on Cloudflare Workers with KV storage. No servers to manage, no recurring infrastructure cost beyond the free tier.

## How It Works

1. Add your Gmail accounts via the Telegram bot using OAuth2 (read-only access)
2. Gmail sends push notifications to the Worker via webhook
3. The Worker formats the email summary and sends it to your Telegram chat
4. A cron trigger polls every 5 minutes as a fallback for missed webhooks

## Features

- **Multi-account support** -- Connect and monitor multiple Gmail accounts from one Telegram bot
- **OAuth2 read-only access** -- Only requests permission to read email metadata, not modify anything
- **Webhook-first delivery** -- Gmail push notifications for near-instant alerts
- **Cron fallback** -- 5-minute polling ensures no emails are missed if webhooks fail
- **Cloudflare KV storage** -- Account data and tokens stored in edge KV, no external database needed

## Bot Commands

| Command | Description |
|---|---|
| `/start` | Initialize the bot |
| `/add` | Connect a new Gmail account via OAuth2 |
| `/list` | Show connected accounts |
| `/remove` | Disconnect a Gmail account |
| `/help` | Show available commands |

## Deployment

### Prerequisites

- Cloudflare account with Workers enabled
- Telegram bot token (from [@BotFather](https://t.me/BotFather))
- Google Cloud project with Gmail API enabled and OAuth2 credentials

### Setup

1. Clone and install dependencies:

```bash
git clone https://github.com/masihjahangiri/gmail-telegram-notifier.git
cd gmail-telegram-notifier
npm install
```

2. Configure `wrangler.toml` with your Google OAuth client ID and redirect URI.

3. Set secrets:

```bash
npx wrangler secret put TELEGRAM_BOT_TOKEN
npx wrangler secret put WEBHOOK_SECRET
npx wrangler secret put GOOGLE_CLIENT_SECRET
```

4. Create the KV namespace:

```bash
npx wrangler kv:namespace create telegram-gmail
```

5. Deploy:

```bash
npm run deploy
```

## Tech Stack

- TypeScript on Cloudflare Workers
- Cloudflare KV for persistent storage
- Gmail API with OAuth2 and push notifications
- Telegram Bot API

## License

MIT
