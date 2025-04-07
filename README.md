# 📬 Gmail Telegram Notifier Bot

[![Telegram Bot](https://img.shields.io/badge/Telegram-Bot-blue.svg)](https://t.me/mygmailsbot)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Stay instantly connected to all your Gmail accounts—right from Telegram.  
With **Gmail Telegram Notifier Bot**, you'll receive real-time alerts for new emails, no matter which inbox they land in.

> 💡 **Now with seamless multi-account support** – handle all your Gmail inboxes in one place, effortlessly.

## 🔥 Features You'll Love

- 🔄 **Multi-Account Support**  
  Easily connect and monitor multiple Gmail inboxes.

- 📥 **Real-Time Email Alerts**  
  Receive instant Telegram notifications the moment an email arrives.

- 🔒 **Security-First Design**  
  OAuth2 authentication with strict **read-only** Gmail access.

- ⚙️ **Intuitive Command System**  
  Use simple bot commands like `/add`, `/list`, and `/remove` to manage accounts.

- 📱 **Cross-Platform Compatibility**  
  Works perfectly on **Android**, **iOS**, **Desktop**, and **Web Telegram** clients.

## 🚀 Getting Started

1. Start the bot 👉 [@mygmailsbot](https://t.me/mygmailsbot)  
2. Type `/add` to connect your Gmail account  
3. Securely authenticate via Google  
4. Get real-time email notifications in Telegram  
5. Add more accounts anytime with `/add`

## 💡 Bot Commands

| Command     | Description                          |
|-------------|--------------------------------------|
| `/start`    | Get a welcome message and intro      |
| `/add`      | Connect a new Gmail account          |
| `/list`     | Show connected Gmail accounts        |
| `/remove`   | Disconnect an existing Gmail account |
| `/help`     | Display all available commands       |

## 🔐 Security & Privacy

- ✅ Official **Google OAuth2** authentication  
- ✅ **Read-only** Gmail access (no email modifications)  
- ✅ No data stored on our servers  
- ✅ Secure token storage with auto-refresh  
- ✅ All communication is **end-to-end encrypted**

## 🧠 How It Works

1. You grant the bot read-only access to your Gmail  
2. It watches for new emails via the Gmail API  
3. You receive Telegram alerts instantly  
4. Tap a notification to open the email in Gmail

## 🖥 Supported Platforms

- Android  
- iOS  
- Windows / macOS  
- Telegram Web

## 🧰 Tech Stack

- **Language:** TypeScript  
- **Hosting:** Cloudflare Workers  
- **APIs:** Gmail API, Telegram Bot API  
- **Architecture:** Secure OAuth2 flow, token refresh, low-latency event pipeline

## ⚡ Performance

- 🚀 Real-time Telegram push notifications  
- 🔁 5-minute polling fallback  
- ✅ High reliability & uptime  
- 🧠 Optimized for minimal latency

## 🤝 Contribute

We welcome contributions!

- Fork the repo and open a PR  
- Submit [issues](https://github.com/masihjahangiri/gmail-telegram-notifier/issues) for bugs & feature requests  
- Got ideas? Let’s improve the bot together!

## 📄 License

MIT License. See [LICENSE](./LICENSE) for full terms.

## 💬 Support

Need help?  
Open an [issue on GitHub](https://github.com/masihjahangiri/gmail-telegram-notifier/issues) — we’re happy to help!

Made with ❤️ by [Masih Jahangiri](https://masihjahangiri.com)
