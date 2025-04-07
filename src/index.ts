// Gmail Notification Telegram Bot for Cloudflare Workers
// This bot monitors multiple Gmail accounts and sends notifications for new emails via Telegram

import { 
  EmailMessage, 
  GmailCredentials, 
  TelegramUpdate, 
  TelegramMessage,
  GmailMessagesResponse,
  GmailMessageDetails,
  GmailPushNotification,
  ErrorWithMessage,
  isErrorWithMessage,
  TelegramWebhookInfo
} from './types';

// Environment variables interface for Cloudflare Worker
interface Env {
  // Telegram Bot Token from BotFather
  TELEGRAM_BOT_TOKEN: string;
  
  // KV namespace for storing user data and Gmail credentials
  'telegram-gmail': KVNamespace;
  
  // Secret for webhook
  WEBHOOK_SECRET: string;
  
  // Google OAuth configuration
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  GOOGLE_REDIRECT_URI: string;
  GOOGLE_TOPIC_NAME: string;
}

// Main worker handler
export default {
  // Handle incoming webhook requests
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    
    // Handle Telegram webhook updates
    if (url.pathname === `/webhook/${env.WEBHOOK_SECRET}`) {
      return this.handleTelegramWebhook(request, env);
    }
    
    // Handle Gmail push notifications
    if (url.pathname === '/gmail-push') {
      return this.handleGmailPush(request, env);
    }
    
    // Handle authentication callbacks from Google OAuth
    if (url.pathname === '/auth/google/callback') {
      return this.handleGoogleAuthCallback(request, env);
    }
    
    // Setup webhook URL (kept for manual setup if needed)
    if (url.pathname === '/setup-webhook') {
      return this.setupWebhook(request, env);
    }
    
    // Check and setup webhook on root path
    if (url.pathname === '/') {
      try {
        const isWebhookSet = await this.checkWebhookStatus(env);
        if (!isWebhookSet) {
          return this.setupWebhook(request, env);
        }
        return new Response('Webhook is already set up', { status: 200 });
      } catch (error) {
        return new Response(`Error setting up webhook: ${error}`, { status: 500 });
      }
    }
    
    return new Response('Not found', { status: 404 });
  },
  
  // Handle scheduled events for checking emails periodically
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(this.checkAllGmailAccounts(env));
  },
  
  // Process Telegram webhook updates
  async handleTelegramWebhook(request: Request, env: Env): Promise<Response> {
    const update = await request.json() as TelegramUpdate;
    
    // Check if this is a message
    if (!update.message) {
      return new Response('OK');
    }
    
    const chatId = update.message.chat.id;
    const text = update.message.text;
    
    // Process commands
    if (text.startsWith('/')) {
      await this.handleCommand(text, chatId, env);
    } else {
      // Regular message
      await this.sendTelegramMessage(chatId, 'To add a Gmail account, use /add command', env);
    }
    
    return new Response('OK');
  },
  
  // Handle bot commands
  async handleCommand(command: string, chatId: number, env: Env): Promise<void> {
    const cmd = command.split(' ')[0].toLowerCase();
    
    switch (cmd) {
      case '/start':
        await this.sendTelegramMessage(
          chatId, 
          'Welcome to Gmail Notification Bot! Use /add to connect your first Gmail account.', 
          env
        );
        break;
        
      case '/add':
        // Generate OAuth URL
        const authUrl = this.generateGoogleAuthUrl(chatId, env);
        await this.sendTelegramMessage(
          chatId, 
          `Please authorize access to your Gmail by clicking this link: ${authUrl}`, 
          env
        );
        break;
        
      case '/list':
        // List connected accounts
        await this.listConnectedAccounts(chatId, env);
        break;
        
      case '/remove':
        // Parse email address from command
        const email = command.split(' ')[1];
        if (email) {
          await this.removeAccount(chatId, email, env);
        } else {
          await this.sendTelegramMessage(
            chatId, 
            'Please specify an email address to remove: /remove your@gmail.com', 
            env
          );
        }
        break;
        
      case '/help':
        await this.sendTelegramMessage(
          chatId,
          'Available commands:\n' +
          '/add - Connect a new Gmail account\n' +
          '/list - Show all connected accounts\n' +
          '/remove email@gmail.com - Remove a specific account\n' +
          '/help - Show this help message',
          env
        );
        break;
        
      default:
        await this.sendTelegramMessage(
          chatId, 
          'Unknown command. Type /help to see available commands.', 
          env
        );
    }
  },
  
  // Generate Google OAuth URL
  generateGoogleAuthUrl(chatId: number, env: Env): string {
    const scope = 'https://www.googleapis.com/auth/gmail.readonly';
    const state = chatId.toString();
    
    return `https://accounts.google.com/o/oauth2/v2/auth?` +
      `client_id=${encodeURIComponent(env.GOOGLE_CLIENT_ID)}` +
      `&redirect_uri=${encodeURIComponent(env.GOOGLE_REDIRECT_URI)}` +
      `&response_type=code` +
      `&scope=${encodeURIComponent(scope)}` +
      `&access_type=offline` +
      `&prompt=consent` +
      `&state=${encodeURIComponent(state)}`;
  },
  
  // Handle Google OAuth callback
  async handleGoogleAuthCallback(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state'); // Contains chat ID
    
    if (!code || !state) {
      return new Response('Missing parameters', { status: 400 });
    }
    
    const chatId = parseInt(state);
    
    try {
      // Exchange code for tokens
      const tokens = await this.exchangeCodeForTokens(code, env);
      
      // Get user email
      const userInfo = await this.getUserEmail(tokens.access_token);
      
      // Store credentials in KV
      await this.storeGmailCredentials(chatId, userInfo.email, tokens, env);
      
      // Setup Gmail push notifications
      await this.setupGmailPushNotifications(userInfo.email, tokens.access_token, env);
      
      // Return success page
      return new Response(
        `<html><body>
          <h1>Success!</h1>
          <p>Your Gmail account ${userInfo.email} has been connected to the Telegram bot.</p>
          <p>You can close this window and return to Telegram.</p>
        </body></html>`,
        {
          headers: { 'Content-Type': 'text/html' },
        }
      );
    } catch (error) {
      const errorMessage = isErrorWithMessage(error) ? error.message : 'An unknown error occurred';
      return new Response(`Error: ${errorMessage}`, { status: 500 });
    }
  },
  
  // Exchange authorization code for access and refresh tokens
  async exchangeCodeForTokens(code: string, env: Env): Promise<any> {
    const response = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        code,
        client_id: env.GOOGLE_CLIENT_ID,
        client_secret: env.GOOGLE_CLIENT_SECRET,
        redirect_uri: env.GOOGLE_REDIRECT_URI,
        grant_type: 'authorization_code',
      }),
    });
    
    if (!response.ok) {
      throw new Error(`Failed to exchange code: ${await response.text()}`);
    }
    
    return response.json();
  },
  
  // Get user email from Google
  async getUserEmail(accessToken: string): Promise<{ email: string }> {
    const response = await fetch('https://www.googleapis.com/gmail/v1/users/me/profile', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });
    
    if (!response.ok) {
      throw new Error(`Failed to get user email: ${await response.text()}`);
    }
    
    return response.json();
  },
  
  // Store Gmail credentials in KV
  async storeGmailCredentials(
    chatId: number, 
    email: string, 
    tokens: { 
      access_token: string, 
      refresh_token: string, 
      expiry_date: number 
    }, 
    env: Env
  ): Promise<void> {
    // Get existing accounts for this user
    const userAccountsStr = await env['telegram-gmail'].get(`user:${chatId}:accounts`);
    let userAccounts = userAccountsStr ? JSON.parse(userAccountsStr) : [];
    
    // Add this account if not already added
    if (!userAccounts.includes(email)) {
      userAccounts.push(email);
      await env['telegram-gmail'].put(`user:${chatId}:accounts`, JSON.stringify(userAccounts));
    }
    
    // Store tokens for this email
    const credentials: GmailCredentials = {
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      expiryDate: tokens.expiry_date || Date.now() + 3600 * 1000,
    };
    
    // Store credentials for this email and map email to user
    await env['telegram-gmail'].put(`email:${email}:credentials`, JSON.stringify(credentials));
    await env['telegram-gmail'].put(`email:${email}:chatId`, chatId.toString());
    
    // Notify user
    await this.sendTelegramMessage(
      chatId,
      `Successfully connected ${email} to receive notifications!`,
      env
    );
  },
  
  // List all connected accounts for a user
  async listConnectedAccounts(chatId: number, env: Env): Promise<void> {
    const userAccountsStr = await env['telegram-gmail'].get(`user:${chatId}:accounts`);
    
    if (!userAccountsStr || JSON.parse(userAccountsStr).length === 0) {
      await this.sendTelegramMessage(
        chatId,
        'You have no Gmail accounts connected. Use /add to connect an account.',
        env
      );
      return;
    }
    
    const accounts = JSON.parse(userAccountsStr);
    await this.sendTelegramMessage(
      chatId,
      `Connected Gmail accounts:\n${accounts.map((email: string) => `- ${email}`).join('\n')}`,
      env
    );
  },
  
  // Remove an account
  async removeAccount(chatId: number, email: string, env: Env): Promise<void> {
    const userAccountsStr = await env['telegram-gmail'].get(`user:${chatId}:accounts`);
    
    if (!userAccountsStr) {
      await this.sendTelegramMessage(chatId, 'You have no connected accounts.', env);
      return;
    }
    
    let accounts = JSON.parse(userAccountsStr);
    
    if (!accounts.includes(email)) {
      await this.sendTelegramMessage(
        chatId,
        `The account ${email} is not connected to your Telegram.`,
        env
      );
      return;
    }
    
    // Remove account from user's list
    accounts = accounts.filter((acc: string) => acc !== email);
    await env['telegram-gmail'].put(`user:${chatId}:accounts`, JSON.stringify(accounts));
    
    // Clean up the credentials and mapping
    await env['telegram-gmail'].delete(`email:${email}:credentials`);
    await env['telegram-gmail'].delete(`email:${email}:chatId`);
    
    await this.sendTelegramMessage(
      chatId,
      `Successfully removed ${email} from your notifications.`,
      env
    );
  },
  
  // Setup Gmail push notifications (watch)
  async setupGmailPushNotifications(email: string, accessToken: string, env: Env): Promise<void> {
    const response = await fetch('https://www.googleapis.com/gmail/v1/users/me/watch', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        topicName: env.GOOGLE_TOPIC_NAME,
        labelIds: ['INBOX'],
      }),
    });
    
    if (!response.ok) {
      throw new Error(`Failed to setup push notifications: ${await response.text()}`);
    }
  },
  
  // Handle Gmail push notifications
  async handleGmailPush(request: Request, env: Env): Promise<Response> {
    const data = await request.json() as GmailPushNotification;
    
    // Extract email from notification data
    const email = data.emailAddress;
    
    if (!email) {
      return new Response('Missing email address', { status: 400 });
    }
    
    // Get user chat ID for this email
    const chatIdStr = await env['telegram-gmail'].get(`email:${email}:chatId`);
    
    if (!chatIdStr) {
      return new Response('No user found for this email', { status: 404 });
    }
    
    const chatId = parseInt(chatIdStr);
    
    // Get credentials for this email
    const credentialsStr = await env['telegram-gmail'].get(`email:${email}:credentials`);
    
    if (!credentialsStr) {
      return new Response('No credentials found for this email', { status: 404 });
    }
    
    const credentials: GmailCredentials = JSON.parse(credentialsStr);
    
    // Refresh token if necessary
    let accessToken = credentials.accessToken;
    if (Date.now() >= credentials.expiryDate) {
      const newTokens = await this.refreshAccessToken(credentials.refreshToken, env);
      accessToken = newTokens.access_token;
      
      // Update stored credentials
      const updatedCredentials: GmailCredentials = {
        accessToken: newTokens.access_token,
        refreshToken: credentials.refreshToken,
        expiryDate: Date.now() + (newTokens.expires_in * 1000),
      };
      
      await env['telegram-gmail'].put(`email:${email}:credentials`, JSON.stringify(updatedCredentials));
    }
    
    // Get unread messages
    const unreadMessages = await this.getUnreadMessages(accessToken);
    
    // Send notification for each unread message
    for (const message of unreadMessages) {
      await this.sendEmailNotification(chatId, email, message, env);
    }
    
    return new Response('OK');
  },
  
  // Refresh access token
  async refreshAccessToken(refreshToken: string, env: Env): Promise<any> {
    const response = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: env.GOOGLE_CLIENT_ID,
        client_secret: env.GOOGLE_CLIENT_SECRET,
        refresh_token: refreshToken,
        grant_type: 'refresh_token',
      }),
    });
    
    if (!response.ok) {
      throw new Error(`Failed to refresh token: ${await response.text()}`);
    }
    
    return response.json();
  },
  
  // Get unread messages
  async getUnreadMessages(accessToken: string): Promise<EmailMessage[]> {
    // Query for unread messages in inbox
    const query = 'is:unread in:inbox';
    const response = await fetch(
      `https://www.googleapis.com/gmail/v1/users/me/messages?q=${encodeURIComponent(query)}`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      }
    );
    
    if (!response.ok) {
      throw new Error(`Failed to get messages: ${await response.text()}`);
    }
    
    const data = await response.json() as GmailMessagesResponse;
    const messages: EmailMessage[] = [];
    
    // Get message details
    if (data.messages && data.messages.length > 0) {
      for (const message of data.messages.slice(0, 5)) { // Limit to 5 messages at a time
        const messageDetails = await this.getMessageDetails(message.id, accessToken);
        messages.push(messageDetails);
      }
    }
    
    return messages;
  },
  
  // Get message details
  async getMessageDetails(messageId: string, accessToken: string): Promise<EmailMessage> {
    const response = await fetch(
      `https://www.googleapis.com/gmail/v1/users/me/messages/${messageId}?format=metadata&metadataHeaders=Subject&metadataHeaders=From`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      }
    );
    
    if (!response.ok) {
      throw new Error(`Failed to get message details: ${await response.text()}`);
    }
    
    const data = await response.json() as GmailMessageDetails;
    
    const subject = data.payload.headers.find((h: { name: string; value: string }) => h.name === 'Subject')?.value || 'No Subject';
    const from = data.payload.headers.find((h: { name: string; value: string }) => h.name === 'From')?.value || 'Unknown Sender';
    
    return {
      id: messageId,
      subject,
      from,
      snippet: data.snippet,
      link: `https://mail.google.com/mail/u/0/#inbox/${messageId}`,
    };
  },
  
  // Send email notification via Telegram
  async sendEmailNotification(chatId: number, email: string, message: EmailMessage, env: Env): Promise<void> {
    const text = `📧 New email in ${email}\n` +
                 `From: ${message.from}\n` +
                 `Subject: ${message.subject}\n\n` +
                 `${message.snippet}...\n\n` +
                 `[Open in Gmail](${message.link})`;
    
    await this.sendTelegramMessage(chatId, text, env, true);
  },
  
  // Send Telegram message (supports Markdown)
  async sendTelegramMessage(
    chatId: number, 
    text: string, 
    env: Env, 
    markdown: boolean = false
  ): Promise<void> {
    const url = `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`;
    
    const params = {
      chat_id: chatId,
      text,
      parse_mode: markdown ? 'MarkdownV2' : undefined,
      disable_web_page_preview: true,
    };
    
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(params),
    });
    
    if (!response.ok) {
      console.error(`Failed to send Telegram message: ${await response.text()}`);
    }
  },
  
  // Check if webhook is already set up
  async checkWebhookStatus(env: Env): Promise<boolean> {
    const response = await fetch(
      `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/getWebhookInfo`
    );
    
    if (!response.ok) {
      throw new Error(`Failed to check webhook status: ${await response.text()}`);
    }
    
    const result = await response.json() as TelegramWebhookInfo;
    return result.ok && result.result.url !== '';
  },
  
  // Setup Telegram webhook
  async setupWebhook(request: Request, env: Env): Promise<Response> {
    const domain = new URL(request.url).hostname;
    const webhookUrl = `https://${domain}/webhook/${env.WEBHOOK_SECRET}`;
    
    const response = await fetch(
      `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/setWebhook`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url: webhookUrl,
          allowed_updates: ['message'],
        }),
      }
    );
    
    const result = await response.json();
    
    return new Response(JSON.stringify(result), {
      headers: { 'Content-Type': 'application/json' },
    });
  },
  
  // Check all Gmail accounts for new emails (fallback for push notifications)
  async checkAllGmailAccounts(env: Env): Promise<void> {
    // Get all emails from KV (listing is limited, so this is simplified)
    const listResult = await env['telegram-gmail'].list({ prefix: 'email:' });
    
    const emailRegex = /email:(.+?):credentials/;
    
    for (const key of listResult.keys) {
      const match = key.name.match(emailRegex);
      
      if (match) {
        const email = match[1];
        
        // Get user chat ID for this email
        const chatIdStr = await env['telegram-gmail'].get(`email:${email}:chatId`);
        
        if (!chatIdStr) {
          continue;
        }
        
        const chatId = parseInt(chatIdStr);
        
        // Get credentials for this email
        const credentialsStr = await env['telegram-gmail'].get(`email:${email}:credentials`);
        
        if (!credentialsStr) {
          continue;
        }
        
        const credentials: GmailCredentials = JSON.parse(credentialsStr);
        
        // Refresh token if necessary
        let accessToken = credentials.accessToken;
        if (Date.now() >= credentials.expiryDate) {
          try {
            const newTokens = await this.refreshAccessToken(credentials.refreshToken, env);
            accessToken = newTokens.access_token;
            
            // Update stored credentials
            const updatedCredentials: GmailCredentials = {
              accessToken: newTokens.access_token,
              refreshToken: credentials.refreshToken,
              expiryDate: Date.now() + (newTokens.expires_in * 1000),
            };
            
            await env['telegram-gmail'].put(`email:${email}:credentials`, JSON.stringify(updatedCredentials));
          } catch (error) {
            const errorMessage = isErrorWithMessage(error) ? error.message : 'An unknown error occurred';
            console.error(`Failed to refresh token for ${email}: ${errorMessage}`);
            continue;
          }
        }
        
        // Get unread messages
        try {
          const unreadMessages = await this.getUnreadMessages(accessToken);
          
          // Send notification for each unread message
          for (const message of unreadMessages) {
            await this.sendEmailNotification(chatId, email, message, env);
          }
        } catch (error) {
          const errorMessage = isErrorWithMessage(error) ? error.message : 'An unknown error occurred';
          console.error(`Failed to check emails for ${email}: ${errorMessage}`);
        }
      }
    }
  },
};