// Types for Gmail Notification Bot

// Email message structure
export interface EmailMessage {
  id: string;
  subject: string;
  from: string;
  snippet: string;
  link: string;
}

// Gmail credentials structure
export interface GmailCredentials {
  accessToken: string;
  refreshToken: string;
  expiryDate: number;
}
