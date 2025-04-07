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

// Telegram Update types
export interface TelegramUpdate {
  message?: TelegramMessage;
}

export interface TelegramMessage {
  chat: {
    id: number;
  };
  text: string;
}

// Gmail API Response types
export interface GmailMessagesResponse {
  messages?: Array<{
    id: string;
  }>;
}

export interface GmailMessageDetails {
  payload: {
    headers: Array<{
      name: string;
      value: string;
    }>;
  };
  snippet: string;
}

export interface GmailPushNotification {
  emailAddress: string;
}

// Error type for better error handling
export interface ErrorWithMessage {
  message: string;
}

// Type guard for ErrorWithMessage
export function isErrorWithMessage(error: unknown): error is ErrorWithMessage {
  return (
    typeof error === 'object' &&
    error !== null &&
    'message' in error &&
    typeof (error as Record<string, unknown>).message === 'string'
  );
}

export interface TelegramWebhookInfo {
  ok: boolean;
  result: {
    url: string;
    has_custom_certificate: boolean;
    pending_update_count: number;
    last_error_date?: number;
    last_error_message?: string;
    max_connections?: number;
    ip_address?: string;
  };
}