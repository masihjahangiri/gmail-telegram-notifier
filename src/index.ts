interface Env {
  TELEGRAM_TOKEN: string;
  TELEGRAM_CHAT_ID: string;
  ACCESS_KEY: string;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // Only allow GET requests
    if (request.method !== 'GET') {
      return new Response('Method not allowed', { status: 405 });
    }

    try {
      // Parse URL parameters
      const url = new URL(request.url);
      const message = url.searchParams.get('message');
      const key = url.searchParams.get('key');

      // Validate required parameters
      if (!message) {
        return new Response('Message parameter is required', { status: 400 });
      }

      // Check access key if configured
      if (env.ACCESS_KEY && key !== env.ACCESS_KEY) {
        return new Response('Invalid access key', { status: 401 });
      }

      // Prepare Telegram API request
      const telegramUrl = `https://api.telegram.org/bot${env.TELEGRAM_TOKEN}/sendMessage`;
      const telegramResponse = await fetch(telegramUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          chat_id: env.TELEGRAM_CHAT_ID,
          text: message,
          parse_mode: 'HTML',
        }),
      });

      if (!telegramResponse.ok) {
        const error = await telegramResponse.text();
        return new Response(`Failed to send message: ${error}`, { status: 500 });
      }

      return new Response('Message sent successfully', { status: 200 });
    } catch (error) {
      return new Response(`Error: ${error.message}`, { status: 500 });
    }
  },
}; 