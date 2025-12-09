import { Context, Next } from 'hono';
import { ENV } from '../types';

export async function authMiddleware(c: Context<{ Bindings: ENV; Variables: { userId: string; user: any } }>, next: Next) {
	const apiKey = c.req.header('X-API-Key');
	const env = c.env;

	if (!apiKey || apiKey !== env.API_KEY) {
		return c.json({ error: 'Unauthorized' }, 401);
	}

	// Set user context for single-user mode
	c.set('userId', 'single-user');
	c.set('user', {
		id: 'single-user',
		email: 'self-hosted@pasteproof.local',
		subscription_tier: 'premium', // Self-hosted gets premium features
		subscription_status: 'active',
	});

	await next();
}

