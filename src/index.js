import { getAssetFromKV } from '@cloudflare/kv-asset-handler';

// === OAuth Provider Configuration ===
class OAuthProvider {
	constructor(name, authUrl, tokenUrl, scopes = []) {
		this.name = name;
		this.authUrl = authUrl;
		this.tokenUrl = tokenUrl;
		this.scopes = scopes;
	}

	getClientId(env) {
		return env[`${this.name.toUpperCase()}_CLIENT_ID`];
	}

	getClientSecret(env) {
		return env[`${this.name.toUpperCase()}_CLIENT_SECRET`];
	}

	buildAuthUrl(clientId, redirectUri, state) {
		const url = new URL(this.authUrl);
		url.searchParams.set('client_id', clientId);
		url.searchParams.set('redirect_uri', redirectUri);
		url.searchParams.set('response_type', 'code');
		url.searchParams.set('state', state);

		if (this.scopes.length > 0) {
			url.searchParams.set('scope', this.scopes.join(' '));
		}

		return url.toString();
	}

	async exchangeCodeForToken(code, redirectUri, clientId, clientSecret) {
		const response = await fetch(this.tokenUrl, {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({
				grant_type: 'authorization_code',
				code: code,
				redirect_uri: redirectUri,
				client_id: clientId,
				client_secret: clientSecret,
			}),
		});

		const data = await response.json();

		if (!response.ok) {
			throw new Error(data.error_description || data.error || 'Token exchange failed');
		}

		return data;
	}
}

class ProviderRegistry {
	constructor() {
		this.providers = new Map();
	}
	register(id, provider) {
		this.providers.set(id, provider);
	}
	get(id) {
		return this.providers.get(id);
	}
	has(id) {
		return this.providers.has(id);
	}
}

// Initialize providers
const registry = new ProviderRegistry();

registry.register(
	'salesforce',
	new OAuthProvider(
		'salesforce',
		'https://login.salesforce.com/services/oauth2/authorize',
		'https://login.salesforce.com/services/oauth2/token',
		['api', 'refresh_token'],
	),
);

registry.register(
	'hubspot',
	new OAuthProvider('hubspot', 'https://app.hubspot.com/oauth/authorize', 'https://api.hubapi.com/oauth/v1/token', [
		'crm.objects.contacts.read',
		'crm.objects.companies.read',
	]),
);

registry.register(
	'intercom',
	new OAuthProvider('intercom', 'https://app.intercom.com/oauth', 'https://api.intercom.io/auth/eagle/token', []),
);

registry.register(
	'zoho',
	new OAuthProvider('zoho', 'https://accounts.zoho.com/oauth/v2/auth', 'https://accounts.zoho.com/oauth/v2/token', [
		'ZohoCRM.modules.ALL',
	]),
);

// === Encryption Utilities ===
class Encryptor {
	constructor(encryptionKey) {
		this.key = encryptionKey;
	}

	async encrypt(text) {
		const encoder = new TextEncoder();
		const data = encoder.encode(text);

		const cryptoKey = await crypto.subtle.importKey('raw', this.hexToBytes(this.key), { name: 'AES-GCM' }, false, ['encrypt']);

		const iv = crypto.getRandomValues(new Uint8Array(12));
		const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, data);

		return this.bytesToHex(iv) + ':' + this.bytesToHex(new Uint8Array(encrypted));
	}

	hexToBytes(hex) {
		const bytes = new Uint8Array(hex.length / 2);
		for (let i = 0; i < hex.length; i += 2) {
			bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
		}
		return bytes;
	}

	bytesToHex(bytes) {
		return Array.from(bytes)
			.map((b) => b.toString(16).padStart(2, '0'))
			.join('');
	}
}

// === State Manager ===
class StateManager {
	static generate(clientId, provider) {
		const state = crypto.randomUUID();
		const payload = { state, clientId, provider };
		return btoa(JSON.stringify(payload));
	}

	static parse(stateParam) {
		try {
			return JSON.parse(atob(stateParam));
		} catch {
			return null;
		}
	}
}

// === n8n Storage ===
class N8nStorage {
	constructor(webhookUrl, webhookKey) {
		this.webhookUrl = webhookUrl;
		this.webhookKey = webhookKey;
	}

	async storeToken(clientId, provider, tokens, encryptor) {
		const encryptedAccessToken = await encryptor.encrypt(tokens.access_token);
		const encryptedRefreshToken = tokens.refresh_token ? await encryptor.encrypt(tokens.refresh_token) : null;

		const expiresAt = tokens.expires_in ? new Date(Date.now() + tokens.expires_in * 1000).toISOString() : null;

		const response = await fetch(this.webhookUrl, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${this.webhookKey}`,
			},
			body: JSON.stringify({
				action: 'store_token',
				client_id: clientId,
				provider: provider,
				access_token: encryptedAccessToken,
				refresh_token: encryptedRefreshToken,
				expires_at: expiresAt,
				updated_at: new Date().toISOString(),
			}),
		});

		if (!response.ok) {
			throw new Error('Failed to store token in n8n');
		}

		return await response.json();
	}
}

// === Router ===
class Router {
	constructor(env) {
		this.env = env;
		this.encryptor = new Encryptor(env.ENCRYPTION_KEY);
		this.storage = new N8nStorage(env.N8N_WEBHOOK_URL, env.N8N_WEBHOOK_KEY);
		this.corsHeaders = {
			'Access-Control-Allow-Origin': '*',
			'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
			'Access-Control-Allow-Headers': 'Content-Type',
		};
	}

	async handleRequest(request) {
		const url = new URL(request.url);
		const path = url.pathname;

		if (request.method === 'OPTIONS') {
			return new Response(null, { headers: this.corsHeaders });
		}

		// Route: Initiate OAuth
		if (path.startsWith('/auth/')) {
			return this.handleAuth(url, path);
		}

		// Route: OAuth Callback
		if (path.startsWith('/callback/')) {
			return this.handleCallback(url, path);
		}

		// Route: Serve static assets
		return this.handleStatic(request);
	}

	async handleAuth(url, path) {
		const providerId = path.split('/')[2];
		const clientId = url.searchParams.get('client_id');

		if (!clientId) {
			return new Response('client_id required', { status: 400 });
		}

		const provider = registry.get(providerId);
		if (!provider) {
			return new Response('Unknown provider', { status: 400 });
		}

		const state = StateManager.generate(clientId, providerId);
		const redirectUri = `${url.origin}/callback/${providerId}`;
		const authUrl = provider.buildAuthUrl(provider.getClientId(this.env), redirectUri, state);

		return Response.redirect(authUrl, 302);
	}

	async handleCallback(url, path) {
		const providerId = path.split('/')[2];
		const code = url.searchParams.get('code');
		const stateParam = url.searchParams.get('state');
		const error = url.searchParams.get('error');

		if (error) {
			return Response.redirect(`${this.env.FRONTEND_URL}?error=${error}`, 302);
		}

		const state = StateManager.parse(stateParam);
		if (!state) {
			return new Response('Invalid state', { status: 400 });
		}

		const provider = registry.get(providerId);
		if (!provider) {
			return new Response('Unknown provider', { status: 400 });
		}

		try {
			const redirectUri = `${url.origin}/callback/${providerId}`;
			const tokens = await provider.exchangeCodeForToken(
				code,
				redirectUri,
				provider.getClientId(this.env),
				provider.getClientSecret(this.env),
			);

			await this.storage.storeToken(state.clientId, providerId, tokens, this.encryptor);

			return Response.redirect(`${this.env.FRONTEND_URL}?success=true&provider=${providerId}`, 302);
		} catch (err) {
			return Response.redirect(`${this.env.FRONTEND_URL}?error=${encodeURIComponent(err.message)}`, 302);
		}
	}

	async handleStatic(request) {
		try {
			return await getAssetFromKV(
				{
					request,
					waitUntil: (promise) => Promise.resolve(promise),
				},
				{
					ASSET_NAMESPACE: this.env.__STATIC_CONTENT,
					ASSET_MANIFEST: JSON.parse(this.env.__STATIC_CONTENT_MANIFEST),
				},
			);
		} catch (e) {
			return new Response('Not found', { status: 404 });
		}
	}
}

// === main ===
export default {
	async fetch(request, env) {
		const router = new Router(env);
		return router.handleRequest(request);
	},
};
