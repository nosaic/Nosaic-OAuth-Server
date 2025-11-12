# OAuth Portal for n8n Customer Success Automations

## Problem
Running n8n automations for clients requires access to their CRMs (Salesforce, HubSpot, etc.). OAuth requires browser sign-in, but clients' accounts aren't signed in on your browser. API keys are less secure and harder to manage.

## Solution
A self-service OAuth portal where clients connect their own accounts via their own browsers.

## How It Works

### Client Flow
1. You send client a unique link: `yoursite.com?client_id=acme-corp`
2. Client visits portal, sees list of integrations to connect
3. Client clicks "Connect Salesforce"
4. Redirects to Salesforce login (client uses their credentials)
5. Client approves access
6. Token saved to your n8n Data Table, encrypted
7. Portal shows "✓ Connected"

### Your Automation Flow
1. n8n workflow triggers (schedule/webhook)
2. Query Data Table by `client_id` and `provider`
3. Decrypt token
4. Use token in API calls to client's Salesforce/HubSpot/etc.

## Architecture
```
Client Browser → Cloudflare Worker → OAuth Provider (Salesforce/HubSpot)
                       ↓
                  n8n Webhook
                       ↓
                  n8n Data Table (stores encrypted tokens)
                       ↓
                  n8n Workflows (read tokens, make API calls)
```

## Components
1. **Cloudflare Worker** (Free, commercial use allowed)
    - Hosts portal HTML
    - Handles OAuth redirects
    - Encrypts tokens
    - Calls n8n webhook to store tokens
2. **n8n Data Table** (You already have)
    - Stores: `client_id`, `provider`, `encrypted_token`, `expires_at`
3. **n8n Webhook Workflow** (Need to create)
    - Receives tokens from Cloudflare Worker
    - Stores in Data Table
    - Returns connection status

## Security
- Tokens encrypted (AES-256-GCM) before storage
- Each client isolated by unique `client_id`
- No passwords stored, only OAuth tokens
- Clients can disconnect anytime

## End Goal
Self-service client onboarding where:
- Clients connect their own tools in 2 minutes
- You never handle their passwords
- Your n8n workflows automatically have access
- Zero monthly cost for infrastructure

## Success Criteria
- Client can connect Salesforce in under 2 minutes
- Token stored encrypted in n8n Data Table
- n8n workflow can retrieve and use token
- Portal shows connection status
- Client can disconnect integration
