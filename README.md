# TimeHereNow Test API - Demo Branch

A demo version of the TimeHereNow API client for testing RODiT authentication.

**Version:** 2005.10.01  
**License:** MIT 
**Author:** Discernible Inc.

## Overview

This is a stripped-down demo branch that runs as a simple Node.js application. All configuration is managed through local config files.

## Quick Start

### Prerequisites

- Node.js 20.x or higher
- npm
- NEAR credentials file (for RODiT authentication)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/cableguard/timeherenow.git
cd timeherenow
```

2. Install dependencies:
```bash
npm install
```

3. Configure your environment:
   - Edit `config/default.json` to set your configuration values
   - Place your NEAR credentials in `timeherenow.json`

4. Create required directories:
```bash
mkdir -p logs data .near-credentials/mainnet selfcerts
```

5. Generate self-signed SSL certificates (for HTTPS):
```bash
openssl req -x509 -newkey rsa:4096 \
  -keyout selfcerts/privkey.pem \
  -out selfcerts/fullchain.pem \
  -days 365 -nodes \
  -subj "/C=US/ST=State/L=City/O=Organization/OU=Department/CN=webhook.timeherenow.com"
```

See `selfcerts/README.md` for more details on client side certificate management.

### Running the Application

Start the application with:
```bash
npm start
```

**For human-readable formatted logs:**
```bash
npm run start:pretty
```

Or for development with auto-reload:
```bash
npm run dev
npm run dev:pretty  # with formatted logs
```

**Direct command with log formatting:**
```bash
node src/app.js | ./format-logs.sh
```

The API will start on the URL and port specified when purchasing the TimeHereNow RODiT at purchases.timeherenow.com

## Configuration

Local configuration is managed through the `config/` directory:
- **`config/default.json`** - Main configuration file with all settings

### Key Configuration Options

Edit `config/default.json` to customize:

```json
{
  "NEAR_CONTRACT_ID": "roditcorp-com.near",
  "RODIT_NEAR_CREDENTIALS_SOURCE": "file",
  "NEAR_CREDENTIALS_FILE_PATH": "/home/icarus40/.near-credentials/mainnet/timeherenow.json",
  "NEAR_RPC_URL": "https://near.lava.build:443",
  "LOG_LEVEL": "info"
}
```

### NEAR Credentials Setup

You need a NEAR credentials file for RODiT authentication.

#### Installing near-cli-rs

1. **Download and install near-cli-rs:**

   **On Linux/macOS:**
   ```bash
   curl --proto '=https' --tlsv1.2 -LsSf https://github.com/near/near-cli-rs/releases/latest/download/near-cli-rs-installer.sh | sh
   ```

   **On Windows:**
   ```powershell
   irm https://github.com/near/near-cli-rs/releases/latest/download/near-cli-rs-installer.ps1 | iex
   ```

   **Using Cargo (Rust package manager):**
   ```bash
   cargo install near-cli-rs
   ```

2. **Verify installation:**
   ```bash
   near --version
   ```

#### Generating Your NEAR Account Credentials

1. **Create or import your NEAR account:**

   **Option A: Create a new account (requires funding):**
   ```bash
   near account create-account fund-myself your-account.near '1 NEAR' \
     use-manually-provided-seed-phrase 'your seed phrase here' \
     network-config mainnet
   ```

   **Option B: Import an existing account:**
   ```bash
   near account import-account using-seed-phrase 'your seed phrase here' \
     network-config mainnet
   ```

   **Option C: Import using private key:**
   ```bash
   near account import-account using-private-key ed25519:YOUR_PRIVATE_KEY_HERE \
     network-config mainnet
   ```

2. **Locate the generated credentials file:**

   After importing/creating your account, near-cli-rs stores credentials at:
   ```
   ~/.near-credentials/mainnet/your-account.near.json
   ```

3. **Copy credentials to the project location:**
   ```bash
   mkdir -p ~/.near-credentials/mainnet
   cp ~/.near-credentials/mainnet/your-account.near.json \
      ~/.near-credentials/mainnet/timeherenow.json
   ```

4. **Update the configuration:**

   Edit `config/default.json` to point to your credentials file:
   ```json
   {
     "NEAR_CREDENTIALS_FILE_PATH": "/home/yourusername/.near-credentials/mainnet/timeherenow.json"
   }
   ```

#### Credentials File Format

The generated credentials file should contain:
```json
{
  "account_id": "your-account.near",
  "public_key": "ed25519:...",
  "private_key": "ed25519:..."
}
```

**Security Note:** Keep your private key secure and never commit it to version control. The `.near-credentials` directory should be in your `.gitignore`.

## Project Structure

```
timeherenow-test/
├── config/                  # Configuration files
│   └──  default.json        # Main configuration
├── src/                     # Source code
│   ├── app.js               # Main application entry point
│   ├── test-system.js       # Test orchestration
│   └── test-modules/        # Individual test suites
├── selfcerts/               # Self-signed SSL certificates
│   ├── privkey.pem          # Private key (gitignored)
│   └── fullchain.pem        # Certificate (gitignored)
└── package.json             # Dependencies and scripts
```

## API Endpoints

For complete API documentation and test-to-API mapping, see:
- **[API Documentation](api-docs/README.md)** - Complete test-to-API mapping, usage examples, and implementation details
- **[API Specification](api-docs/swagger.json)** - OpenAPI 3.0 specification

### Webhook Endpoint
- **POST `/webhook`** - Receives webhook events from TimeHereNow timers

## Logging

### Log Levels

Logs are written to the console

Available log levels: `debug`, `info`, `warn`, `error`

Set the log level in `config/default.json`:
```json
{
  "LOG_LEVEL": "info"
}
```

### Human-Readable Log Formatting

By default, the application outputs JSON logs. For easier reading during development, use the formatted log scripts:

**Using npm scripts (recommended):**
```bash
npm run start:pretty        # Start with formatted logs
npm run dev:pretty          # Dev mode with formatted logs
```

**Direct command:**
```bash
node src/app.js | ./format-logs.sh
```

**Formatted output example:**
```
12:33:49 ℹ [server] RODiT SDK initialized successfully
12:33:49 ℹ [server] HTTPS Server started on port 3444
12:33:51 ℹ [TestRunner] testHealthEndpoint ✓
12:33:52 ✗ [TestRunner] testInvalidEndpoint ✗
```

**Features:**
- Color-coded log levels (ERROR=red, WARN=yellow, INFO=green)
- Symbols for quick scanning (✗ ✓ ⚠ ℹ)
- Timestamps for each log entry
- Component tags for easy filtering
- Test results with pass/fail indicators
- Automatic DEBUG filtering when LOG_LEVEL=info

**Available formatter:**
- `format-logs.sh` - Simple log formatter with no external dependencies (uses bash regex)

## Development

### Scripts

- `npm start` - Run the application in production mode
- `npm run dev` - Run with nodemon for auto-reload during development


## Troubleshooting

### NEAR Credentials Error
Ensure your credentials file exists and is valid JSON at the path specified in `NEAR_CREDENTIALS_FILE_PATH`.


## Support

For issues or questions, contact Discernible Inc at support@discernible.com

---

## RODiT SDK Usage Guide

This section explains how to use the `@rodit/rodit-auth-be` SDK and how the test modules demonstrate real-world usage patterns.

### app.js - Main Application Entry Point

#### Step 1: Import SDK Components
```javascript
const { 
  RoditClient,        // Main client for API requests
  roditManager,       // Manages RODiT configuration
  stateManager,       // Manages tokens, sessions, config
  blockchainService   // Handles blockchain interactions
} = require('@rodit/rodit-auth-be');

// Get SDK utilities (logger, middleware, config)
const tempClient = new RoditClient();
const logger = tempClient.getLogger();           // Structured logging
const loggingmw = tempClient.getLoggingMiddleware(); // Request logging
const config = tempClient.getConfig();           // Configuration utilities
```

#### Step 2: Initialize RoditClient (CRITICAL - Only do this ONCE)
```javascript
async function startServer() {
  // This is the most important step:
  // 1. Loads credentials from environment variables
  // 2. Connects to RODiT blockchain
  // 3. Fetches and verifies RODiT tokens
  // 4. Sets up authentication for all future requests
  roditClient = await RoditClient.create('client');
  
  // Store in app.locals so it's accessible throughout the app
  // This is the "single shared client" pattern for efficiency
  app.locals.roditClient = roditClient;
  
  // Get webhook configuration from RODiT token
  const configOwnRodit = await stateManager.getConfigOwnRodit();
  const webhookUrl = configOwnRodit?.own_rodit?.metadata?.webhook_url;
  
  // Start HTTPS server (RODiT requires HTTPS for webhooks)
  const WEBHOOKPORT = extractPortFromUrl(webhookUrl);
  const httpsOptions = {
    key: fs.readFileSync(path.join(__dirname, '../selfcerts/privkey.pem')),
    cert: fs.readFileSync(path.join(__dirname, '../selfcerts/fullchain.pem'))
  };
  
  server = https.createServer(httpsOptions, app).listen(WEBHOOKPORT);
}
```

#### Step 3: Set up Webhook Handler
```javascript
const webhookHandlerModule = tempClient.getWebhookHandler();
const { createWebhookHandler, WebhookEventHandlerFactory } = webhookHandlerModule;

// Create webhook handler with state management
// This validates webhook authenticity using signatures
const webhookHandler = createWebhookHandler(stateManager);
webhookHandler.applyMiddleware(app, express);
```

#### Step 4: Implement Webhook Endpoint
```javascript
app.post("/webhook", 
  // SDK's authentication middleware verifies webhook signature
  webhookHandler.authenticationMiddleware,
  
  async (req, res) => {
    try {
      // Process webhook event using SDK
      // SDK validates signature and extracts event data
      const event = webhookHandler.processWebhookEvent(req, logContext);
      
      if (event.error) {
        return res.status(400).json({ error: event.error });
      }
      
      // Handle event (different types routed to appropriate handlers)
      const result = await webhookEventHandlerFactory.handleEvent(event, req, res);
      res.status(result.success ? 200 : 400).json(result);
    } catch (error) {
      logger.error("Error processing webhook", { error: error.message });
      res.status(500).json({ error: error.message });
    }
  }
);
```

#### Step 5: Run Tests to Verify Everything Works
```javascript
// After server starts, run comprehensive tests
const testResults = await runSdkTests(app);
// Tests verify: client init, auth flows, sessions, webhooks, API endpoints
```

### Test Modules - What Each One Does

> **💡 Tip:** Each test is linked to specific API endpoints. See [Test-to-API Mapping](docs/TEST-API-MAPPING.md) for complete details.

#### 1. **sdk-tests.js** - Core SDK Functionality
Tests that the SDK initializes and core functions work.

**Key Tests**:
- `testSdkClientInitializationWithSdk`: Verify client is initialized with valid credentials
  - **API:** `POST /api/login` - [Swagger Ref](api-docs/swagger.json#L17-L46)
- `testSdkUtilityFunctionsWithSdk`: Test utility functions (subscription check, config retrieval, metadata)
  - **API:** `GET /health` - [Swagger Ref](api-docs/swagger.json#L311-L329)

**Why it matters**: If these fail, nothing else works. These are the foundation.

#### 2. **authentication-test.js** - Login & JWT Handling
Tests authentication flows and JWT token validation.

**Key Tests**:
- `testLoginEndpoint`: Can users log in and get JWT tokens?
  - **API:** `POST /api/login` - [Swagger Ref](api-docs/swagger.json#L17-L46)
- `testExpiredTokenRejection`: Do expired tokens get rejected?
  - **API:** `POST /api/logout` - [Swagger Ref](api-docs/swagger.json#L48-L64)
- `testJwtClaimIntegrity`: Are JWT claims valid and tamper-proof?
  - **API:** `POST /api/login` - [Swagger Ref](api-docs/swagger.json#L17-L46)

**Why it matters**: Authentication is the security foundation. Users need valid tokens to access APIs.

#### 3. **session-management.js** - Session Lifecycle
Tests session creation, management, and revocation.

**Key Tests**:
- `testSessionManagementWithSdk`: Create and manage sessions
  - **API:** `GET /api/sessions/list_all` - [Swagger Ref](api-docs/swagger.json#L616-L656)
- `testConcurrentSessions`: Multiple users can have concurrent sessions
  - **API:** `GET /api/sessions/list_all` - [Swagger Ref](api-docs/swagger.json#L616-L656)
- `testSessionRevocationEnforcement`: Sessions can be revoked/closed
  - **API:** `POST /api/sessions/revoke` - [Swagger Ref](api-docs/swagger.json#L658-L702)
- `testSessionCleanup`: Old sessions are cleaned up
  - **API:** `POST /api/sessions/cleanup` - [Swagger Ref](api-docs/swagger.json#L704-L738)

**Why it matters**: Real apps need to support multiple simultaneous users with isolated sessions.

#### 4. **timeherenow.js** - API Integration
Tests that API endpoints work with SDK authentication.

**Key Tests**:
- `testHealthEndpoint`: Is API healthy?
  - **API:** `GET /health` - [Swagger Ref](api-docs/swagger.json#L311-L329)
- `testTimezoneList`: Can we fetch timezone data?
  - **API:** `POST /api/timezone` - [Swagger Ref](api-docs/swagger.json#L110-L119)
- `testTimeByIpFallback`: Does IP geolocation work?
  - **API:** `POST /api/ip` - [Swagger Ref](api-docs/swagger.json#L209-L240)
- `testSignHashValidation`: Can we sign hashes using RODiT?
  - **API:** `POST /api/sign/hash` - [Swagger Ref](api-docs/swagger.json#L242-L274)
- `testReliabilityMultiRequest`: Multiple requests work reliably
  - **API:** `POST /api/timezone/time` - [Swagger Ref](api-docs/swagger.json#L147-L181)
- `testPerformanceLatency`: API responds within acceptable time
  - **API:** `POST /api/timezone/time` - [Swagger Ref](api-docs/swagger.json#L147-L181)

**Why it matters**: Shows how to integrate SDK authentication with real API endpoints and data retrieval.

#### 5. **timer-webhook.js** - Webhook Integration
Tests webhook delivery and event handling.

**Key Tests**:
- `testTimerScheduleBasic`: Can we schedule timers?
  - **API:** `POST /api/timers/schedule` - [Swagger Ref](api-docs/swagger.json#L276-L309)
- `testTimerWebhookDelivery`: Are webhooks actually delivered?
  - **API:** `POST /api/timers/schedule` + Webhook delivery - [Swagger Ref](api-docs/swagger.json#L276-L309)
- `testTimerPayloadEcho`: Is webhook payload intact?
  - **API:** `POST /api/timers/schedule` - [Swagger Ref](api-docs/swagger.json#L276-L309)
- `testTimerBlockchainTimestamps`: Are timestamps blockchain-based?
  - **API:** `POST /api/timers/schedule` - [Swagger Ref](api-docs/swagger.json#L276-L309)
- `testTimerInvalidDelayTooSmall/Large`: Input validation works
  - **API:** `POST /api/timers/schedule` - [Swagger Ref](api-docs/swagger.json#L276-L309)

**Why it matters**: Webhooks are how RODiT notifies you of events. This tests the entire event delivery pipeline.

#### 6. **test-utils.js** - Testing Utilities
Helper functions used by all tests.

**Key Functions**:
- `runTest()`: Execute test and capture results
- `captureTestData()`: Record test results for analysis
- `decodeJwt()`: Inspect JWT token claims
- `waitForWebhook()`: Wait for webhook with timeout
- `getRoditClientForTest()`: Create test client instances

**Why it matters**: Provides consistent testing framework and utilities for all tests.

### SDK Usage Patterns to Learn

#### Pattern 1: Client Initialization (Do Once)
```javascript
// Initialize once at app startup
const client = await RoditClient.create('client');
app.locals.roditClient = client; // Store for reuse

// Reuse throughout app
const client = app.locals.roditClient;
```

#### Pattern 2: Making Authenticated Requests
```javascript
const client = app.locals.roditClient;

// SDK automatically adds authentication headers
const response = await client.request('GET', '/api/health');
const data = await client.request('POST', '/api/timers/schedule', {
  delay_seconds: 5,
  payload: { test_id: 'abc123' }
});
```

#### Pattern 3: Accessing State
```javascript
// Get configuration
const config = await stateManager.getConfigOwnRodit();

// Get JWT token
const token = await stateManager.getJwtToken();

// Get session data
const sessionData = await stateManager.getSessionData(sessionId);
```

#### Pattern 4: Webhook Handling
```javascript
// Set up webhook handler
const webhookHandler = createWebhookHandler(stateManager);
webhookHandler.applyMiddleware(app, express);

// Process incoming webhook
const event = webhookHandler.processWebhookEvent(req, logContext);
const result = await webhookEventHandlerFactory.handleEvent(event, req, res);
```

#### Pattern 5: Error Handling
```javascript
try {
  const result = await client.request('GET', '/api/endpoint');
  // Process result
} catch (error) {
  logger.error('API request failed', { error: error.message });
  // Handle error appropriately
}
```

### How to Use These Tests as Learning Resources

#### For Beginners
1. Read `src/app.js` - Understand basic setup
2. Study `src/test-modules/sdk-tests.js` - Learn SDK initialization
3. Read `src/test-modules/authentication-test.js` - Learn login flows

#### For Intermediate Users
1. Study `src/test-modules/session-management.js` - Learn session handling
2. Explore `src/test-modules/timeherenow.js` - Learn API integration
3. Review `src/test-modules/test-utils.js` - Learn testing patterns

#### For Advanced Users
1. Deep dive `src/test-modules/timer-webhook.js` - Understand webhooks
2. Study webhook architecture and event handling
3. Learn blockchain timestamp integration

### Key Takeaways

✅ **Initialize RoditClient once** - Store in app.locals, reuse everywhere  
✅ **Use SDK's request() method** - Automatically handles authentication  
✅ **Access state via stateManager** - Get tokens, config, session data  
✅ **Handle webhooks securely** - Use SDK's webhook handler for validation  
✅ **Always wrap in try-catch** - SDK calls can fail, handle errors gracefully  
✅ **Use structured logging** - SDK provides logger for consistent logging  
✅ **Verify tokens** - Always validate JWT claims and signatures  
✅ **Test thoroughly** - Use these tests as templates for your own tests

---

## License

MIT
