# TimeHereNow Test API - Demo Branch

![TimeHereNow Banner](banner.png)

A demo version of the TimeHereNow API client for testing RODiT authentication.

**Version:** 2025.11.08  
**API Version:** 20251023  
**License:** MIT  
**Author:** Discernible Inc.

## Overview

This is a stripped-down demo branch that runs as a simple Node.js application. All configuration is managed through local config files.

**Key Features:**
- 🔗 NEAR blockchain-based time source (NOT system/NTP)
- 🔐 RODiT token authentication with JWT
- ⏰ Blockchain-timestamped webhook timers
- 🌍 Complete IANA timezone database support
- 📊 Performance and system metrics
- 🤖 Model Context Protocol (MCP) for AI integration
- ✅ 100% API test coverage (20/20 endpoints)

## Quick Start

Follow these steps in order to set up and run the TimeHereNow API:

### Step 1: Clone the Repository

```bash
git clone https://github.com/cableguard/timeherenow.git
cd timeherenow
```

### Step 2: Install Dependencies

**Prerequisites:**
- Node.js 20.x or higher
- npm

```bash
npm install
```

### Step 3: Install near-cli-rs

Install the NEAR CLI tool to manage your NEAR account credentials.

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

**Verify installation:**
```bash
near --version
```

### Step 4: Generate NEAR Implicit Account

Create a NEAR implicit account for RODiT authentication. See the [NEAR Credentials Setup](#near-credentials-setup) section for detailed instructions.

**Quick command:**
```bash
near account import-account using-seed-phrase 'your seed phrase here' \
  network-config mainnet
```

Your credentials will be stored at:
```
~/.near-credentials/mainnet/YOUR_IMPLICIT_ACCOUNT_ID.json
```

### Step 5: Configure the Application

Edit `config/default.json` to set your configuration:

```json
{
  "NEAR_CONTRACT_ID": "roditcorp-com.near",
  "RODIT_NEAR_CREDENTIALS_SOURCE": "file",
  "NEAR_CREDENTIALS_FILE_PATH": "/FULL_PATH/.near-credentials/mainnet/timeherenow.json",
  "NEAR_RPC_URL": "https://near.lava.build:443",
  "LOG_LEVEL": "info"
}
```

**Important:** Update `NEAR_CREDENTIALS_FILE_PATH` with the full path to your credentials file.

### Step 6: Create Required Directories

```bash
mkdir -p logs data .near-credentials/mainnet selfcerts
```

### Step 7: Generate Self-Signed SSL Certificates

Generate SSL certificates for HTTPS (required for webhooks):

```bash
openssl req -x509 -newkey rsa:4096 \
  -keyout selfcerts/privkey.pem \
  -out selfcerts/fullchain.pem \
  -days 365 -nodes \
  -subj "/C=US/ST=State/L=City/O=Organization/OU=Department/CN=YOUR_DOMAIN_OR_IP"
```

**Certificate Details:**
- **privkey.pem**: Private key (4096-bit RSA)
- **fullchain.pem**: Self-signed certificate
- **Common Name (CN)**: YOUR_DOMAIN_OR_IP (use your domain or public IP)
- **Validity**: 365 days from creation date

**Important:** The CN (Common Name) should match the URL you'll use to receive webhooks.

### Step 8: Purchase a TimeHereNow RODiT

Visit [https://purchase.timeherenow.com](https://purchase.timeherenow.com) to purchase your RODiT token.

**You'll need:**
- A NEAR-compatible wallet (MyNearWallet, Meteor Wallet, etc.)
- Your NEAR implicit account from Step 4
- Your webhook URL (matching the CN from Step 7)

See the [Purchasing a TimeHereNow RODiT](#purchasing-a-timeherenow-rodit) section for detailed instructions.

### Step 9: Test the API

Start the application:
```bash
npm start
```

**For human-readable formatted logs:**
```bash
npm run start:pretty
```

**Or for development with auto-reload:**
```bash
npm run dev
npm run dev:pretty  # with formatted logs
```

The API will start on the URL and port specified in your RODiT metadata.

**Run the test suite:**
```bash
npm test
```

This will validate all API endpoints and verify your setup is working correctly.

---

## Detailed Setup Instructions

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
  "NEAR_CREDENTIALS_FILE_PATH": "/FULL_PATH/.near-credentials/mainnet/timeherenow.json",
  "NEAR_RPC_URL": "https://near.lava.build:443",
  "LOG_LEVEL": "info"
}
```

### NEAR Credentials Setup

Before purchasing your RODiT, you need to set up NEAR credentials for authentication.

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
  "account_id": "IMPLICIT_ACCOUNT_ID",
  "public_key": "ed25519:...",
  "private_key": "ed25519:..."
}
```

**Security Note:** Keep your private key secure and never commit it to version control. The `.near-credentials` directory should be in your `.gitignore`.


### Purchasing a TimeHereNow RODiT

Before you can use this API, you need to purchase a TimeHereNow RODiT token on the NEAR blockchain.

#### What is a RODiT?

A RODiT (Rights On Distributed Infrastructure Token) is a blockchain-based access token that grants you the right to use the TimeHereNow API. Your RODiT token contains:
- Your API endpoint URL and port
- Webhook configuration
- Access permissions and subscription details
- Authentication credentials

#### How to Purchase

1. **Visit the purchase page:**
   ```
   https://purchase.timeherenow.com
   ```

2. **Connect your NEAR wallet:**
   - You'll need a NEAR-compatible wallet such as:
     - **NEAR Wallet** (wallet.near.org)
     - **MyNearWallet** (mynearwallet.com)
     - **Meteor Wallet** (meteorwallet.app)
     - **Sender Wallet** (senderwallet.io)
     - **HERE Wallet** (herewallet.app)

3. **Complete the purchase:**
   - Follow the on-screen instructions to purchase your RODiT
   - The RODiT will be minted to your NEAR account
   - You'll receive your API endpoint URL and configuration details

4. **Note your credentials:**
   - After purchase, you'll receive:
     - Your unique API endpoint URL (e.g., `https://webhook.timeherenow.com:3444`)
     - Your NEAR account ID (implicit account)
     - Configuration metadata for your RODiT

#### Important Notes

- **One RODiT per account:** Each NEAR account can hold one TimeHereNow RODiT
- **Implicit accounts recommended:** Use a NEAR implicit account for easier credential management
- **Webhook URL:** Your RODiT metadata includes your webhook URL - this is where timer events will be delivered
- **API endpoint:** The URL and port specified in your RODiT is where your API instance should run

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

### Complete API Reference

The TimeHereNow API provides comprehensive time, timezone, authentication, and webhook capabilities. All endpoints are fully documented and tested.

**API Documentation:**
- **[API Specification](api-docs/swagger.json)** - OpenAPI 3.0 specification
- **Test Coverage:** 100% (20/20 endpoints)

### Authentication & Session Management

#### `POST /api/login`
- **Capability:** User Authentication
- **Auth Required:** No
- **Purpose:** Authenticate with RODiT token and obtain JWT session token
- **Tests:** `testLoginEndpoint`, `testJwtClaimIntegrity`

#### `POST /api/logout`
- **Capability:** Session Termination
- **Auth Required:** Yes (Bearer JWT)
- **Purpose:** Terminate session and invalidate token
- **Tests:** `testLogoutEndpoint`, `testExpiredTokenRejection`

#### `GET /api/sessions/list_all`
- **Capability:** Session Listing
- **Auth Required:** Yes (Admin)
- **Purpose:** List all active sessions
- **Tests:** `testSessionManagementWithSdk`, `testConcurrentSessions`

#### `POST /api/sessions/revoke`
- **Capability:** Session Revocation
- **Auth Required:** Yes (Admin)
- **Purpose:** Terminate specific session by ID
- **Tests:** `testSessionRevocationEnforcement`

#### `POST /api/sessions/cleanup`
- **Capability:** Session Cleanup
- **Auth Required:** Yes
- **Purpose:** Remove expired sessions
- **Tests:** `testSessionCleanup`

---

### Time & Timezone APIs

#### `GET /health`
- **Capability:** Health Check
- **Auth Required:** No
- **Purpose:** Monitor API and NEAR blockchain connectivity
- **Tests:** `testHealthEndpoint`
- **Returns:** Server health, blockchain connection status, blockchain time

#### `POST /api/timezone`
- **Capability:** Timezone Listing
- **Auth Required:** Yes
- **Purpose:** Retrieve complete IANA timezone database
- **Tests:** `testTimezoneList`

#### `POST /api/timezone/area`
- **Capability:** Timezone Filtering
- **Auth Required:** Yes
- **Purpose:** Filter timezones by continent/region (e.g., "America", "Europe")
- **Tests:** `testTimezoneByArea`

#### `POST /api/timezone/time`
- **Capability:** Blockchain Time by Timezone
- **Auth Required:** Yes
- **Purpose:** Returns NEAR blockchain-sourced time for specified timezone
- **Tests:** `testTimeByTimezone`, `testReliabilityMultiRequest`, `testPerformanceLatency`
- **Key Feature:** All timestamps from NEAR blockchain at 5Hz polling (200ms intervals), NOT system/NTP time

#### `POST /api/timezones/by-country`
- **Capability:** Country Timezone Lookup
- **Auth Required:** Yes
- **Purpose:** Get timezones for specific countries (ISO 3166-1 alpha-2)
- **Tests:** `testTimezonesByCountry`

#### `POST /api/ip`
- **Capability:** IP-based Time Lookup
- **Auth Required:** Yes
- **Purpose:** Determine timezone from IP and return blockchain time
- **Tests:** `testTimeByIpFallback`
- **Features:** IP geolocation (geoip-lite), IPv4/IPv6 support, automatic timezone detection

---

### Blockchain Features

#### `POST /api/sign/hash`
- **Capability:** Blockchain Timestamping
- **Auth Required:** Yes
- **Purpose:** Create tamper-proof timestamped signatures
- **Tests:** `testSignHashValidation`
- **Use Case:** Proves a hash existed at or before the blockchain timestamp
- **Format:** `hash + timestamp + time_diff + public_key` (Base64url encoded)

---

### Timer & Webhook System

#### `POST /api/timers/schedule`
- **Capability:** Timer Scheduling
- **Auth Required:** Yes
- **Purpose:** Schedule blockchain-timed webhook delivery
- **Delay Range:** 1 second to 48 hours
- **Tests:** `testTimerScheduleBasic`, `testTimerWebhookDelivery`, `testTimerPayloadEcho`, `testTimerBlockchainTimestamps`, `testTimerInvalidDelayTooSmall`, `testTimerInvalidDelayTooLarge`
- **Features:**
  - ULID timer ID generation
  - Blockchain timestamps (scheduled_at, execute_at, fired_at)
  - Automatic persistence (hourly saves)
  - Late timers skipped on restore (never sent late)
  - Payload preservation through delivery

#### `POST /webhook`
- **Capability:** Webhook Event Reception
- **Auth Required:** Signature validation
- **Purpose:** Receive webhook events from TimeHereNow timers
- **Features:** SDK signature validation, event type routing

---

### Metrics & Monitoring

#### `GET /api/metrics`
- **Capability:** Performance Metrics
- **Auth Required:** Yes
- **Purpose:** Retrieve request counts and performance data
- **Tests:** `testMetricsEndpoint`
- **Returns:** Request count, error count, requests per minute, load level, active sessions

#### `GET /api/metrics/system`
- **Capability:** System Metrics
- **Auth Required:** Yes
- **Purpose:** Monitor CPU, memory, and uptime
- **Tests:** `testSystemMetrics`
- **Returns:** CPU usage, memory used/total, system uptime

#### `POST /api/metrics/reset`
- **Capability:** Metrics Management
- **Auth Required:** Yes (Admin with entityAndProperties scope)
- **Purpose:** Reset metric counters
- **Tests:** `testMetricsReset`

---

### Model Context Protocol (MCP)

#### `GET /mcp/resources`
- **Capability:** MCP Resource Discovery
- **Auth Required:** No (Public for AI discovery)
- **Purpose:** AI discovery of available API resources
- **Tests:** `testMcpResources`
- **Features:** Resource listing, pagination, metadata

#### `GET /mcp/resource/{uri}`
- **Capability:** MCP Resource Access
- **Auth Required:** No (Public for AI discovery)
- **Purpose:** Retrieve specific resource content for AI agents
- **Tests:** `testMcpResourceRetrieval`

#### `GET /mcp/schema`
- **Capability:** MCP Schema
- **Auth Required:** No (Public for AI discovery)
- **Purpose:** Provide API schema for AI agent integration
- **Tests:** `testMcpSchema`

---

### API Coverage Summary

| Category | Endpoints | Tests | Coverage |
|----------|-----------|-------|----------|
| Authentication | 2 | 4 | 100% |
| Session Management | 3 | 4 | 100% |
| Timezone Operations | 4 | 4 | 100% |
| Time Retrieval | 2 | 2 | 100% |
| Blockchain Features | 1 | 1 | 100% |
| Timer/Webhook | 1 | 6 | 100% |
| Metrics | 3 | 3 | 100% |
| MCP | 3 | 3 | 100% |
| Health | 1 | 1 | 100% |

**Total:** 20 endpoints, 100% coverage

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

## Test Suite & API Validation

### Test-to-API Capability Mapping

The test suite provides comprehensive validation of all API endpoints with full traceability. Each test is mapped to specific API capabilities and documented in detail.

**Test Coverage:** 100% (20/20 endpoints tested)

### Test Modules Overview

#### 1. **sdk-tests.js** - Core SDK Functionality
Tests SDK initialization and core functions.

**Key Tests:**
- `testSdkClientInitializationWithSdk` - Verify client initialization with valid credentials
  - **API:** `POST /api/login`
- `testSdkUtilityFunctionsWithSdk` - Test utility functions (subscription check, config retrieval)
  - **API:** `GET /health`

#### 2. **authentication-test.js** - Login & JWT Handling
Tests authentication flows and JWT token validation.

**Key Tests:**
- `testLoginEndpoint` - User login and JWT token generation
  - **API:** `POST /api/login`
- `testExpiredTokenRejection` - Expired token rejection
  - **API:** `POST /api/logout`
- `testJwtClaimIntegrity` - JWT claims validation and tamper-proofing
  - **API:** `POST /api/login`

#### 3. **session-management.js** - Session Lifecycle
Tests session creation, management, and revocation.

**Key Tests:**
- `testSessionManagementWithSdk` - Create and manage sessions
  - **API:** `GET /api/sessions/list_all`
- `testConcurrentSessions` - Multiple concurrent user sessions
  - **API:** `GET /api/sessions/list_all`
- `testSessionRevocationEnforcement` - Session revocation
  - **API:** `POST /api/sessions/revoke`
- `testSessionCleanup` - Expired session cleanup
  - **API:** `POST /api/sessions/cleanup`

#### 4. **timeherenow.js** - API Integration
Tests API endpoints with SDK authentication.

**Key Tests:**
- `testHealthEndpoint` - API health check
  - **API:** `GET /health`
- `testTimezoneList` - Fetch timezone data
  - **API:** `POST /api/timezone`
- `testTimeByIpFallback` - IP geolocation
  - **API:** `POST /api/ip`
- `testSignHashValidation` - Sign hashes using RODiT
  - **API:** `POST /api/sign/hash`
- `testReliabilityMultiRequest` - Concurrent request handling
  - **API:** `POST /api/timezone/time`
- `testPerformanceLatency` - API response time
  - **API:** `POST /api/timezone/time`

#### 5. **timer-webhook.js** - Webhook Integration
Tests webhook delivery and event handling.

**Key Tests:**
- `testTimerScheduleBasic` - Schedule timers
  - **API:** `POST /api/timers/schedule`
- `testTimerWebhookDelivery` - Webhook delivery verification
  - **API:** `POST /api/timers/schedule` + Webhook delivery
- `testTimerPayloadEcho` - Payload integrity through delivery
  - **API:** `POST /api/timers/schedule`
- `testTimerBlockchainTimestamps` - Blockchain timestamp validation
  - **API:** `POST /api/timers/schedule`
- `testTimerInvalidDelayTooSmall/Large` - Input validation
  - **API:** `POST /api/timers/schedule`

#### 6. **test-utils.js** - Testing Utilities
Helper functions for all tests.

**Key Functions:**
- `runTest()` - Execute test and capture results
- `captureTestData()` - Record test results with API capability info
- `decodeJwt()` - Inspect JWT token claims
- `waitForWebhook()` - Wait for webhook with timeout
- `getRoditClientForTest()` - Create test client instances

### Running Tests

```bash
# Run all tests
npm test

# Run with formatted logs
npm run start:pretty

# Generate API coverage report
npm run coverage
```

### Test Results Format

Tests automatically include API capability information:

```json
{
  "testName": "testTimerScheduleBasic",
  "success": true,
  "testInfo": {
    "apiCapability": {
      "api_endpoint": "POST /api/timers/schedule",
      "capability": "Timer Scheduling",
      "requires_auth": true,
      "swagger_ref": "#/paths/~1timers~1schedule/post"
    }
  }
}
```

### Key API Features Validated

#### 🔗 NEAR Blockchain Integration
- All time values sourced from NEAR blockchain (NOT system/NTP time)
- 5Hz polling (200ms intervals) with cached timestamps
- Blockchain time granularity: ~500-600ms (block interval)
- Returns HTTP 503 if blockchain time unavailable

#### 🔐 Security & Authentication
- RODiT token-based authentication
- JWT token generation and validation
- Session management and revocation
- Bearer token authentication for protected endpoints

#### ⏰ Timer System
- Blockchain-timestamped webhook delivery
- 1 second to 48 hour delay range
- Automatic persistence (hourly saves)
- Late timers skipped on restore (never sent late)

#### 🌍 Timezone & Localization
- Complete IANA tzdb support
- IP-based geolocation (geoip-lite)
- Locale support (IETF BCP 47)
- DST handling

#### 📊 Monitoring & Metrics
- Performance metrics (requests, errors, RPM)
- System metrics (CPU, memory, uptime)
- Admin-only metric reset

#### 🤖 AI Integration
- Model Context Protocol (MCP) support
- Public resource discovery
- OpenAPI schema for AI agents

## Development

### Scripts

- `npm start` - Run the application in production mode
- `npm run dev` - Run with nodemon for auto-reload during development
- `npm run coverage` - Generate API coverage report


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

## Documentation Structure

This README integrates content from multiple documentation sources:

### Integrated Documentation
- **Main README** - Project overview, setup, and configuration
- **API Documentation** (`api-docs/README.md`) - Complete API endpoint reference and test-to-API mapping
- **SSL Certificates** (`selfcerts/README.md`) - Certificate management and trust configuration

### Additional Resources
- **[API Specification](api-docs/swagger.json)** - OpenAPI 3.0 specification with detailed endpoint schemas
- **Test Modules** (`src/test-modules/`) - Comprehensive test suite with 100% API coverage
- **Configuration** (`config/default.json`) - Application configuration settings

## License

MIT
