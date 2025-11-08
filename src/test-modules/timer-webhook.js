const { ulid } = require('ulid');
const { captureTestData } = require('./test-utils');

// Get the shared RoditClient instance from app.locals
function getSharedClient() {
  const { app } = require('../app');
  if (!app.locals.roditClient) {
    throw new Error('RoditClient not initialized in app.locals');
  }
  return app.locals.roditClient;
}

/**
 * Timer and Webhook Tests
 * 
 * Tests the /api/timers/schedule endpoint and webhook delivery functionality.
 * 
 * The timer endpoint schedules a delayed webhook that fires after the specified
 * delay_seconds. The webhook is sent to the SDK-configured destination (this test
 * server's /webhook endpoint).
 * 
 * All timestamps (scheduled_at, execute_at, fired_at) use NEAR blockchain time.
 */

// Global webhook storage for test validation
// Key: test_id from payload, Value: webhook data
const webhookStore = new Map();
const webhookPromises = new Map();

/**
 * Register a webhook for a specific test_id
 * Returns a promise that resolves when the webhook is received
 */
function waitForWebhook(testId, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    // Check if webhook already received
    if (webhookStore.has(testId)) {
      resolve(webhookStore.get(testId));
      return;
    }
    
    // Store promise for later resolution
    webhookPromises.set(testId, { resolve, reject });
    
    // Set timeout
    const timeout = setTimeout(() => {
      webhookPromises.delete(testId);
      reject(new Error(`Webhook timeout after ${timeoutMs}ms for test_id: ${testId}`));
    }, timeoutMs);
    
    // Clear timeout when resolved
    const originalResolve = resolve;
    webhookPromises.get(testId).resolve = (data) => {
      clearTimeout(timeout);
      webhookPromises.delete(testId);
      originalResolve(data);
    };
  });
}

/**
 * Store a received webhook and resolve any waiting promises
 * This should be called from the webhook handler in app.js
 */
function storeWebhook(webhookData) {
  const testId = webhookData.payload?.test_id;
  if (!testId) {
    return; // Not a test webhook
  }
  
  webhookStore.set(testId, webhookData);
  
  // Resolve any waiting promises
  if (webhookPromises.has(testId)) {
    const { resolve } = webhookPromises.get(testId);
    resolve(webhookData);
  }
}

/**
 * Clear webhook storage (for test cleanup)
 */
function clearWebhookStore() {
  webhookStore.clear();
  // Reject any pending promises
  for (const [testId, { reject }] of webhookPromises.entries()) {
    reject(new Error(`Test cleanup: webhook never received for ${testId}`));
  }
  webhookPromises.clear();
}

const timerWebhookTests = {
  /**
   * Test 1: Basic timer scheduling
   * Validates the response structure from /api/timers/schedule
   */
  testTimerScheduleBasic: async (apiBase, context) => {
    const moduleName = "timerWebhook";
    const testName = "testTimerScheduleBasic";
    const testData = { apiBase };
    
    try {
      const client = getSharedClient();
      const testPayload = { test_id: ulid(), description: "basic_schedule_test" };
      
      const response = await client.request('POST', '/api/timers/schedule', {
        delay_seconds: 5,
        payload: testPayload
      });
      
      // Validate response structure
      const hasRequiredFields = 
        response &&
        typeof response.timer_id === 'string' &&
        typeof response.delay_seconds === 'number' &&
        typeof response.scheduled_at === 'string' &&
        typeof response.execute_at === 'string' &&
        typeof response.requestId === 'string';
      
      // Validate values
      const valuesCorrect = 
        response.delay_seconds === 5 &&
        response.timer_id.length > 0;
      
      // Validate timestamps are valid ISO 8601
      let timestampsValid = false;
      try {
        const scheduledAt = new Date(response.scheduled_at);
        const executeAt = new Date(response.execute_at);
        timestampsValid = !isNaN(scheduledAt.getTime()) && !isNaN(executeAt.getTime());
      } catch (e) {
        timestampsValid = false;
      }
      
      const success = hasRequiredFields && valuesCorrect && timestampsValid;
      const result = {
        success,
        error: success ? null : 'Invalid timer schedule response structure',
        details: {
          response,
          hasRequiredFields,
          valuesCorrect,
          timestampsValid
        }
      };
      
      return captureTestData(testName, moduleName, result, testData);
    } catch (error) {
      return captureTestData(testName, moduleName, { 
        success: false, 
        error: error.message,
        details: { stack: error.stack }
      }, testData);
    }
  },

  /**
   * Test 2: End-to-end webhook delivery
   * Schedules a timer and validates the webhook is received with correct structure
   */
  testTimerWebhookDelivery: async (apiBase, context) => {
    const moduleName = "timerWebhook";
    const testName = "testTimerWebhookDelivery";
    const testData = { apiBase };
    
    try {
      const client = getSharedClient();
      const testId = ulid();
      const testPayload = { 
        test_id: testId, 
        description: "webhook_delivery_test",
        timestamp: new Date().toISOString()
      };
      
      // Set up webhook listener
      const webhookPromise = waitForWebhook(testId, 15000); // 15 second timeout
      
      // Schedule the timer
      const scheduleResponse = await client.request('POST', '/api/timers/schedule', {
        delay_seconds: 3,
        payload: testPayload
      });
      
      // Wait for webhook delivery
      const webhook = await webhookPromise;
      
      // Validate webhook structure
      const hasRequiredFields = 
        webhook &&
        typeof webhook.timer_id === 'string' &&
        typeof webhook.scheduled_at === 'string' &&
        typeof webhook.execute_at === 'string' &&
        typeof webhook.fired_at === 'string' &&
        typeof webhook.user_id === 'string' &&
        typeof webhook.session_key === 'string' &&
        webhook.payload !== undefined;
      
      // Validate payload matches
      const payloadMatches = 
        webhook.payload?.test_id === testId &&
        webhook.payload?.description === testPayload.description;
      
      // Validate timer_id matches
      const timerIdMatches = webhook.timer_id === scheduleResponse.timer_id;
      
      // Validate timestamp ordering (scheduled < execute <= fired)
      let timestampsValid = false;
      try {
        const scheduledTime = new Date(webhook.scheduled_at).getTime();
        const executeTime = new Date(webhook.execute_at).getTime();
        const firedTime = new Date(webhook.fired_at).getTime();
        
        timestampsValid = 
          scheduledTime < executeTime &&
          executeTime <= firedTime;
      } catch (e) {
        timestampsValid = false;
      }
      
      const success = hasRequiredFields && payloadMatches && timerIdMatches && timestampsValid;
      const result = {
        success,
        error: success ? null : 'Webhook validation failed',
        details: {
          webhook,
          scheduleResponse,
          hasRequiredFields,
          payloadMatches,
          timerIdMatches,
          timestampsValid
        }
      };
      
      return captureTestData(testName, moduleName, result, testData);
    } catch (error) {
      return captureTestData(testName, moduleName, { 
        success: false, 
        error: error.message,
        details: { stack: error.stack }
      }, testData);
    }
  },

  /**
   * Test 3: Invalid delay_seconds (too small)
   * Should reject delay_seconds < 1
   */
  testTimerInvalidDelayTooSmall: async (apiBase, context) => {
    const moduleName = "timerWebhook";
    const testName = "testTimerInvalidDelayTooSmall";
    const testData = { apiBase };
    
    try {
      const client = getSharedClient();
      
      let errorCaught = false;
      let statusCode = null;
      
      try {
        await client.request('POST', '/api/timers/schedule', {
          delay_seconds: 0,
          payload: { test: "should_fail" }
        });
      } catch (error) {
        errorCaught = true;
        // Extract status code from various possible error structures
        statusCode = error.status || error.statusCode || error.response?.status || 
                     (error.message?.match(/status (\d+)/) ? parseInt(error.message.match(/status (\d+)/)[1]) : null);
      }
      
      const success = errorCaught && statusCode === 400;
      const result = {
        success,
        error: success ? null : `Expected 400 error for delay_seconds=0, got ${statusCode || 'no error'}`,
        details: {
          errorCaught,
          statusCode
        }
      };
      
      return captureTestData(testName, moduleName, result, testData);
    } catch (error) {
      return captureTestData(testName, moduleName, { 
        success: false, 
        error: error.message,
        details: { stack: error.stack }
      }, testData);
    }
  },

  /**
   * Test 4: Invalid delay_seconds (too large)
   * Should reject delay_seconds > 172800 (48 hours)
   */
  testTimerInvalidDelayTooLarge: async (apiBase, context) => {
    const moduleName = "timerWebhook";
    const testName = "testTimerInvalidDelayTooLarge";
    const testData = { apiBase };
    
    try {
      const client = getSharedClient();
      
      let errorCaught = false;
      let statusCode = null;
      
      try {
        await client.request('POST', '/api/timers/schedule', {
          delay_seconds: 172801,
          payload: { test: "should_fail" }
        });
      } catch (error) {
        errorCaught = true;
        // Extract status code from various possible error structures
        statusCode = error.status || error.statusCode || error.response?.status || 
                     (error.message?.match(/status (\d+)/) ? parseInt(error.message.match(/status (\d+)/)[1]) : null);
      }
      
      const success = errorCaught && statusCode === 400;
      const result = {
        success,
        error: success ? null : `Expected 400 error for delay_seconds=172801, got ${statusCode || 'no error'}`,
        details: {
          errorCaught,
          statusCode
        }
      };
      
      return captureTestData(testName, moduleName, result, testData);
    } catch (error) {
      return captureTestData(testName, moduleName, { 
        success: false, 
        error: error.message,
        details: { stack: error.stack }
      }, testData);
    }
  },

  /**
   * Test 5: Missing required field (delay_seconds)
   * Should reject request without delay_seconds
   */
  testTimerMissingDelaySeconds: async (apiBase, context) => {
    const moduleName = "timerWebhook";
    const testName = "testTimerMissingDelaySeconds";
    const testData = { apiBase };
    
    try {
      const client = getSharedClient();
      
      let errorCaught = false;
      let statusCode = null;
      
      try {
        await client.request('POST', '/api/timers/schedule', {
          payload: { test: "should_fail" }
        });
      } catch (error) {
        errorCaught = true;
        // Extract status code from various possible error structures
        statusCode = error.status || error.statusCode || error.response?.status || 
                     (error.message?.match(/status (\d+)/) ? parseInt(error.message.match(/status (\d+)/)[1]) : null);
      }
      
      const success = errorCaught && statusCode === 400;
      const result = {
        success,
        error: success ? null : `Expected 400 error for missing delay_seconds, got ${statusCode || 'no error'}`,
        details: {
          errorCaught,
          statusCode
        }
      };
      
      return captureTestData(testName, moduleName, result, testData);
    } catch (error) {
      return captureTestData(testName, moduleName, { 
        success: false, 
        error: error.message,
        details: { stack: error.stack }
      }, testData);
    }
  },

  /**
   * Test 6: Unauthorized access
   * Should reject requests without authentication
   */
  testTimerUnauthorized: async (apiBase, context) => {
    const moduleName = "timerWebhook";
    const testName = "testTimerUnauthorized";
    const testData = { apiBase };
    
    try {
      // Make request without authentication
      const response = await fetch(`${apiBase}/api/timers/schedule`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'X-Request-ID': ulid()
        },
        body: JSON.stringify({ 
          delay_seconds: 5, 
          payload: {} 
        })
      });
      
      const success = response.status === 401;
      const result = {
        success,
        error: success ? null : `Expected 401 for unauthorized request, got ${response.status}`,
        details: {
          statusCode: response.status,
          statusText: response.statusText
        }
      };
      
      return captureTestData(testName, moduleName, result, testData);
    } catch (error) {
      return captureTestData(testName, moduleName, { 
        success: false, 
        error: error.message,
        details: { stack: error.stack }
      }, testData);
    }
  },

  /**
   * Test 7: Payload echo validation
   * Validates that the payload is echoed back correctly in the webhook
   */
  testTimerPayloadEcho: async (apiBase, context) => {
    const moduleName = "timerWebhook";
    const testName = "testTimerPayloadEcho";
    const testData = { apiBase };
    
    try {
      const client = getSharedClient();
      const testId = ulid();
      const complexPayload = {
        test_id: testId,
        nested: {
          object: {
            with: "multiple",
            levels: [1, 2, 3]
          }
        },
        array: ["a", "b", "c"],
        number: 42,
        boolean: true,
        null_value: null
      };
      
      // Set up webhook listener
      const webhookPromise = waitForWebhook(testId, 15000);
      
      // Schedule the timer
      await client.request('POST', '/api/timers/schedule', {
        delay_seconds: 3,
        payload: complexPayload
      });
      
      // Wait for webhook delivery
      const webhook = await webhookPromise;
      
      // Deep comparison of payload
      const payloadMatches = JSON.stringify(webhook.payload) === JSON.stringify(complexPayload);
      
      const result = {
        success: payloadMatches,
        error: payloadMatches ? null : 'Payload mismatch in webhook',
        details: {
          sentPayload: complexPayload,
          receivedPayload: webhook.payload,
          payloadMatches
        }
      };
      
      return captureTestData(testName, moduleName, result, testData);
    } catch (error) {
      return captureTestData(testName, moduleName, { 
        success: false, 
        error: error.message,
        details: { stack: error.stack }
      }, testData);
    }
  },

  /**
   * Test 8: NEAR blockchain timestamp validation
   * Validates that all timestamps use NEAR blockchain time
   */
  testTimerBlockchainTimestamps: async (apiBase, context) => {
    const moduleName = "timerWebhook";
    const testName = "testTimerBlockchainTimestamps";
    const testData = { apiBase };
    
    try {
      const client = getSharedClient();
      const testId = ulid();
      const testPayload = { test_id: testId, description: "blockchain_timestamp_test" };
      
      // Set up webhook listener
      const webhookPromise = waitForWebhook(testId, 15000);
      
      // Record system time before scheduling
      const systemTimeBefore = Date.now();
      
      // Schedule the timer
      const scheduleResponse = await client.request('POST', '/api/timers/schedule', {
        delay_seconds: 3,
        payload: testPayload
      });
      
      // Record system time after scheduling
      const systemTimeAfter = Date.now();
      
      // Wait for webhook delivery
      const webhook = await webhookPromise;
      
      // Parse timestamps
      const scheduledAt = new Date(webhook.scheduled_at).getTime();
      const executeAt = new Date(webhook.execute_at).getTime();
      const firedAt = new Date(webhook.fired_at).getTime();
      
      // Validate timestamps are within reasonable range of system time
      // (accounting for NEAR blockchain time which may differ slightly)
      const reasonableRange = 10000; // 10 seconds tolerance
      const scheduledInRange = 
        scheduledAt >= (systemTimeBefore - reasonableRange) &&
        scheduledAt <= (systemTimeAfter + reasonableRange);
      
      // Validate delay is approximately correct (3 seconds with tolerance)
      // Allows for network latency, webhook delivery overhead, blockchain polling,
      // timer persistence operations, and system load variations
      const actualDelay = (firedAt - scheduledAt) / 1000;
      const delayCorrect = actualDelay >= 2 && actualDelay <= 8;
      
      // Validate timestamp ordering
      const orderingCorrect = scheduledAt < executeAt && executeAt <= firedAt;
      
      const success = scheduledInRange && delayCorrect && orderingCorrect;
      const result = {
        success,
        error: success ? null : 'Blockchain timestamp validation failed',
        details: {
          systemTimeBefore,
          systemTimeAfter,
          scheduledAt,
          executeAt,
          firedAt,
          actualDelaySeconds: actualDelay,
          scheduledInRange,
          delayCorrect,
          orderingCorrect
        }
      };
      
      return captureTestData(testName, moduleName, result, testData);
    } catch (error) {
      return captureTestData(testName, moduleName, { 
        success: false, 
        error: error.message,
        details: { stack: error.stack }
      }, testData);
    }
  }
};

module.exports = {
  timerWebhookTests,
  storeWebhook,
  clearWebhookStore,
  waitForWebhook
};
