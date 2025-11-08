const crypto = require("crypto");
const { ulid } = require("ulid");
const { logger, RoditClient } = require('@rodit/rodit-auth-be');
const { captureTestData } = require("./test-utils");

// Get the shared RoditClient instance from app.locals
function getSharedClient() {
  const { app } = require('../app');
  if (!app.locals.roditClient) {
    throw new Error('RoditClient not initialized in app.locals');
  }
  return app.locals.roditClient;
}

function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

const timeHereNowTests = {
  testHealthEndpoint: async (apiBase, context) => {
    const moduleName = "timeherenow";
    const testName = "testHealthEndpoint";
    const testData = { apiBase };
    try {
      const client = getSharedClient();
      const data = await client.request('GET', '/health');
      const ok = data && typeof data.status === "string" && 
                 typeof data.timestamp === "string" &&
                 typeof data.service === "string";
      // Check for NEAR health info (optional but should be present)
      const hasNearInfo = data.near && typeof data.near.status === "string";
      const result = { 
        success: !!ok, 
        error: ok ? null : `Unexpected /health response`, 
        details: { body: data, hasNearInfo } 
      };
      return captureTestData(testName, moduleName, result, testData);
    } catch (error) {
      return captureTestData(testName, moduleName, { success: false, error: error.message }, testData);
    }
  },

  testTimezoneList: async (apiBase, context) => {
    const moduleName = "timeherenow";
    const testName = "testTimezoneList";
    const testData = { apiBase };
    try {
      const client = getSharedClient();
      const data = await client.request('POST', '/api/timezone');
      const ok = Array.isArray(data);
      const result = { success: !!ok, error: ok ? null : `Expected array response`, details: { count: Array.isArray(data) ? data.length : 0 } };
      return captureTestData(testName, moduleName, result, testData);
    } catch (error) {
      return captureTestData(testName, moduleName, { success: false, error: error.message }, testData);
    }
  },

  testTimezoneAreaList: async (apiBase, context) => {
    const moduleName = "timeherenow";
    const testName = "testTimezoneAreaList";
    const testData = { apiBase };
    try {
      const client = getSharedClient();
      const data = await client.request('POST', '/api/timezone/area', { area: "Europe" });
      const ok = Array.isArray(data) && data.every((s) => typeof s === "string");
      const result = { success: !!ok, error: ok ? null : `Invalid area listing response`, details: { sample: Array.isArray(data) ? data.slice(0, 5) : null } };
      return captureTestData(testName, moduleName, result, testData);
    } catch (error) {
      return captureTestData(testName, moduleName, { success: false, error: error.message }, testData);
    }
  },

  testTimeForTimezone: async (apiBase, context) => {
    const moduleName = "timeherenow";
    const testName = "testTimeForTimezone";
    const testData = { apiBase };
    try {
      const client = getSharedClient();
      const body = await client.request('POST', '/api/timezone/time', { timezone: "Europe/Berlin", locale: "en-US" });
      const hasFields = body && typeof body === "object" &&
        typeof body.date_time === "string" &&
        typeof body.utc_datetime === "string" &&
        typeof body.utc_offset === "string" &&
        typeof body.unix_time === "number" &&
        typeof body.day_of_week === "number" &&
        typeof body.day_of_year === "number" &&
        typeof body.week_number === "number" &&
        typeof body.time_zone === "string" &&
        typeof body.likely_time_difference_ms === "number";
      const result = { success: !!hasFields, error: hasFields ? null : `Invalid DateTimeJsonResponse`, details: { body } };
      return captureTestData(testName, moduleName, result, testData);
    } catch (error) {
      return captureTestData(testName, moduleName, { success: false, error: error.message }, testData);
    }
  },

  testTimeByIpFallback: async (apiBase, context) => {
    const moduleName = "timeherenow";
    const testName = "testTimeByIpFallback";
    const testData = { apiBase };
    try {
      const client = getSharedClient();
      const body = await client.request('POST', '/api/ip', {});
      const ok = typeof body.date_time === "string" && 
                 typeof body.user_ip === "string" &&
                 typeof body.likely_time_difference_ms === "number";
      const result = { success: !!ok, error: ok ? null : `Invalid /ip response`, details: { body } };
      return captureTestData(testName, moduleName, result, testData);
    } catch (error) {
      return captureTestData(testName, moduleName, { success: false, error: error.message }, testData);
    }
  },

  testTimezonesByCountry: async (apiBase, context) => {
    const moduleName = "timeherenow";
    const testName = "testTimezonesByCountry";
    const testData = { apiBase };
    try {
      const client = getSharedClient();
      const data = await client.request('POST', '/api/timezones/by-country', { country_code: "US" });
      const ok = Array.isArray(data) && data.length > 0;
      const result = { success: !!ok, error: ok ? null : `Expected non-empty array`, details: { count: Array.isArray(data) ? data.length : 0 } };
      return captureTestData(testName, moduleName, result, testData);
    } catch (error) {
      return captureTestData(testName, moduleName, { success: false, error: error.message }, testData);
    }
  },

  testSignHashValidation: async (apiBase, context) => {
    const moduleName = "timeherenow";
    const testName = "testSignHashValidation";
    const testData = { apiBase };
    try {
      const client = getSharedClient();
      
      // Test 1: Invalid base64url format should be rejected
      let invalidFormatRejected = false;
      try {
        await client.request('POST', '/api/sign/hash', { hash_b64url: "!!!not_base64url!!!" });
      } catch (error) {
        invalidFormatRejected = true;
      }
      
      // Test 2: Empty hash should be rejected
      let emptyHashRejected = false;
      try {
        await client.request('POST', '/api/sign/hash', { hash_b64url: "" });
      } catch (error) {
        emptyHashRejected = true;
      }
      
      // Test 3: Hash too long (>128 bytes) should be rejected
      let tooLongRejected = false;
      try {
        const longHash = crypto.randomBytes(129);
        await client.request('POST', '/api/sign/hash', { hash_b64url: b64url(longHash) });
      } catch (error) {
        tooLongRejected = true;
      }
      
      // Test 4: Valid hash (32 bytes) should succeed
      const validHash = crypto.randomBytes(32);
      const response = await client.request('POST', '/api/sign/hash', { hash_b64url: b64url(validHash) });
      
      // Validate response structure
      const hasData = response && typeof response.data === 'object';
      const hasHashB64url = hasData && typeof response.data.hash_b64url === 'string';
      const hasTimestamp = hasData && typeof response.data.timestamp_iso === 'string';
      const hasTimeDiff = hasData && typeof response.data.likely_time_difference_ms === 'number';
      const hasPublicKey = hasData && typeof response.data.public_key_base64url === 'string';
      const hasConcatenated = typeof response.concatenated === 'string';
      const hasSignature = typeof response.signature_base64url === 'string';
      
      // Verify concatenated format matches expected pattern
      const expectedConcatenated = `${response.data.hash_b64url}.${response.data.timestamp_iso}.${response.data.likely_time_difference_ms}.${response.data.public_key_base64url}`;
      const concatenatedMatches = response.concatenated === expectedConcatenated;
      
      // Verify timestamp is valid ISO 8601
      const timestampValid = !isNaN(Date.parse(response.data.timestamp_iso));
      
      // Test 5: Minimum hash size (1 byte) should succeed
      const minHash = crypto.randomBytes(1);
      const minResponse = await client.request('POST', '/api/sign/hash', { hash_b64url: b64url(minHash) });
      const minHashOk = minResponse && typeof minResponse.signature_base64url === 'string';
      
      // Test 6: Maximum hash size (128 bytes) should succeed
      const maxHash = crypto.randomBytes(128);
      const maxResponse = await client.request('POST', '/api/sign/hash', { hash_b64url: b64url(maxHash) });
      const maxHashOk = maxResponse && typeof maxResponse.signature_base64url === 'string';
      
      const allValid = invalidFormatRejected && emptyHashRejected && tooLongRejected &&
                       hasData && hasHashB64url && hasTimestamp && hasTimeDiff && hasPublicKey &&
                       hasConcatenated && hasSignature && concatenatedMatches && timestampValid &&
                       minHashOk && maxHashOk;
      
      const result = {
        success: allValid,
        error: allValid ? null : 'Sign/hash validation failed',
        details: {
          invalidFormatRejected,
          emptyHashRejected,
          tooLongRejected,
          responseStructureValid: hasData && hasHashB64url && hasTimestamp && hasTimeDiff && hasPublicKey,
          concatenatedMatches,
          timestampValid,
          minHashOk,
          maxHashOk,
          sampleTimestamp: response.data.timestamp_iso,
          sampleTimeDiff: response.data.likely_time_difference_ms
        }
      };
      return captureTestData(testName, moduleName, result, testData);
    } catch (error) {
      return captureTestData(testName, moduleName, { success: false, error: error.message }, testData);
    }
  },

  testReliabilityMultiRequest: async (apiBase, context) => {
    const moduleName = "timeherenow";
    const testName = "testReliabilityMultiRequest";
    const testData = { apiBase };
    try {
      const client = getSharedClient();
      const iterations = 5;
      const results = [];
      for (let i = 0; i < iterations; i++) {
        const start = Date.now();
        try {
          await client.request('POST', '/api/timezone/time', { timezone: "Europe/Berlin" });
          results.push({ ok: true, duration: Date.now() - start });
        } catch (error) {
          results.push({ ok: false, duration: Date.now() - start, error: error.message });
        }
      }
      const successRate = results.filter(r => r.ok).length / iterations;
      const avg = results.reduce((s, r) => s + r.duration, 0) / iterations;
      const result = { success: successRate >= 0.8, error: successRate >= 0.8 ? null : `Low success rate ${(successRate*100).toFixed(0)}%`, details: { results, avgDurationMs: Math.round(avg), successRate } };
      return captureTestData(testName, moduleName, result, testData);
    } catch (error) {
      return captureTestData(testName, moduleName, { success: false, error: error.message }, testData);
    }
  },

  testPerformanceLatency: async (apiBase, context) => {
    const moduleName = "timeherenow";
    const testName = "testPerformanceLatency";
    const testData = { apiBase };
    try {
      const client = getSharedClient();
      const concurrent = 3;
      const batch = new Array(concurrent).fill(0).map(async () => {
        const start = Date.now();
        try {
          await client.request('POST', '/api/timezone/time', { timezone: "Europe/Berlin" });
          return { ok: true, duration: Date.now() - start };
        } catch (error) {
          return { ok: false, duration: Date.now() - start, error: error.message };
        }
      });
      const res = await Promise.all(batch);
      const durations = res.map(r => r.duration);
      const avg = durations.reduce((s, d) => s + d, 0) / res.length;
      const ok = res.every(r => r.ok);
      const result = { success: ok, error: ok ? null : "One or more concurrent requests failed", details: { avgDurationMs: Math.round(avg), durations } };
      return captureTestData(testName, moduleName, result, testData);
    } catch (error) {
      return captureTestData(testName, moduleName, { success: false, error: error.message }, testData);
    }
  },

  testLoginInvalidToken: async (apiBase, context) => {
    const moduleName = "timeherenow";
    const testName = "testLoginInvalidToken";
    const testData = { apiBase };
    try {
      // Login endpoint test - this should fail with invalid credentials
      // Note: We can't use client.request() here as it's testing the login itself
      const response = await fetch(`${apiBase}/api/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Request-ID": ulid() },
        body: JSON.stringify({ roditToken: "invalid" })
      });
      const ok = !response.ok && (response.status === 401 || response.status === 400);
      const result = { success: ok, error: ok ? null : `Expected 4xx for invalid login, got ${response.status}`, details: { status: response.status } };
      return captureTestData(testName, moduleName, result, testData);
    } catch (error) {
      return captureTestData(testName, moduleName, { success: false, error: error.message }, testData);
    }
  },
};

module.exports = timeHereNowTests;
