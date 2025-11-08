// api-capability-mapper.js
// Maps test functions to API capabilities documented in swagger.json

const fs = require('fs');
const path = require('path');
const { logger } = require('@rodit/rodit-auth-be');

/**
 * API Capability Mapping
 * Links test functions to their corresponding API endpoints and capabilities
 */
const TEST_TO_API_MAPPING = {
  // Authentication Tests
  'testLoginEndpoint': {
    apiPath: '/login',
    method: 'POST',
    capability: 'Authentication',
    description: 'Authenticate and obtain session token',
    swaggerRef: '#/paths/~1login/post',
    requiredAuth: false,
    testsPurpose: 'Verifies user authentication flow and JWT token generation'
  },
  'testLogoutEndpoint': {
    apiPath: '/logout',
    method: 'POST',
    capability: 'Session Management',
    description: 'Terminate session',
    swaggerRef: '#/paths/~1logout/post',
    requiredAuth: true,
    testsPurpose: 'Verifies session termination and token invalidation'
  },
  'testExpiredTokenRejection': {
    apiPath: '/logout',
    method: 'POST',
    capability: 'Token Validation',
    description: 'Reject expired JWT tokens',
    swaggerRef: '#/paths/~1logout/post',
    requiredAuth: true,
    testsPurpose: 'Ensures expired tokens are properly rejected'
  },
  'testJwtClaimIntegrity': {
    apiPath: '/login',
    method: 'POST',
    capability: 'JWT Security',
    description: 'Validate JWT claims and signatures',
    swaggerRef: '#/paths/~1login/post',
    requiredAuth: false,
    testsPurpose: 'Verifies JWT token structure and claim integrity'
  },

  // Session Management Tests
  'testSessionManagementWithSdk': {
    apiPath: '/sessions/list_all',
    method: 'GET',
    capability: 'Session Management',
    description: 'List and manage active sessions',
    swaggerRef: '#/paths/~1sessions~1list_all/get',
    requiredAuth: true,
    testsPurpose: 'Tests session creation, listing, and management'
  },
  'testConcurrentSessions': {
    apiPath: '/sessions/list_all',
    method: 'GET',
    capability: 'Concurrent Session Support',
    description: 'Support multiple concurrent sessions',
    swaggerRef: '#/paths/~1sessions~1list_all/get',
    requiredAuth: true,
    testsPurpose: 'Verifies multiple users can have simultaneous sessions'
  },
  'testSessionRevocationEnforcement': {
    apiPath: '/sessions/revoke',
    method: 'POST',
    capability: 'Session Revocation',
    description: 'Revoke specific sessions',
    swaggerRef: '#/paths/~1sessions~1revoke/post',
    requiredAuth: true,
    testsPurpose: 'Tests admin ability to terminate sessions'
  },
  'testSessionCleanup': {
    apiPath: '/sessions/cleanup',
    method: 'POST',
    capability: 'Session Cleanup',
    description: 'Clean up expired sessions',
    swaggerRef: '#/paths/~1sessions~1cleanup/post',
    requiredAuth: true,
    testsPurpose: 'Verifies automatic cleanup of expired sessions'
  },

  // TimeHereNow API Tests
  'testHealthEndpoint': {
    apiPath: '/health',
    method: 'GET',
    capability: 'Health Check',
    description: 'Server health including NEAR blockchain status',
    swaggerRef: '#/paths/~1health/get',
    requiredAuth: false,
    testsPurpose: 'Monitors API and blockchain connectivity health'
  },
  'testTimezoneList': {
    apiPath: '/timezone',
    method: 'POST',
    capability: 'Timezone Listing',
    description: 'List all available timezones',
    swaggerRef: '#/paths/~1timezone/post',
    requiredAuth: true,
    testsPurpose: 'Retrieves complete IANA timezone database'
  },
  'testTimezoneByArea': {
    apiPath: '/timezone/area',
    method: 'POST',
    capability: 'Timezone Filtering',
    description: 'List timezones by geographic area',
    swaggerRef: '#/paths/~1timezone~1area/post',
    requiredAuth: true,
    testsPurpose: 'Filters timezones by continent/region'
  },
  'testTimezonesByCountry': {
    apiPath: '/timezones/by-country',
    method: 'POST',
    capability: 'Country Timezone Lookup',
    description: 'List timezones by ISO country code',
    swaggerRef: '#/paths/~1timezones~1by-country/post',
    requiredAuth: true,
    testsPurpose: 'Retrieves timezones for specific countries'
  },
  'testTimeByTimezone': {
    apiPath: '/timezone/time',
    method: 'POST',
    capability: 'Blockchain Time by Timezone',
    description: 'Get current NEAR blockchain time for timezone',
    swaggerRef: '#/paths/~1timezone~1time/post',
    requiredAuth: true,
    testsPurpose: 'Returns blockchain-sourced time for specified timezone'
  },
  'testTimeByIpFallback': {
    apiPath: '/ip',
    method: 'POST',
    capability: 'IP-based Time Lookup',
    description: 'Get time based on client IP geolocation',
    swaggerRef: '#/paths/~1ip/post',
    requiredAuth: true,
    testsPurpose: 'Determines timezone from IP and returns blockchain time'
  },
  'testSignHashValidation': {
    apiPath: '/sign/hash',
    method: 'POST',
    capability: 'Blockchain Timestamping',
    description: 'Sign hash with NEAR blockchain timestamp',
    swaggerRef: '#/paths/~1sign~1hash/post',
    requiredAuth: true,
    testsPurpose: 'Creates tamper-proof timestamped signatures'
  },
  'testReliabilityMultiRequest': {
    apiPath: '/timezone/time',
    method: 'POST',
    capability: 'API Reliability',
    description: 'Multiple concurrent requests',
    swaggerRef: '#/paths/~1timezone~1time/post',
    requiredAuth: true,
    testsPurpose: 'Stress tests API with concurrent requests'
  },
  'testPerformanceLatency': {
    apiPath: '/timezone/time',
    method: 'POST',
    capability: 'Performance',
    description: 'Response time measurement',
    swaggerRef: '#/paths/~1timezone~1time/post',
    requiredAuth: true,
    testsPurpose: 'Measures API response latency'
  },

  // Timer/Webhook Tests
  'testTimerScheduleBasic': {
    apiPath: '/timers/schedule',
    method: 'POST',
    capability: 'Timer Scheduling',
    description: 'Schedule delayed webhooks',
    swaggerRef: '#/paths/~1timers~1schedule/post',
    requiredAuth: true,
    testsPurpose: 'Schedules blockchain-timed webhook delivery'
  },
  'testTimerWebhookDelivery': {
    apiPath: '/timers/schedule',
    method: 'POST',
    capability: 'Webhook Delivery',
    description: 'Webhook event delivery',
    swaggerRef: '#/paths/~1timers~1schedule/post',
    requiredAuth: true,
    testsPurpose: 'Verifies webhook is delivered to configured endpoint'
  },
  'testTimerPayloadEcho': {
    apiPath: '/timers/schedule',
    method: 'POST',
    capability: 'Payload Preservation',
    description: 'Echo webhook payload',
    swaggerRef: '#/paths/~1timers~1schedule/post',
    requiredAuth: true,
    testsPurpose: 'Ensures payload data integrity through webhook delivery'
  },
  'testTimerBlockchainTimestamps': {
    apiPath: '/timers/schedule',
    method: 'POST',
    capability: 'Blockchain Timestamps',
    description: 'NEAR blockchain time for timers',
    swaggerRef: '#/paths/~1timers~1schedule/post',
    requiredAuth: true,
    testsPurpose: 'Validates all timestamps use NEAR blockchain time'
  },
  'testTimerInvalidDelayTooSmall': {
    apiPath: '/timers/schedule',
    method: 'POST',
    capability: 'Input Validation',
    description: 'Reject invalid delay values',
    swaggerRef: '#/paths/~1timers~1schedule/post',
    requiredAuth: true,
    testsPurpose: 'Tests minimum delay validation (1 second)'
  },
  'testTimerInvalidDelayTooLarge': {
    apiPath: '/timers/schedule',
    method: 'POST',
    capability: 'Input Validation',
    description: 'Reject excessive delay values',
    swaggerRef: '#/paths/~1timers~1schedule/post',
    requiredAuth: true,
    testsPurpose: 'Tests maximum delay validation (48 hours)'
  },

  // Metrics Tests
  'testMetricsEndpoint': {
    apiPath: '/metrics',
    method: 'GET',
    capability: 'Performance Metrics',
    description: 'Get performance metrics',
    swaggerRef: '#/paths/~1metrics/get',
    requiredAuth: true,
    testsPurpose: 'Retrieves request counts and performance data'
  },
  'testSystemMetrics': {
    apiPath: '/metrics/system',
    method: 'GET',
    capability: 'System Metrics',
    description: 'Get system resource metrics',
    swaggerRef: '#/paths/~1metrics~1system/get',
    requiredAuth: true,
    testsPurpose: 'Monitors CPU, memory, and uptime'
  },
  'testMetricsReset': {
    apiPath: '/metrics/reset',
    method: 'POST',
    capability: 'Metrics Management',
    description: 'Reset performance metrics',
    swaggerRef: '#/paths/~1metrics~1reset/post',
    requiredAuth: true,
    testsPurpose: 'Admin function to reset metric counters'
  },

  // SDK Tests
  'testSdkClientInitializationWithSdk': {
    apiPath: '/login',
    method: 'POST',
    capability: 'SDK Initialization',
    description: 'Initialize RODiT SDK client',
    swaggerRef: '#/paths/~1login/post',
    requiredAuth: false,
    testsPurpose: 'Verifies SDK can initialize and authenticate'
  },
  'testSdkUtilityFunctionsWithSdk': {
    apiPath: '/health',
    method: 'GET',
    capability: 'SDK Utilities',
    description: 'SDK utility functions',
    swaggerRef: '#/paths/~1health/get',
    requiredAuth: false,
    testsPurpose: 'Tests SDK helper functions and configuration access'
  },

  // MCP (Model Context Protocol) Tests
  'testMcpResources': {
    apiPath: '/mcp/resources',
    method: 'GET',
    capability: 'MCP Resource Discovery',
    description: 'List available MCP resources',
    swaggerRef: '#/paths/~1mcp~1resources/get',
    requiredAuth: false,
    testsPurpose: 'AI discovery of available API resources'
  },
  'testMcpResourceRetrieval': {
    apiPath: '/mcp/resource/{uri}',
    method: 'GET',
    capability: 'MCP Resource Access',
    description: 'Get specific MCP resource',
    swaggerRef: '#/paths/~1mcp~1resource~1{uri}/get',
    requiredAuth: false,
    testsPurpose: 'Retrieves specific resource content for AI agents'
  },
  'testMcpSchema': {
    apiPath: '/mcp/schema',
    method: 'GET',
    capability: 'MCP Schema',
    description: 'Get MCP OpenAPI schema',
    swaggerRef: '#/paths/~1mcp~1schema/get',
    requiredAuth: false,
    testsPurpose: 'Provides API schema for AI agent integration'
  }
};

/**
 * Load swagger.json and parse API capabilities
 * @returns {Object} Parsed swagger specification
 */
function loadSwaggerSpec() {
  try {
    const swaggerPath = path.join(__dirname, '../../api-docs/swagger.json');
    const swaggerContent = fs.readFileSync(swaggerPath, 'utf8');
    return JSON.parse(swaggerContent);
  } catch (error) {
    logger.error('Failed to load swagger.json', {
      component: 'api-capability-mapper',
      error: error.message
    });
    return null;
  }
}

/**
 * Get API capability information for a test
 * @param {string} testName - Name of the test function
 * @returns {Object|null} API capability information
 */
function getApiCapabilityForTest(testName) {
  const mapping = TEST_TO_API_MAPPING[testName];
  if (!mapping) {
    logger.debug(`No API mapping found for test: ${testName}`, {
      component: 'api-capability-mapper'
    });
    return null;
  }

  const swagger = loadSwaggerSpec();
  if (!swagger) {
    return mapping; // Return basic mapping without swagger details
  }

  // Enrich with swagger details
  const pathKey = mapping.apiPath.replace(/\//g, '~1');
  const swaggerPath = swagger.paths?.[mapping.apiPath];
  const operation = swaggerPath?.[mapping.method.toLowerCase()];

  return {
    ...mapping,
    swaggerDetails: operation ? {
      summary: operation.summary,
      description: operation.description,
      parameters: operation.parameters,
      requestBody: operation.requestBody,
      responses: operation.responses,
      security: operation.security
    } : null,
    apiVersion: swagger.info?.version,
    apiTitle: swagger.info?.title
  };
}

/**
 * Get all tests that exercise a specific API endpoint
 * @param {string} apiPath - API endpoint path (e.g., '/login')
 * @returns {Array} List of test names
 */
function getTestsForApiEndpoint(apiPath) {
  return Object.entries(TEST_TO_API_MAPPING)
    .filter(([_, mapping]) => mapping.apiPath === apiPath)
    .map(([testName, mapping]) => ({
      testName,
      capability: mapping.capability,
      testsPurpose: mapping.testsPurpose
    }));
}

/**
 * Get all tests grouped by capability
 * @returns {Object} Tests grouped by capability
 */
function getTestsByCapability() {
  const grouped = {};
  
  Object.entries(TEST_TO_API_MAPPING).forEach(([testName, mapping]) => {
    const capability = mapping.capability;
    if (!grouped[capability]) {
      grouped[capability] = [];
    }
    grouped[capability].push({
      testName,
      apiPath: mapping.apiPath,
      method: mapping.method,
      testsPurpose: mapping.testsPurpose
    });
  });

  return grouped;
}

/**
 * Generate API coverage report
 * @param {Object} testResults - Test execution results
 * @returns {Object} Coverage report
 */
function generateApiCoverageReport(testResults) {
  const swagger = loadSwaggerSpec();
  if (!swagger) {
    return { error: 'Could not load swagger specification' };
  }

  const allEndpoints = Object.keys(swagger.paths || {});
  const testedEndpoints = new Set();
  const capabilityCoverage = {};

  // Analyze test results
  Object.keys(testResults).forEach(testName => {
    const mapping = TEST_TO_API_MAPPING[testName];
    if (mapping) {
      testedEndpoints.add(mapping.apiPath);
      
      const capability = mapping.capability;
      if (!capabilityCoverage[capability]) {
        capabilityCoverage[capability] = {
          total: 0,
          passed: 0,
          failed: 0,
          tests: []
        };
      }
      
      capabilityCoverage[capability].total++;
      const testResult = testResults[testName];
      if (testResult?.success || testResult?.result === 'passed') {
        capabilityCoverage[capability].passed++;
      } else {
        capabilityCoverage[capability].failed++;
      }
      
      capabilityCoverage[capability].tests.push({
        testName,
        apiPath: mapping.apiPath,
        success: testResult?.success || testResult?.result === 'passed'
      });
    }
  });

  const untestedEndpoints = allEndpoints.filter(ep => !testedEndpoints.has(ep));

  return {
    summary: {
      totalEndpoints: allEndpoints.length,
      testedEndpoints: testedEndpoints.size,
      untestedEndpoints: untestedEndpoints.length,
      coveragePercent: ((testedEndpoints.size / allEndpoints.length) * 100).toFixed(2)
    },
    capabilityCoverage,
    untestedEndpoints,
    apiVersion: swagger.info?.version,
    generatedAt: new Date().toISOString()
  };
}

/**
 * Format API capability information for logging
 * @param {string} testName - Test name
 * @returns {Object} Formatted capability info
 */
function formatApiCapabilityForLog(testName) {
  const capability = getApiCapabilityForTest(testName);
  if (!capability) {
    return null;
  }

  return {
    api_endpoint: `${capability.method} ${capability.apiPath}`,
    capability: capability.capability,
    requires_auth: capability.requiredAuth,
    swagger_ref: capability.swaggerRef,
    description: capability.description
  };
}

module.exports = {
  TEST_TO_API_MAPPING,
  getApiCapabilityForTest,
  getTestsForApiEndpoint,
  getTestsByCapability,
  generateApiCoverageReport,
  formatApiCapabilityForLog,
  loadSwaggerSpec
};
