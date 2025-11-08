#!/usr/bin/env node
// generate-api-coverage.js
// Generates API coverage report from test results

const fs = require('fs');
const path = require('path');
const { 
  generateApiCoverageReport, 
  getTestsByCapability,
  loadSwaggerSpec 
} = require('./test-modules/api-capability-mapper');

/**
 * Generate and display API coverage report
 */
function generateCoverageReport() {
  console.log('\n=== TimeHereNow API Coverage Report ===\n');

  // Load swagger spec
  const swagger = loadSwaggerSpec();
  if (!swagger) {
    console.error('❌ Failed to load swagger.json');
    process.exit(1);
  }

  console.log(`API: ${swagger.info.title}`);
  console.log(`Version: ${swagger.info.version}`);
  console.log(`Description: ${swagger.info.description}\n`);

  // Get tests by capability
  const testsByCapability = getTestsByCapability();
  
  console.log('=== Coverage by Capability ===\n');
  
  Object.entries(testsByCapability).forEach(([capability, tests]) => {
    console.log(`📋 ${capability}`);
    console.log(`   Tests: ${tests.length}`);
    tests.forEach(test => {
      console.log(`   ✓ ${test.testName}`);
      console.log(`     ${test.method} ${test.apiPath}`);
      console.log(`     Purpose: ${test.testsPurpose}`);
    });
    console.log('');
  });

  // Count endpoints
  const allEndpoints = Object.keys(swagger.paths || {});
  const endpointMethods = [];
  
  allEndpoints.forEach(path => {
    const methods = Object.keys(swagger.paths[path]);
    methods.forEach(method => {
      if (['get', 'post', 'put', 'delete', 'patch'].includes(method)) {
        endpointMethods.push(`${method.toUpperCase()} ${path}`);
      }
    });
  });

  console.log('=== API Endpoints Summary ===\n');
  console.log(`Total Endpoints: ${endpointMethods.length}`);
  console.log(`Total Test Capabilities: ${Object.keys(testsByCapability).length}`);
  
  // Count total tests
  const totalTests = Object.values(testsByCapability).reduce((sum, tests) => sum + tests.length, 0);
  console.log(`Total Tests: ${totalTests}\n`);

  console.log('=== All API Endpoints ===\n');
  endpointMethods.sort().forEach(endpoint => {
    console.log(`  ${endpoint}`);
  });

  console.log('\n=== Key Features ===\n');
  console.log('✓ NEAR Blockchain Integration');
  console.log('  - All time values from NEAR blockchain (NOT system/NTP)');
  console.log('  - 5Hz polling (200ms intervals)');
  console.log('  - Blockchain time granularity: ~500-600ms\n');
  
  console.log('✓ Security & Authentication');
  console.log('  - RODiT token-based authentication');
  console.log('  - JWT token generation and validation');
  console.log('  - Session management and revocation\n');
  
  console.log('✓ Timer System');
  console.log('  - Blockchain-timestamped webhooks');
  console.log('  - 1 second to 48 hour delay range');
  console.log('  - Automatic persistence (hourly saves)\n');
  
  console.log('✓ Timezone & Localization');
  console.log('  - Complete IANA tzdb support');
  console.log('  - IP-based geolocation');
  console.log('  - Locale support (IETF BCP 47)\n');

  console.log('=== Documentation ===\n');
  console.log('📄 Full API Specification: api-docs/swagger.json');
  console.log('📄 Test-to-API Mapping: docs/TEST-API-MAPPING.md');
  console.log('📄 README: README.md\n');

  console.log('=== Report Generated ===');
  console.log(`Timestamp: ${new Date().toISOString()}\n`);
}

// Run if called directly
if (require.main === module) {
  generateCoverageReport();
}

module.exports = { generateCoverageReport };
