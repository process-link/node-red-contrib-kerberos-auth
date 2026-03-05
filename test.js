/**
 * Standalone test script to verify Kerberos/SPNEGO authentication works
 * against your PI Web API server before using the Node-RED node.
 *
 * This uses the 'kerberos' package (mongodb-js/kerberos) which:
 *   - On Windows: uses SSPI (can use current user or explicit credentials)
 *   - On Linux: uses GSSAPI (requires kinit first)
 *
 * Usage:
 *   1. Edit the config below with your server details
 *   2. npm install (in this directory)
 *   3. node test.js
 */

const { initializeClient } = require('kerberos');
const https = require('https');

// ─── Edit these values ─────────────────────────────────────────
const config = {
    // PI Web API endpoint to test
    piWebApiUrl: 'https://piserver.yourdomain.com/piwebapi/system',

    // The hostname of the PI Web API server (used to build the SPN: HTTP@hostname)
    serviceFqdn: 'piserver.yourdomain.com',

    // Explicit credentials (Windows SSPI only).
    // Leave all blank to use the current Windows user's identity.
    domain: '',        // e.g. 'MYDOMAIN'
    user: '',          // e.g. 'myusername'
    password: '',      // e.g. 'mypassword'

    // Set true if the server uses a self-signed SSL certificate
    allowSelfSignedCerts: false
};
// ────────────────────────────────────────────────────────────────

(async () => {
    try {
        const spn = 'HTTP@' + config.serviceFqdn;
        console.log('1. Initializing Kerberos client for SPN:', spn);

        const clientOpts = {};
        if (config.user && config.password) {
            clientOpts.user = config.user;
            clientOpts.password = config.password;
            if (config.domain) clientOpts.domain = config.domain;
            console.log('   Using explicit credentials:', (config.domain ? config.domain + '\\' : '') + config.user);
        } else {
            console.log('   Using current Windows user credentials (SSPI)');
        }

        const client = await initializeClient(spn, clientOpts);
        await client.step('');
        const token = client.response;

        if (!token) {
            throw new Error('Failed to obtain SPNEGO token (empty response)');
        }
        console.log('   SPNEGO token obtained (' + token.length + ' chars)');

        // Step 2: Make authenticated request
        console.log('2. Requesting', config.piWebApiUrl, '...');
        const fetchOptions = {
            headers: {
                'Authorization': 'Negotiate ' + token,
                'Accept': 'application/json'
            }
        };

        if (config.allowSelfSignedCerts) {
            fetchOptions.agent = new https.Agent({ rejectUnauthorized: false });
        }

        const response = await fetch(config.piWebApiUrl, fetchOptions);
        console.log('   Status:', response.status, response.statusText);

        if (response.ok) {
            const data = await response.json();
            console.log('\nPI Web API Response:');
            console.log(JSON.stringify(data, null, 2));
            console.log('\nSuccess! Kerberos authentication is working.');
        } else {
            const text = await response.text();
            console.error('\nRequest failed with status', response.status);
            console.error('Response:', text);

            if (response.status === 401) {
                console.error('\nTroubleshooting 401:');
                console.error('  - The SPNEGO token was rejected by the server');
                console.error('  - Check that the SPN (HTTP/' + config.serviceFqdn + ') is registered in AD');
                console.error('  - Check that your user has access to PI Web API');
                console.error('  - If using explicit credentials, verify domain/user/password');
            }
        }

    } catch (err) {
        console.error('\nError:', err.message);
        console.error('\nTroubleshooting:');
        if (err.message.includes('SEC_E_') || err.message.includes('SSPI')) {
            console.error('  - Windows SSPI error. Check:');
            console.error('    - Machine can reach the domain controller');
            console.error('    - Credentials are correct');
            console.error('    - SPN is valid');
        } else if (err.message.includes('GSSAPI') || err.message.includes('KRB5')) {
            console.error('  - GSSAPI/Kerberos error. Check:');
            console.error('    - /etc/krb5.conf is configured correctly');
            console.error('    - Run "kinit user@REALM" to obtain a ticket');
            console.error('    - Run "klist" to verify you have a valid ticket');
        } else {
            console.error('  - Check network connectivity to the server');
            console.error('  - Check that the kerberos package installed correctly');
        }
        process.exit(1);
    }
})();
