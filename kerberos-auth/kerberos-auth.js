module.exports = function (RED) {
    const { initializeClient } = require('kerberos');
    const https = require('https');

    const VALID_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];

    // ─── Config Node ───────────────────────────────────────────────
    function KerberosAuthConfigNode(config) {
        RED.nodes.createNode(this, config);
        const node = this;

        node.baseUrl = (config.baseUrl || '').replace(/\/+$/, '');
        node.serviceFqdn = config.serviceFqdn || '';
        node.rejectUnauthorized = config.rejectUnauthorized !== false;

        // Reusable HTTPS agent for when SSL verification is disabled
        if (!node.rejectUnauthorized) {
            node._agent = new https.Agent({ rejectUnauthorized: false });
        }

        // Resolve the service principal name (SPN)
        node._getServicePrincipal = function () {
            let hostname = node.serviceFqdn;
            if (!hostname && node.baseUrl) {
                try {
                    hostname = new URL(node.baseUrl).hostname;
                } catch (e) {
                    throw new Error('Cannot extract hostname from base URL: ' + node.baseUrl);
                }
            }
            if (!hostname) {
                throw new Error('No service FQDN or base URL configured');
            }
            return 'HTTP@' + hostname;
        };

        // Get a SPNEGO token for the target service using the kerberos package.
        // On Windows this uses SSPI (current user's credentials automatically).
        // On Linux this uses GSSAPI (requires a valid Kerberos ticket in the ccache,
        // obtained via kinit on the command line or keytab).
        node.getToken = async function () {
            const spn = node._getServicePrincipal();

            const clientOpts = {};

            // If explicit credentials are provided, pass them for SSPI (Windows)
            if (node.credentials && node.credentials.user && node.credentials.password) {
                clientOpts.user = node.credentials.user;
                clientOpts.password = node.credentials.password;
                if (node.credentials.domain) {
                    clientOpts.domain = node.credentials.domain;
                }
            }

            const client = await initializeClient(spn, clientOpts);
            await client.step('');
            const token = client.response;

            if (!token) {
                throw new Error('Kerberos: failed to obtain SPNEGO token (empty response)');
            }

            return token;
        };

        node.on('close', function () {
            if (node._agent) {
                node._agent.destroy();
                node._agent = null;
            }
        });
    }

    RED.nodes.registerType('kerberos-auth-config', KerberosAuthConfigNode, {
        credentials: {
            domain: { type: 'text' },
            user: { type: 'text' },
            password: { type: 'password' }
        }
    });

    // ─── Request Node ──────────────────────────────────────────────
    function KerberosAuthNode(n) {
        RED.nodes.createNode(this, n);
        const node = this;

        node.server = RED.nodes.getNode(n.server);
        node.method = n.method || 'GET';
        node.url = n.url || '';
        node.ret = n.ret || 'obj';

        if (!node.server) {
            node.error('No Kerberos server configuration selected');
            node.status({ fill: 'red', shape: 'ring', text: 'no config' });
            return;
        }

        node.on('input', async function (msg, send, done) {
            send = send || function () { node.send.apply(node, arguments); };

            let fullUrl;

            try {
                const method = (node.method === 'use')
                    ? (msg.method || 'GET').toUpperCase()
                    : node.method.toUpperCase();

                if (!VALID_METHODS.includes(method)) {
                    throw new Error('Invalid HTTP method: ' + method);
                }

                // Build full URL
                const urlPath = msg.url || node.url || '';
                if (urlPath.startsWith('http://') || urlPath.startsWith('https://')) {
                    // Validate that absolute URLs match the configured base URL origin
                    // to prevent SSRF (sending Kerberos tokens to unintended servers)
                    const targetOrigin = new URL(urlPath).origin;
                    const baseOrigin = new URL(node.server.baseUrl).origin;
                    if (targetOrigin !== baseOrigin) {
                        throw new Error('URL origin "' + targetOrigin + '" does not match configured server "' + baseOrigin + '". Blocked to prevent sending credentials to an unintended server.');
                    }
                    fullUrl = urlPath;
                } else {
                    fullUrl = node.server.baseUrl + '/' + urlPath.replace(/^\//, '');
                }

                // Build headers
                const headers = Object.assign(
                    { 'Accept': 'application/json' },
                    msg.headers || {}
                );

                // Build fetch options
                const fetchOptions = {
                    method: method,
                    headers: headers
                };

                // Body for POST/PUT/PATCH
                if (['POST', 'PUT', 'PATCH'].includes(method) && msg.payload !== undefined) {
                    if (typeof msg.payload === 'object' && !(msg.payload instanceof Buffer)) {
                        fetchOptions.body = JSON.stringify(msg.payload);
                        if (!headers['Content-Type']) {
                            headers['Content-Type'] = 'application/json';
                        }
                    } else {
                        fetchOptions.body = msg.payload;
                    }
                }

                // TLS: reuse the shared agent when SSL verification is disabled
                if (node.server._agent) {
                    fetchOptions.agent = node.server._agent;
                }

                // Request timeout (30 seconds)
                fetchOptions.signal = AbortSignal.timeout(30000);

                node.status({ fill: 'blue', shape: 'dot', text: 'requesting...' });

                const response = await makeAuthenticatedRequest(node, fullUrl, fetchOptions, true);
                const statusCode = response.status;

                // Parse response
                let payload;
                if (node.ret === 'obj') {
                    const text = await response.text();
                    try {
                        payload = JSON.parse(text);
                    } catch (e) {
                        payload = text;
                    }
                } else if (node.ret === 'bin') {
                    const ab = await response.arrayBuffer();
                    payload = Buffer.from(ab);
                } else {
                    payload = await response.text();
                }

                msg.payload = payload;
                msg.statusCode = statusCode;
                msg.headers = {};
                response.headers.forEach(function (value, key) {
                    msg.headers[key] = value;
                });

                if (statusCode >= 200 && statusCode < 300) {
                    node.status({ fill: 'green', shape: 'dot', text: String(statusCode) });
                } else {
                    node.status({ fill: 'yellow', shape: 'ring', text: String(statusCode) });
                }

                send(msg);
                if (done) done();
            } catch (err) {
                node.status({ fill: 'red', shape: 'ring', text: (err.message || 'error').substring(0, 32) });
                const errorMsg = formatError(err, fullUrl);
                if (done) {
                    done(errorMsg);
                } else {
                    node.error(errorMsg, msg);
                }
            }
        });

        node.on('close', function () {
            node.status({});
        });
    }

    RED.nodes.registerType('kerberos-auth', KerberosAuthNode);

    // ─── Helpers ───────────────────────────────────────────────────

    async function makeAuthenticatedRequest(node, url, fetchOptions, allowRetry) {
        // Get a fresh SPNEGO token for each request
        const token = await node.server.getToken();
        fetchOptions.headers['Authorization'] = 'Negotiate ' + token;

        const response = await fetch(url, fetchOptions);

        // If 401 and we haven't retried yet, try once more with a fresh token
        if (response.status === 401 && allowRetry) {
            node.warn('Got 401, retrying with fresh Kerberos token...');
            return makeAuthenticatedRequest(node, url, fetchOptions, false);
        }

        return response;
    }

    function formatError(err, url) {
        const msg = err.message || String(err);
        if (err.name === 'TimeoutError' || msg.includes('abort')) {
            return 'Request timed out: ' + url;
        }
        if (msg.includes('ENOTFOUND')) {
            return 'Server not found: ' + url;
        }
        if (msg.includes('ETIMEDOUT') || msg.includes('ECONNREFUSED')) {
            return 'Cannot connect to server: ' + url;
        }
        if (msg.includes('UNABLE_TO_VERIFY_LEAF_SIGNATURE') || msg.includes('CERT_HAS_EXPIRED') || msg.includes('SELF_SIGNED_CERT')) {
            return 'SSL certificate error. Disable "Verify SSL Certificate" in server config if using self-signed certs. Detail: ' + msg;
        }
        if (msg.includes('SEC_E_') || msg.includes('InitializeSecurityContext') || msg.includes('SSPI')) {
            return 'Windows SSPI error: ' + msg + '. Check that the machine can reach the domain controller and credentials are correct.';
        }
        if (msg.includes('KRB5') || msg.includes('GSSAPI') || msg.includes('Cannot find KDC')) {
            return 'Kerberos error: ' + msg + '. Check krb5.conf, realm, KDC connectivity, and that you have a valid ticket (run kinit).';
        }
        return msg;
    }
};
