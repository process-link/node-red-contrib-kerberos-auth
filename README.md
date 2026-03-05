# @processlink/node-red-contrib-kerberos-auth

Node-RED node for making HTTP requests with Kerberos/SPNEGO (Negotiate) authentication. Built for talking to OSIsoft/AVEVA PI Web API servers, but works with anything that uses Windows Negotiate auth.

## Why this exists

The built-in Node-RED HTTP request node doesn't support Kerberos. The `node-red-contrib-piwebapi` package only supports Basic auth. If your PI Web API server requires Windows authentication, you're stuck. This fixes that.

## Install

```bash
cd ~/.node-red
npm install @processlink/node-red-contrib-kerberos-auth
```

Or install from GitHub:

```bash
cd ~/.node-red
npm install github:process-link/node-red-contrib-kerberos-auth
```

Restart Node-RED after installing.

## How it works

The node uses the [kerberos](https://github.com/mongodb-js/kerberos) package to handle SPNEGO negotiation. On **Windows** it uses SSPI, on **Linux** it uses GSSAPI.

```
  Node-RED                                PI Web API             Active Directory
  (your flow)                             Server                 (KDC)
      │                                       │                       │
      │  1. Message hits the                   │                       │
      │     kerberos http node                 │                       │
      │                                        │                       │
      │  2. Node asks kerberos lib:            │                       │
      │     "I need to auth to                 │                       │
      │      HTTP@piserver"                    │                       │
      │         │                              │                       │
      │         │  3. Kerberos lib talks to AD ─┼──────────────────────▶│
      │         │     (SSPI on Win,            │  "Give me a ticket    │
      │         │      GSSAPI on Linux)        │   for HTTP@piserver"  │
      │         │                              │                       │
      │         │  4. AD returns a ◀───────────┼───────────────────────│
      │         │     service ticket           │  "Here's your ticket" │
      │         │                              │                       │
      │  5. Node sends HTTP request ──────────▶│                       │
      │     Authorization: Negotiate <token>   │                       │
      │                                        │                       │
      │                                        │  6. Server validates ─▶│
      │                                        │     ticket with AD    │
      │                                        │                       │
      │  7. Server returns data ◀──────────────│◀── "Yes, legit" ──────│
      │     (200 OK + JSON)                    │                       │
      ▼                                        ▼                       ▼
```

If the server returns 401, the node retries once with a fresh token.

## Nodes

### kerberos http (request node)

Drag this onto your flow. Works like the built-in HTTP request node but with Kerberos auth.

**Properties:**
- **Server** — pick a server config (see below)
- **Method** — GET, POST, PUT, DELETE, PATCH, or set via `msg.method`
- **URL Path** — appended to the server's base URL, or a full URL
- **Return** — parsed JSON, UTF-8 string, or binary buffer

**Input msg:**
- `msg.url` — override the URL path
- `msg.method` — override the method (when set to "set by msg.method")
- `msg.payload` — request body for POST/PUT/PATCH (objects are auto-serialized to JSON)
- `msg.headers` — extra headers to include

**Output msg:**
- `msg.payload` — response body
- `msg.statusCode` — HTTP status code
- `msg.headers` — response headers

### Server config node

Stores your connection details. Shared across all kerberos http nodes pointing to the same server.

**Settings:**
- **Base URL** — e.g. `https://piserver.domain.com/piwebapi`
- **Service FQDN** — hostname for the SPN (optional, extracted from URL if blank)
- **Verify SSL Certificate** — uncheck for self-signed certs
- **Domain / Username / Password** — AD credentials. On Windows, leave blank to use the current user's identity via SSPI.

## Platform setup

### Windows

No extra setup needed if your machine is domain-joined — leave the credentials blank and it uses your Windows login.

For non-domain machines, provide explicit domain/username/password in the server config.

### Linux

1. Install Kerberos dev libraries:
   ```bash
   # Debian/Ubuntu
   apt-get install libkrb5-dev

   # RHEL/CentOS
   yum install krb5-devel
   ```

2. Configure `/etc/krb5.conf` with your realm and KDC:
   ```ini
   [libdefaults]
       default_realm = YOURDOMAIN.COM

   [realms]
       YOURDOMAIN.COM = {
           kdc = your-dc-server.yourdomain.com
       }
   ```

3. Get a ticket before starting Node-RED:
   ```bash
   kinit youruser@YOURDOMAIN.COM
   ```

## Testing without Node-RED

There's a standalone test script to verify Kerberos works before you wire anything up:

1. Edit `test.js` with your server details and credentials
2. Run `node test.js`
3. If you see PI Web API system info, you're good

## Author

Built and maintained by [Process Link Pty Ltd](https://processlink.com.au).

## License

MIT
