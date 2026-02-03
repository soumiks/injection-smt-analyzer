# Axios SSRF (CVE-2020-28168)

**CVE-2020-28168**: Server-Side Request Forgery via proxy bypass on redirect

## Vulnerability Summary

Axios versions before 0.21.1 are vulnerable to SSRF when using proxy configuration. The vulnerability allows attackers to bypass proxy settings by providing a URL that responds with a redirect to a restricted host or IP address.

When a proxy is configured, the initial request correctly goes through the proxy. However, if the server responds with a redirect (e.g., HTTP 302), the redirect request does NOT go through the proxy, allowing an attacker to reach internal services that should be blocked.

## Affected Code

**Vulnerable Location**: `lib/adapters/http.js`

In the vulnerable version, proxy settings are only applied to the initial request:

```javascript
if (proxy) {
  options.hostname = proxy.host;
  options.host = proxy.host;
  options.port = proxy.port;
  options.path = protocol + '//' + parsed.hostname + ...;
  
  // But no beforeRedirect callback!
}
```

## Attack Vector

1. Attacker controls a server that returns a redirect
2. User makes axios request through a proxy to the attacker's server
3. Attacker's server responds with 302 redirect to internal service (e.g., `http://localhost:6379`)
4. Axios follows the redirect WITHOUT going through the proxy
5. Attacker gains access to internal service

Example malicious server:
```javascript
// Attacker's server
app.get('/evil', (req, res) => {
  res.redirect('http://localhost:6379/');  // Redis
});

// Victim's code
await axios.get('http://attacker.com/evil', {
  proxy: { host: 'proxy.company.com', port: 8080 }
});
// Vulnerable version: redirect bypasses proxy!
```

## Detection Strategy

Our detector identifies:

1. **Proxy configuration**: Setting `options.hostname`, `options.port` from proxy config
2. **Missing redirect protection**: No `beforeRedirect` callback to re-apply proxy settings
3. **Vulnerable pattern**: Proxy settings applied but redirects not handled

## Fix

**Fixed in**: v0.21.1

The fix adds a `beforeRedirect` callback that re-applies proxy settings on redirects:

```javascript
function setProxy(options, proxy, location) {
  options.hostname = proxy.host;
  options.port = proxy.port;
  options.path = location;
  
  // Key fix: ensure redirects also go through proxy
  options.beforeRedirect = function beforeRedirect(redirection) {
    redirection.headers.host = redirection.host;
    setProxy(redirection, proxy, redirection.href);
  };
}
```

## Versions

- **Vulnerable**: v0.21.0 (tag: `v0.21.0`)
- **Fixed**: v0.21.1 (tag: `v0.21.1`)

## References

- [GitHub Advisory GHSA-4w2v-q235-vp99](https://github.com/advisories/GHSA-4w2v-q235-vp99)
- [CVE-2020-28168](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-28168)
- [Snyk Advisory SNYK-JS-AXIOS-1038255](https://snyk.io/vuln/SNYK-JS-AXIOS-1038255)
- [Original Issue #3407](https://github.com/axios/axios/issues/3407)

## Setup

Clone the vulnerable and fixed versions:

```bash
./clone.sh
```

This creates two directories:
- `axios_vuln/` - v0.21.0 (vulnerable)
- `axios_fixed/` - v0.21.1 (patched)

## Usage

Run the detector:

```bash
# Check vulnerable version
isa analyze axios_ssrf axios_vuln --legacy

# Check fixed version
isa analyze axios_ssrf axios_fixed --legacy
```

Expected output:
- Vulnerable version: VULNERABLE (proxy settings applied but no beforeRedirect)
- Fixed version: NOT VULNERABLE (beforeRedirect callback present)
