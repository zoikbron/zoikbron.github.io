---
title: "Google Botguard Bypass - Custom Modification Evilginx2"
date: 2026-05-26 12:00:00 -500
categories: [security, phishing, browser-security]
tags: [reverse-proxy, telemetry, javascript, anti-phishing, session-security]
excerpt: "An overview of how modern web applications use telemetry-based secret tokens to detect reverse proxy phishing attacks and the limitations of stateless authentication flows."
image:
  path: /assets/img/posts/phishing/evilginx-bg-21eyJ_Yy.png
---

## Overview

> Most of the things I’ll be talking about here come from other people’s research, which I ultimately used to create my own implementation, along with multiple hints that the creator of Evilginx Pro shared on his blog about the approach he took for the Pro version. My goal with this blog is to walk through the investigation process and, later on, the implementations that came out of that research, while also providing insight into the concepts and understanding required to build something similar on your own. I won’t be providing plug-and-play code or ready-to-use implementations. If that’s what you’re looking for, then you should probably pay for the Pro version.
{: .prompt-info}

* [Google Botguard Security Research](https://github.com/tomkabel/google-botguard-security-research)
* [Botguard VM Reverse Engineering](https://github.com/dsekz/botguard-reverse)
* [Evilginx Pro](https://evilginx.com)
* [BreakDev Blog](https://breakdev.org)

This implementation effort was largely driven by necessity and experimentation. It was built primarily around modifications to the open-source Evilginx2 framework combined with a custom browser automation implementation. The process involved integrating a WebDriver-based automation layer with Evilginx2 in order to coordinate background browser sessions and authentication flows.

A major part of the research focused on identifying exactly:

* Where the telemetry token was generated
* Where the token was temporarily stored client-side
* How it moved through the login workflow
* Which requests transmitted the token to the server
* How the server validated the telemetry during authentication

After mapping the flow, custom interceptors and handlers were implemented to capture and process the required values at the correct stages of the authentication sequence.

--- 
## Secret Token Protections

Modern phishing kits have evolved significantly beyond static credential collection pages. Today, many attacks rely on reverse proxy architectures that relay traffic between a victim and a legitimate service in real time. This enables attackers to capture authenticated sessions, bypass MFA workflows, and impersonate users.

To counter these attacks, some large platforms have introduced additional browser telemetry protections implemented through heavily obfuscated JavaScript.

One of the more interesting mechanisms is the use of what can be described as a **secret token**.


### What Is a Secret Token?

A secret token is typically an encrypted or encoded payload generated client-side inside the browser.

The token commonly contains telemetry such as:

- Browser environment information
- Navigation context
- Timing metrics
- JavaScript execution characteristics
- Current URL or origin data
- Device fingerprints
- Behavioral indicators

This value is often transmitted as a hidden POST parameter during the authentication process.

Once received by the server, the token is decrypted and analyzed for anomalies that may indicate:

- Browser automation
- Headless environments
- Reverse proxy phishing infrastructure
- Domain mismatches
- Suspicious request forwarding behavior

For example, if a login flow expects the browser to be operating on a legitimate domain but the telemetry indicates a phishing origin, the authentication attempt may be flagged or blocked.

### Reverse Proxy Detection

Traditional phishing pages simply imitate login forms.

Reverse proxy phishing is different. Instead of recreating the authentication process, the phishing server forwards requests directly to the legitimate website while relaying responses back to the victim. This allows the attacker to capture session cookies, relay MFA prompts, maintain a live authenticated session and avoid needing the victim's password after login.

Because the traffic ultimately reaches the legitimate service, conventional credential validation defenses are insufficient.
As a result, providers increasingly rely on browser telemetry and contextual validation.

### The Role of Browser Telemetry

Modern anti-phishing systems often rely heavily on JavaScript-based telemetry collection.

These scripts may gather:

```javascript
const telemetry = {
  userAgent: navigator.userAgent,
  language: navigator.language,
  timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
  screen: {
    width: screen.width,
    height: screen.height
  },
  url: window.location.href,
  timing: performance.now()
};
```

In practice, production implementations are substantially more complex and frequently obfuscated.
Some protections dynamically generate cryptographic payloads that are validated server-side before authentication can continue.

### Stateless Authentication and a Design Limitation

One of the underlying challenges is that HTTP is fundamentally stateless.

Although applications emulate state using:

- Cookies
- Session IDs
- Authorization headers
- CSRF tokens

## What is Botguard?

Botguard is Google's client-side anti-fraud and anti-bot system, deployed on Google login pages, ReCaptcha v2/v3, and YouTube. It's commonly mistaken for a simple browser fingerprinting script, it is not. It is a full custom Virtual Machine (VM) running inside the user's browser, written in obfuscated JavaScript. Its job is to verify that the person interacting with the page is a real human using a legitimate browser environment.


### The VM Architecture

When a page loads, Botguard boots a CPU-like processor inside the browser:
It uses a register-based architecture (similar to x86), with named registers holding state and operational data.
It loads and executes custom bytecode, binary instructions that you cannot simply read or beautify.
The bytecode is loaded from an obfuscated string, with a dynamic key derived at runtime to prevent static analysis tools from finding the entry point.
Crucially, it uses self-modifying code: the VM generates new opcodes at runtime using EVAL-like operations, so the code running at the end is different from what was loaded at the start.


Key identified instructions include arithmetic/bitwise ops, object property manipulation (likely to check for webdriver flags), and a HALT opcode that kills execution if tampering is detected.

### Anti-Tamper Mechanisms

Botguard actively fights reverse engineering in two clever ways:

1. Chronometric Defense (Anti-Debug)

The VM constantly polls performance.now() and Date.now(). If you pause execution with a debugger, the elapsed time grows too large. This time delta corrupts a seed value (K.U) used to decrypt the next block of bytecode. The program doesn't crash visibly, it silently diverges into a garbage execution path and generates an invalid token.

2. Anti-Logger
The script aggressively overrides console methods. If you try to inject a console.log or conditional breakpoint, it triggers a trap that shifts an internal memory pointer, causing the VM to read the wrong bytes and corrupting the instruction stream. The session dies quietly.


### Secret Token Weakness
Despite all this complexity, the research [Google Botguard Security Research](https://github.com/tomkabel/google-botguard-security-research) identified a fundamental architectural flaw: the server validates token integrity, not token origin. A token minted in a clean environment is indistinguishable from one minted by a real user.

The bypass (demonstrated in 2021) used a headless browser (go-rod/Golang) with stealth patches to mask navigator.webdriver and spoof WebGL/user-agent signals. This "puppet" browser navigated to Google's login page, let Botguard run fully, extracted the minted token before it was consumed, and injected it into a separate (attacker-controlled) session. No VM opcodes needed to be cracked.

## What is needed to fight against BotGuard
To bypass Google’s BotGuard protection, is necessary the utilization of an undetected web browser with automation capabilities, Kuba Gretzky called it  Puppet  or (evilpuppet) which servers a module to harvest secrets token and inject it into the victim’s request.

* This approach is especially effective for bypassing secret token-based protections like Google's BotGuard. As explained in the multiple researches, secret tokens are generated by client-side JavaScript to telemetry data (often including the visited URL) and are used to detect reverse proxy attempts. By running a genuine Chromium instance via puppet, we can obtain valid tokens that reflect the victim's browser context, making them indistinguishable from legitimate traffic.

### Investigating Where Secret Tokens Play a Role

Before implementing the puppet-based solution, it's crucial to understand where in the login flow the secret token (like Google's BotGuard) is generated and validated. Here's a step-by-step approach to investigate this:

1. **Start with public phishlets** - Try using existing phishlets for Google/Microsoft/Linkedin login . On Google specifics you'll likely encounter warnings like "This browser or App may not be secure" during the email entry phase.

![Warning Google](/assets/img/posts/phishing/Warning.png)

2. **Use Burp Suite for interception** - Set up Burp Suite to intercept and analyze the traffic between the victim's browser and Google's servers.

3. **Observe the login flow in a real browser** - Manually go through the Google login process in a regular browser while monitoring the requests in Burp Suite. Pay close attention to:
   - The initial email submission request
   - Any subsequent requests that might carry security tokens
   - Parameters that change between requests

4. **Identify the breaking point** - Systematically modify parameters in the intercepted requests to see which specific change triggers the security warning. The parameter that, when altered, causes Google to show the "browser may not be secure" message is likely carrying the secret token.

5. **Extract and validate** - Once you've identified the token parameter (in Google's case, it's the `bg_token`), you can:
   - Configure puppet to extract this token from a legitimate browser session
   - Inject it into the victim's request before it reaches Google
   - Verify that the security warning disappears

This investigation process reveals that secret tokens like BotGuard are typically generated early in the login flow and are tied to the browser's fingerprint rather than being session-specific, making them ideal targets for puppet-based extraction and injection.

### How Puppet Works Alongside Evilginx2

The Go proxy and the Node.js puppet run as two independent processes, but they coordinate through a straightforward request/response exchange:

1. **Request from Go** – When processing a victim’s request that matches an `evilpuppet` trigger (e.g., a POST containing the email), the Go code calls `p.puppetClient.SpawnEvilPuppet(...)`. This builds a JSON payload describing what the puppet should do (the target URL, the actions to perform, and which data to capture) and sends it via an HTTP POST to the puppet’s `/evilpuppet/spawn` endpoint.

2. **Waiting** – The Go call does not return until the puppet finishes its work (or times out). Inside the puppet, Puppeteer launches Chrome, carries out the actions (e.g., typing the email and clicking “Next”), intercepts the outgoing network request that contains the BotGuard token, extracts that token, and (if `abort:true`) aborts the request so it never reaches Google. The puppet then packages the captured token (and any cookies) into a JSON response and sends it back to the Go proxy.

3. **Result in Go** – Once the HTTP response arrives, the Go code stores the received token (e.g., `bg_token`) in the victim’s session data. At this point the puppet’s work is done and its browser is closed (because `keep_alive:false`), guaranteeing that no further traffic from the puppet will reach Google.

4. **Using the token** – The original victim’s request continues through the proxy. After the request body has been read, the Go code checks whether the session already holds a `bot_token` from the puppet. If it does, it simply replaces the victim’s own BotGuard token in the post_data parameter with the puppet‑captured one, then lets the request proceed to Google.

Because the Go call waits for the puppet to finish, the token is guaranteed to be available before we modify the victim’s request. The two processes stay in sync without any complex shared state—just a simple HTTP handshake.

### Core Idea

Google’s BotGuard signs a token (`bg_token`). Instead of trying to mimic the browser fingerprint, we let a real Chromium instance (controlled by Puppet) generate a valid token for the exact same login context, then transfer that token to the victim’s request while ensuring the Puppet’s own traffic never reaches Google.


## Implementations

### 1. Puppet‑enabled phishlet

To make this possible was necessary to create a puppet client `evilginx2/core/puppet` client and hooks for starting/stopping puppets. And based on the definitions on the phishlets make the puppet behave properly.

### 2. Evilpuppet configuration in the Google phishlet

In `google2.yaml` we added an `evilpuppet` block:

```yaml
evilpuppet:
  triggers:
    - domains: ['accounts.google.com']
      paths:
        - 'path_login_post'
      method: 'POST'
      token: 'post_data_parameter_containing_botguard_token'               # what we will replace in the victim’s request
      target_token: 'bg_token'     # puppet waits until it captures this token
      open_url: 'https://accounts.google.com/AccountChooser/signinchooser?service=mail&continue=https%3A%2F%2Fmail.google.com%2Fmail%2F&flowName=GlifWebSignIn&flowEntry=AccountChooser&ec=asw-gmail-globalnav-signin'
      keep_alive: false
      humanize: false
      actions:
        - selector: 'input[type="email"]'
          value: '{username}'
          enter: false
          type_delay: 0            # instant typing
          post_wait: 300
        - selector: 'div[id="identifierNext"] button, #identifierNext button'
          click: true
          post_wait: 2500          # wait for the botguard token to appear
  interceptors:
    - token: 'bg_token'            # the BotGuard blob
      url_re: 'accounts\.google\.com/path_login_post'
      abort: true                  # <‑‑ drop the puppet’s request after capturing the blob
      post_re: 'token_botguard_google(![A-Za-z0-9_-]+)'
```

* The `open_url` exactly matches the URL the victim is sent to (from the `login` section)
* The `bg_token` interceptor extracts the token from the `post_data_parameter` parameter and then **aborts** the puppet’s request so Google only sees the victim’s traffic.

### 3. Token injection in the proxy

When the victim submits their email (the first `path_login_post` POST containing `post_data`), the proxy checks whether the current session already has a `bg_token` captured from the puppet. If so, it replaces the victim’s own BotGuard token with the puppet‑captured one.

In `core/http_proxy.go`, inside the request‑handling loop after the form body is parsed:

```go
if s, ok := p.sessions[ps.SessionId]; ok {
    if bgToken, exists := s.PuppetTokens["bg_token"]; exists && bgToken != "" {
        bgRe := regexp.MustCompile(`token_botguard_google(?:!|%21)[A-Za-z0-9_-]+`)
        bodyStr := string(body)
        if bgRe.MatchString(bodyStr) {
            bgValue := strings.TrimPrefix(bgToken, "!")
            replacement := "token_botguard_google%5C%22%2C%5C%22%21" + bgValue
            bodyStr = bgRe.ReplaceAllLiteralString(bodyStr, replacement)
            body = []byte(bodyStr)
            req.ContentLength = int64(len(body))
            // Log for debugging (optional)
        }
    }
}
```

* The regex matches both the raw `!` (as sent by the browser) and the URL‑encoded `%21` (as produced by `url.Values.Encode()` after the form branch).
* Because the puppet’s request was aborted (see `abort: true` above), the victim’s request is the only one that reaches Google, now carrying the puppet’s BotGuard token.  

## Resulting Flow

1. Victim lands on the lure → proxy serves the fake Google login page (via the phishlet).
2. Victim enters email and clicks “Next” → their browser sends a `path_login_post` POST containing data with the email.
3. The proxy recognises this as the "evilpuppet" trigger (via the `evilpuppet` block) and:
   * spawns a puppet session that navigates to the exact same `open_url`,
   * fills in the victim’s email,
   * clicks “Next”.
4. The puppet’s outbound `path_login_post` is intercepted by the Puppet service:
   * the `bg_token` interceptor extracts the BotGuard blob from the post parameter containing the data,
   * the request is **aborted** (`abort: true`), so Google never sees the puppet’s attempt,
5. The victim’s original request continues through the proxy; the request‑handling code detects the presence of `bgToken` in `s.PuppetTokens` and replaces the victim’s own BotGuard blob with the puppet’s version.
6. The victim’s request (now carrying the puppet‑sourced BotGuard token and the victim’s genuine User‑Agent/header context) reaches Google and passes the BotGuard check.
7. Subsequent steps (password submission) proceed normally; the BotGuard token from step 1 remains valid for the session because it is bound to the browser fingerprint, which the victim supplies.
8. Session cookies (`SID`, `SSID`, etc.) are harvested via the `auth_tokens` mechanism and logged as usual.
<style>
.video-container {
    position: relative;
    width: 80%;
    max-width: 900px;
    padding-bottom: 45%;
    height: 0;
    margin: 30px auto;
}

.video-container iframe {
    position: absolute;
    width: 100%;
    height: 100%;
}
</style>
<div class="video-container">
  <iframe width="420" height="315" src="https://www.youtube.com/embed/WUm-qA0-vQI" frameborder="0" allowfullscreen></iframe>
</div>


## Conclusion

By configuring an evilpuppet to harvest the BotGuard token and aborting its own request, then injecting that token into the victim’s `post_data` payload, we bypass Google’s BotGuard protection. This approach showcases how Evilginx2’s modular design lets an operator plug in sophisticated, target‑specific bypasses while leaving the bulk of the code unchanged.




