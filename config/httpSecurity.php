<?php

return [
    /**
     * The X-Content-Type-Options response HTTP header is a marker used by the server to indicate
     * that the MIME types advertised in the Content-Type headers should not be changed and be followed.
     * This allows to opt-out of MIME type sniffing, or, in other words, it is a way to say that
     * the webmasters knew what they were doing.
     *
     * @see https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/X-Content-Type-Options
     */
    'contentMime' => [
        'enable' => true,
    ],

    /**
     * @see https://www.php.net/manual/zh/function.header-remove.php
     */
    'poweredByHeader' => [
        'enable' => true,
        'options' => null,
    ],

    /**
     * @see https://developer.mozilla.org/zh-CN/docs/Mozilla/Persona/Browser_compatibility
     * @see https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/cc288325(v=vs.85)?redirectedfrom=MSDN
     */
    'uaCompatible' => [
        'enable' => true,
        'policy' => "IE=Edge,chrome=1"
    ],

    /**
     * The HTTP Strict-Transport-Security response header (often abbreviated as HSTS)
     * lets a web site tell browsers that it should only be accessed using HTTPS, instead of using HTTP.
     *
     * @see https://developer.mozilla.org/zh-CN/docs/Security/HTTP_Strict_Transport_Security
     */
    'hsts' => [
        'enable' => null,

        /**
         * The time, in seconds, that the browser should remember that a site is only to be accessed using HTTPS.
         */
        'maxAge' => 31536000,

        /**
         * If this optional parameter is specified, this rule applies to all of the site's subdomains as well.
         */
        'includeSubDomains' => true,

        /**
         * See Preloading Strict Transport Security for details. Not part of the specification.
         */
        'preload' => true,
    ],

    /**
     * The HTTP X-XSS-Protection response header is a feature of Internet Explorer, Chrome and Safari
     * that stops pages from loading when they detect reflected cross-site scripting (XSS) attacks.
     * Although these protections are largely unnecessary in modern browsers when sites implement a
     * strong Content-Security-Policy that disables the use of inline JavaScript ('unsafe-inline'),
     * they can still provide protections for users of older web browsers that don't yet support CSP.
     *
     * @see https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/X-XSS-Protection
     * @see https://developer.mozilla.org/zh-CN/docs/Web/HTTP/CSP
     */
    'xssProtection' => [
        'enable' => true,

        /**
         * 0: Disables XSS filtering.
         * 1: Enables XSS filtering (usually default in browsers).
         *    If a cross-site scripting attack is detected, the browser will sanitize the page (remove the unsafe parts).
         * 1; mode=block: Enables XSS filtering. Rather than sanitizing the page, the browser will prevent rendering of the page if an attack is detected.
         * 1; report=<reporting-URI> (Chromium only): Enables XSS filtering. If a cross-site scripting attack is detected, the browser will sanitize the page and report the violation.
         *    This uses the functionality of the CSP report-uri directive to send a report.
         */
        'policy' => 1,
    ],
];
