<?php

namespace HughCube\HttpSecurity;

use Closure;
use HughCube\HttpSecurity\Exceptions\ClientIpHasChangeHttpException;
use HughCube\HttpSecurity\Exceptions\IpAccessDeniedHttpException;
use HughCube\HttpSecurity\Exceptions\UserAgentHasChangeHttpException;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Str;
use ReflectionClass;
use Symfony\Component\HttpFoundation\IpUtils;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class Middleware
{
    /**
     * The config repository instance.
     *
     * @var \Illuminate\Contracts\Config\Repository
     */
    protected $config;

    /**
     * Create a new trusted proxies middleware instance.
     *
     * @param \Illuminate\Contracts\Config\Repository $config
     */
    public function __construct(Repository $config)
    {
        $this->config = $config;
    }

    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request
     * @param \Closure $next
     *
     * @return mixed
     * @throws \ReflectionException
     *
     * @throws \Symfony\Component\HttpKernel\Exception\HttpException
     */
    public function handle(Request $request, Closure $next)
    {
        $response = $next($request);

        /**
         * Call all guards.
         */
        $reflection = new ReflectionClass($this);
        foreach ($reflection->getMethods() as $method) {
            if (!$method->isPublic() || !Str::endsWith($method->getName(), 'Guard')) {
                continue;
            }

            $method->invokeArgs($this, [$request, $response]);
        }

        return $response;
    }

    /**
     * @param string $key
     *
     * @return mixed
     */
    protected function getGuardConfig($key, $default = null)
    {
        return $this->config->get("httpSecurity.{$key}", $default);
    }

    /**
     * Determine if a session driver has been configured.
     *
     * @param Request $request
     * @return bool
     */
    protected function sessionIsStarted(Request $request)
    {
        /** @var \Illuminate\Contracts\Session\Session $session */
        $session = $request->getSession();

        return $session->isStarted();
    }

    protected function buildCacheKey($key)
    {
        return "HttpSecurity:" . md5(serialize($key));
    }

    /**
     * @param Request $request
     * @param Response $response
     */
    public function contentMimeGuard($request, $response)
    {
        if (false == $this->getGuardConfig('contentMime.enable')) {
            return;
        }

        if (!$response instanceof Response) {
            return;
        }

        $response->headers->set('X-Content-Type-Options', 'nosniff', false);
    }

    /**
     * @param Request $request
     * @param Response $response
     */
    public function poweredByHeaderGuard($request, $response)
    {
        if (false == $this->getGuardConfig('poweredByHeader.enable')) {
            return;
        }

        if (!$response instanceof Response) {
            return;
        }

        /**
         * Remove X-Powered-By header.
         */
        if (function_exists('header_remove')) {
            @header_remove('X-Powered-By'); // PHP 5.3+
        } else {
            @ini_set('expose_php', 'off');
        }

        $options = $this->getGuardConfig('poweredByHeader.options');
        if (null === $options) {
            return;
        }

        $response->headers->set('X-Powered-By', $options, false);
    }

    /**
     * @param Request $request
     * @param Response $response
     */
    public function uaCompatibleGuard($request, $response)
    {
        if (false == $this->getGuardConfig('uaCompatible.enable')) {
            return;
        }

        if (!$response instanceof Response) {
            return;
        }

        $policy = $this->getGuardConfig('uaCompatible.policy');
        if (null === $policy) {
            return;
        }

        $response->headers->set('X-Ua-Compatible', $policy, false);
    }

    /**
     * @param Request $request
     * @param Response $response
     */
    public function hstsGuard($request, $response)
    {
        $enable = $this->getGuardConfig('hsts.enable');
        if (false == (null === $enable ? $request->isSecure() : $enable)) {
            return;
        }

        if (!$response instanceof Response) {
            return;
        }

        $maxAge = $this->getGuardConfig('hsts.maxAge', -1);
        if (0 >= $maxAge) {
            return;
        }

        $includeSubDomains = $this->getGuardConfig('hsts.includeSubDomains', false);
        $preload = $this->getGuardConfig('hsts.preload', false);

        $header = '';
        $header .= ("max-age={$maxAge}");
        $header .= ($includeSubDomains ? '; includeSubDomains' : '');
        $header .= ($preload ? '; preload' : '');
        $response->headers->set('Strict-Transport-Security', $header, false);
    }

    /**
     * @param Request $request
     * @param Response $response
     */
    public function xssProtectionGuard($request, $response)
    {
        if (false == $this->getGuardConfig('xssProtection.enable')) {
            return;
        }

        if (!$response instanceof Response) {
            return;
        }

        $policy = $this->getGuardConfig('xssProtection.policy');
        if (null === $policy) {
            return;
        }

        $response->headers->set('X-XSS-Protection', strval($policy), false);
    }

    /**
     * @param Request $request
     * @param Response $response
     */
    public function refererHotlinkingGuard($request, $response)
    {
        if (false == $this->getGuardConfig('refererHotlinking.enable')) {
            return;
        }

        $allow = false;
        $referer = $request->headers->get('Referer');

        // 如果 Referer 为空直接通过
        $allowEmpty = $this->getGuardConfig('refererHotlinking.allowEmpty', true);
        if (!$allow && $allowEmpty && null == $referer) {
            $allow = true;
        }

        // 去匹配允许的条件, 如果 allowedPatterns 为空直接通过
        $allowPatterns = $this->getGuardConfig('refererHotlinking.allowPatterns', []);
        $allow = $allow || empty($allowPatterns);
        foreach ($allowPatterns as $pathPattern => $refererPatterns) {
            if ($allow) {
                break;
            }

            if (!Str::is($pathPattern, $request->getPathInfo())) {
                continue;
            }

            $allow = Str::is($refererPatterns, $referer);
            break;
        }

        // 不允许的
        $forbidPatterns = $this->getGuardConfig('refererHotlinking.forbidPatterns', []);
        foreach ($forbidPatterns as $pathPattern => $refererPatterns) {
            if (!$allow) {
                break;
            }

            if (!Str::is($pathPattern, $request->getPathInfo())) {
                continue;
            }

            $allow = !Str::is($refererPatterns, $referer);
            break;
        }

        if (!$allow) {
            # throw new RefererHotlinkingHttpException("HTTP referer not allow");
        }
    }

    /**
     * @param Request $request
     * @param Response $response
     */
    public function clientIpChangeGuard($request, $response)
    {
        if (false == $this->getGuardConfig('clientIpChange.enable')) {
            return;
        }

        if (!$this->sessionIsStarted($request)) {
            return;
        }

        $clientIpHash = crc32(serialize($request->getClientIp()));

        $sessionKey = $this->buildCacheKey(__METHOD__);
        if (!$request->getSession()->has($sessionKey)) {
            $request->getSession()->set($sessionKey, $clientIpHash);
        }

        if ($clientIpHash !== $request->getSession()->get($sessionKey)) {
            throw new ClientIpHasChangeHttpException('Ip has change.');
        }
    }

    /**
     * @param Request $request
     * @param Response $response
     */
    protected function userAgentChangeGuard($request, $response)
    {
        if (false == $this->getGuardConfig('userAgentChange.enable')) {
            return;
        }

        if (!$this->sessionIsStarted($request)) {
            return;
        }

        $userAgentHash = crc32(serialize($request->headers->get('User-Agent')));

        $sessionKey = $this->buildCacheKey(__METHOD__);
        if (!$request->getSession()->has($sessionKey)) {
            $request->getSession()->set($sessionKey, $userAgentHash);
        }

        if ($userAgentHash !== $request->getSession()->get($sessionKey)) {
            throw new UserAgentHasChangeHttpException('User-Agent has change.');
        }
    }

    /**
     * @param Request $request
     * @param Response $response
     */
    protected function ipAccessGuard($request, $response)
    {
        if (false == $this->getGuardConfig('ipAccess.enable')) {
            return;
        }

        $clientIp = $request->getClientIp();
        if (null == $clientIp) {
            return;
        }

        $allow = false;

        // 去匹配允许条件, 如果 allowedIps 为空直接通过
        $allowedIps = $this->getGuardConfig('ipAccess.allowedIps', []);
        $allow = ($allow || empty($allowedIps));
        foreach ($allowedIps as $pathPattern => $ipPatterns) {
            if ($allow) {
                break;
            }

            if (!Str::is($pathPattern, $request->getPathInfo())) {
                continue;
            }

            $allow = IpUtils::checkIp($clientIp, $ipPatterns);
            break;
        }

        // 不允许的
        $forbidPatterns = $this->getGuardConfig('ipAccess.forbidIps', []);
        foreach ($forbidPatterns as $pathPattern => $ipPatterns) {
            if (!$allow) {
                break;
            }

            if (!Str::is($pathPattern, $request->getPathInfo())) {
                continue;
            }

            $allow = !IpUtils::checkIp($clientIp, $ipPatterns);
            break;
        }

        if (!$allow) {
            throw new IpAccessDeniedHttpException('Not allowed ip.');
        }
    }
}
