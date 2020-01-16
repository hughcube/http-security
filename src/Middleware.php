<?php

namespace HughCube\HttpSecurity;

use Closure;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use ReflectionClass;
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
     * @param string $key
     *
     * @return mixed
     */
    protected function getGuardConfig($key, $default = null)
    {
        return $this->config->get("httpSecurity.{$key}", $default);
    }

    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request
     * @param \Closure                 $next
     *
     * @throws \Symfony\Component\HttpKernel\Exception\HttpException
     * @throws \ReflectionException
     *
     * @return mixed
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
     * @param Request  $request
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
     * @param Request  $request
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
     * @param Request  $request
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
     * @param Request  $request
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
     * @param Request  $request
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
}
