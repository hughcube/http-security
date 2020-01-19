<?php

namespace HughCube\HttpSecurity\Tests;

use HughCube\HttpSecurity\Middleware;
use HughCube\HttpSecurity\ServiceProvider;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Foundation\Testing\TestResponse;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;

class MiddlewareTest extends \Orchestra\Testbench\TestCase
{
    use ValidatesRequests;

    protected function resolveApplicationConfiguration($app)
    {
        $_ENV['APP_DEBUG'] = true;
        parent::resolveApplicationConfiguration($app);
    }

    protected function getPackageProviders($app)
    {
        return [ServiceProvider::class];
    }

    /**
     * @return \Illuminate\Config\Repository
     */
    protected function getAppConfig()
    {
        return $this->app['config'];
    }

    /**
     * Define environment setup.
     *
     * @param \Illuminate\Foundation\Application $app
     *
     * @return void
     */
    protected function getEnvironmentSetUp($app)
    {
        /** @var Kernel $kernel */
        $kernel = $app->make(Kernel::class);
        $kernel->prependMiddleware(Middleware::class);

        /** @var Router $router */
        $router = $app['router'];

        $this->addRoutes($router);
    }

    /**
     * @param Router $router
     */
    protected function addRoutes($router)
    {
        $router->get('ping', [
            'uses' => function (Request $request) {
                return 'PONG';
            },
        ]);

        $router->post('ping', [
            'uses' => function (Request $request) {
                return 'PONG';
            },
        ]);

        $router->put('ping', [
            'uses' => function (Request $request) {
                return 'PONG';
            },
        ]);

        $router->options('ping', [
            'uses' => function (Request $request) {
                return 'PONG';
            },
        ]);

        $router->get('error', [
            'uses' => function (Request $request) {
                abort(500);
            },
        ]);

        $router->get('validation', [
            'uses' => function (Request $request) {
                $this->validate($request, ['name' => 'required']);

                return 'ok';
            },
        ]);
    }

    /**
     * @return TestResponse[]
     */
    protected function createCrawlers()
    {
        return [
            $this->call('GET', 'ping'),
            $this->call('POST', 'ping'),
            $this->call('PUT', 'ping'),
            $this->call('OPTIONS', 'ping'),
            #$this->call('GET', 'error'),
            #$this->call('GET', 'validation'),
        ];
    }

    public function testContentMimeGuard()
    {
        foreach ($this->createCrawlers() as $crawler) {
            $this->assertEquals('nosniff', $crawler->headers->get('X-Content-Type-Options'));
        }

        $this->getAppConfig()->set('httpSecurity.contentMime.enable', true);
        foreach ($this->createCrawlers() as $crawler) {
            $this->assertEquals('nosniff', $crawler->headers->get('X-Content-Type-Options'));
        }

        $this->getAppConfig()->set('httpSecurity.contentMime.enable', false);
        foreach ($this->createCrawlers() as $crawler) {
            $this->assertEquals(null, $crawler->headers->get('X-Content-Type-Options'));
        }
    }

    public function testPoweredByHeaderGuard()
    {
        foreach ($this->createCrawlers() as $crawler) {
            $this->assertEquals(null, $crawler->headers->get('X-Powered-By'));
        }

        $this->getAppConfig()->set('httpSecurity.poweredByHeader.enable', false);
        foreach ($this->createCrawlers() as $crawler) {
            $this->assertEquals(null, $crawler->headers->get('X-Powered-By'));
        }

        $this->getAppConfig()->set('httpSecurity.poweredByHeader.enable', true);
        foreach ($this->createCrawlers() as $crawler) {
            $this->assertEquals(null, $crawler->headers->get('X-Powered-By'));
        }

        $this->getAppConfig()->set('httpSecurity.poweredByHeader.enable', true);
        $this->getAppConfig()->set('httpSecurity.poweredByHeader.options', 'PHP:' . PHP_VERSION);
        foreach ($this->createCrawlers() as $crawler) {
            $this->assertEquals('PHP:' . PHP_VERSION, $crawler->headers->get('X-Powered-By'));
        }
    }

    public function testUaCompatibleGuard()
    {
        foreach ($this->createCrawlers() as $crawler) {
            $this->assertEquals('IE=Edge,chrome=1', $crawler->headers->get('X-Ua-Compatible'));
        }

        $this->getAppConfig()->set('httpSecurity.uaCompatible.enable', false);
        foreach ($this->createCrawlers() as $crawler) {
            $this->assertEquals(null, $crawler->headers->get('X-Ua-Compatible'));
        }

        $this->getAppConfig()->set('httpSecurity.uaCompatible.enable', true);
        $this->getAppConfig()->set('httpSecurity.uaCompatible.policy', null);
        foreach ($this->createCrawlers() as $crawler) {
            $this->assertEquals(null, $crawler->headers->get('X-Ua-Compatible'));
        }

        $this->getAppConfig()->set('httpSecurity.uaCompatible.enable', true);
        $this->getAppConfig()->set('httpSecurity.uaCompatible.policy', PHP_VERSION);
        foreach ($this->createCrawlers() as $crawler) {
            $this->assertEquals(PHP_VERSION, $crawler->headers->get('X-Ua-Compatible'));
        }
    }

    public function testHstsGuard()
    {
        foreach ($this->createCrawlers() as $crawler) {
            $this->assertEquals(null, $crawler->headers->get('Strict-Transport-Security'));
        }

        $this->getAppConfig()->set('httpSecurity.hsts.enable', false);
        foreach ($this->createCrawlers() as $crawler) {
            $this->assertEquals(null, $crawler->headers->get('Strict-Transport-Security'));
        }

        $this->getAppConfig()->set('httpSecurity.hsts.enable', true);
        foreach ($this->createCrawlers() as $crawler) {
            $this->assertEquals(
                'max-age=31536000; includeSubDomains; preload',
                $crawler->headers->get('Strict-Transport-Security')
            );
        }

        $this->getAppConfig()->set('httpSecurity.hsts.maxAge', -1);
        foreach ($this->createCrawlers() as $crawler) {
            $this->assertEquals(null, $crawler->headers->get('Strict-Transport-Security'));
        }

        $this->getAppConfig()->set('httpSecurity.hsts.enable', true);
        $this->getAppConfig()->set('httpSecurity.hsts.maxAge', 60);

        $this->getAppConfig()->set('httpSecurity.hsts.includeSubDomains', true);
        foreach ($this->createCrawlers() as $crawler) {
            $this->assertEquals(
                'max-age=60; includeSubDomains; preload',
                $crawler->headers->get('Strict-Transport-Security')
            );
        }

        $this->getAppConfig()->set('httpSecurity.hsts.includeSubDomains', false);
        foreach ($this->createCrawlers() as $crawler) {
            $this->assertEquals(
                'max-age=60; preload',
                $crawler->headers->get('Strict-Transport-Security')
            );
        }

        $this->getAppConfig()->set('httpSecurity.hsts.preload', false);
        foreach ($this->createCrawlers() as $crawler) {
            $this->assertEquals(
                'max-age=60',
                $crawler->headers->get('Strict-Transport-Security')
            );
        }

        $this->getAppConfig()->set('httpSecurity.hsts.preload', true);
        foreach ($this->createCrawlers() as $crawler) {
            $this->assertEquals(
                'max-age=60; preload',
                $crawler->headers->get('Strict-Transport-Security')
            );
        }
    }

    public function testXssProtectionGuard()
    {
        foreach ($this->createCrawlers() as $crawler) {
            $this->assertEquals('1', $crawler->headers->get('X-XSS-Protection'));
        }

        $this->getAppConfig()->set('httpSecurity.xssProtection.enable', false);
        foreach ($this->createCrawlers() as $crawler) {
            $this->assertEquals(null, $crawler->headers->get('X-XSS-Protection'));
        }

        $this->getAppConfig()->set('httpSecurity.xssProtection.enable', true);
        $this->getAppConfig()->set('httpSecurity.xssProtection.policy', null);
        foreach ($this->createCrawlers() as $crawler) {
            $this->assertEquals(null, $crawler->headers->get('X-XSS-Protection'));
        }

        $this->getAppConfig()->set('httpSecurity.xssProtection.enable', true);
        $this->getAppConfig()->set('httpSecurity.xssProtection.policy', PHP_VERSION);
        foreach ($this->createCrawlers() as $crawler) {
            $this->assertEquals(PHP_VERSION, $crawler->headers->get('X-XSS-Protection'));
        }
    }

    public function testRefererHotlinkingGuard()
    {
        $this->markTestSkipped();
    }

    public function testClientIpChangeGuard()
    {
        $this->markTestSkipped();
    }

    public function testUserAgentChangeGuard()
    {
        $this->markTestSkipped();
    }

    public function testIpAccessGuard()
    {
        $this->markTestSkipped();
    }
}
