<?php

namespace HughCube\HttpSecurity;

use Illuminate\Foundation\Application as LaravelApplication;
use Illuminate\Foundation\Http\Kernel;
use Illuminate\Support\ServiceProvider as BaseServiceProvider;
use Laravel\Lumen\Application as LumenApplication;

class ServiceProvider extends BaseServiceProvider
{
    /**
     * Boot the service provider.
     *
     * @return void
     */
    public function boot()
    {
        $this->registerConfig();
        $this->prependMiddleware();
    }

    /**
     * Prepend the middleware.
     *
     * @return void
     */
    protected function prependMiddleware()
    {
        if ($this->app instanceof LaravelApplication && !$this->app->runningInConsole()){
            /** @var Kernel $kernel */
            $kernel = $this->app->make(Kernel::class);
            $kernel->prependMiddleware(Middleware::class);
        }//

        elseif ($this->app instanceof LumenApplication){
            $this->app->middleware([Middleware::class]);
        }
    }

    /**
     * Register the service provider config.
     *
     * @return void
     */
    protected function registerConfig()
    {
        $source = realpath($raw = __DIR__ . '/../config/httpSecurity.php') ?: $raw;

        if ($this->app instanceof LaravelApplication && $this->app->runningInConsole()){
            $this->publishes([$source => config_path('httpSecurity.php')]);
        }//
        elseif ($this->app instanceof LumenApplication){
            $this->app->configure('httpSecurity');
        }

        if ($this->app instanceof LaravelApplication && !$this->app->configurationIsCached()){
            $this->mergeConfigFrom($source, 'httpSecurity');
        }
    }

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        //
    }
}
