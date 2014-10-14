<?php

namespace TTools\Provider\Silex;

use TTools\App;
use TTools\Provider\Silex\SilexStorageSession;
use TTools\Provider\Silex\SilexRequestProvider;
use Pimple\Container;
use Pimple\ServiceProviderInterface;

class TToolsServiceProvider implements ServiceProviderInterface{

    public function register(Container $app)
    {
        $app['ttools'] = $app->share(function ($app) {
           
            $storage_provider = null;
            $request_provider = null;

            $config = array(
                'consumer_key'        => $app['ttools.consumer_key'],
                'consumer_secret'     => $app['ttools.consumer_secret'],
                'access_token'        => isset($app['ttools.access_token']) ? $app['ttools.access_token'] : null,
                'access_token_secret' => isset($app['ttools.access_token_secret']) ? $app['ttools.access_token_secret'] : null,
                'auth_method'         => isset($app['ttools.auth_method']) ? $app['ttools.auth_method'] : null,
            );
            if (isset($app['session'])) {
                $storage_provider = new SilexStorageSession($app['session']);
            }

            $request_provider = new SilexRequestProvider($app['request']);

            return new App($config, $storage_provider, $request_provider);
        });

    }

    public function boot(Application $app)
    {
    }
}
