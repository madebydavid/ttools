[![Latest Stable Version](https://poser.pugx.org/ttools/ttools/v/stable.png)](https://packagist.org/packages/ttools/ttools) [![Total Downloads](https://poser.pugx.org/ttools/ttools/downloads.png)](https://packagist.org/packages/ttools/ttools) [![Latest Unstable Version](https://poser.pugx.org/ttools/ttools/v/unstable.png)](https://packagist.org/packages/ttools/ttools) [![License](https://poser.pugx.org/ttools/ttools/license.png)](https://packagist.org/packages/ttools/ttools)

ttools 2.1
======

TTools (Twitter Tools) Library aims to make life easier for twitter app developers, providing a simple workflow for authentication, while maintaining a high-level of flexibility for various types of applications.

Installation via Composer
=====

Add this requirement to your composer.json file:

<pre>
{
    "require": {
            "ttools/ttools": "2.1.*"
    }
}

</pre>

Basic Usage
======

### Static Apps

    <?php
    $config = array(
        'consumer_key'        => 'APP_CONSUMER_KEY',
        'consumer_secret'     => 'APP_CONSUMER_SECRET',
        'access_token'        => 'USER_ACCESS_TOKEN',
        'access_token_secret' => 'USER_ACCESS_TOKEN_SECRET',
    );

    $app = new \TTools\App($config);
    $user = $app->getCredentials();

    echo "This is the static user:<br><pre>";
    print_r($user);
    echo "</pre>";


### Multi User Apps (with authentication)

    <?php
    $config = array(
        'consumer_key'  => 'APP_CONSUMER_KEY',
        'consumer_secret' => 'APP_CONSUMER_SECRET'
    );

    $app = new \TTools\App($config);

    if ($app->isLogged()) {
        $user = $app->getCurrentUser();

        echo "This is the logged user:<br><pre>";
        print_r($user);
        echo "</pre>";

    } else {
        $login_url = $app->getLoginUrl();
        echo 'Please log in: <a href="'. $login_url . '">' . $login_url . '</a>';
    }

docs
=====

- [Getting Started](https://github.com/ttools/ttools/blob/master/doc/getting_started.md)
- [Basic Usage - single user Application](https://github.com/ttools/ttools/blob/master/doc/basic_singleuser.md)
- [Basic multi-user (with auth) Application](https://github.com/ttools/ttools/blob/master/doc/basic_multiuser.md)
- [Symfony example](https://github.com/ttools/ttools/blob/master/doc/example_symfony.md)
- [Laravel example] (https://github.com/ttools/ttools/blob/master/doc/laravel_example.md)
- [Making Requests to the Twitter API](https://github.com/ttools/ttools/blob/master/doc/making_requests.md)

