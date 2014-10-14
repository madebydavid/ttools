<?php
/**
 * OAuthRequest Class
 */

namespace TTools;

class OAuthRequest {

    /** @var string Application consumer key */
    protected $consumerKey;

    /** @var string Application consumer secret */
    protected $consumerSecret;

    /** @var string Request Token */
    protected $token;

    /** @var string Request Secret */
    protected $tokenSecret;

    /** @var string Curl User Agent */
    protected $userAgent;

    /** @var string Request Base String */
    protected $baseUrl = "";

    const OAUTH_VERSION = '1.0';
    const OAUTH_SIGNATURE_METHOD = 'HMAC-SHA1';

    /**
     * Creates the OAuthRequest object
     *
     * @param string $consumerKey    Application Consumer Key
     * @param string $consumerSecret Application Consumer Secret
     * @param string $token          Request Token
     * @param string $tokenSecret    Request Token Secret
     */
    public function __construct($consumerKey, $consumerSecret, $token, $tokenSecret)
    {
        $this->userAgent      = 'TTools 2.0';
        $this->baseUrl        = 'https://api.twitter.com';

        $this->consumerKey    = $consumerKey;
        $this->consumerSecret = $consumerSecret;
        $this->token          = $token;
        $this->tokenSecret    = $tokenSecret;
    }

    /**
     * @param string $consumerKey
     */
    public function setConsumerKey($consumerKey)
    {
        $this->consumerKey = $consumerKey;
    }

    /**
     * @return string
     */
    public function getConsumerKey()
    {
        return $this->consumerKey;
    }

    /**
     * @param string $consumerSecret
     */
    public function setConsumerSecret($consumerSecret)
    {
        $this->consumerSecret = $consumerSecret;
    }

    /**
     * @return string
     */
    public function getConsumerSecret()
    {
        return $this->consumerSecret;
    }

    /**
     * @param string $token
     */
    public function setToken($token)
    {
        $this->token = $token;
    }

    /**
     * @return string
     */
    public function getToken()
    {
        return $this->token;
    }

    /**
     * @param string $tokenSecret
     */
    public function setTokenSecret($tokenSecret)
    {
        $this->tokenSecret = $tokenSecret;
    }

    /**
     * @return string
     */
    public function getTokenSecret()
    {
        return $this->tokenSecret;
    }

    /**
     * @param string $userAgent
     */
    public function setUserAgent($userAgent)
    {
        $this->userAgent = $userAgent;
    }

    /**
     * @return string
     */
    public function getUserAgent()
    {
        return $this->userAgent;
    }

    /**
     * @param string $baseUrl
     */
    public function setBaseUrl($baseUrl)
    {
        $this->baseUrl = $baseUrl;
    }

    /**
     * @return string
     */
    public function getBaseUrl()
    {
        return $this->baseUrl;
    }

    /**
     * Performs an authenticated OAuth Request
     *
     * @param string $method    Request Method (GET / POST)
     * @param string $url       Request endpoint (e.g: /1.1/account/verify_credentials.json)
     * @param array  $params    Params for the request
     * @param bool   $multipart If the request is multipart or not (defaults to false)
     *
     * @return OAuthResponse    Returns an OAuthResponse object
     */
    public function request($method, $url, $params = array(), $multipart = false)
    {
        $headers = array(
            'Authorization: ' . $this->getOAuthHeader($method, $this->baseUrl . $url, $params)
        );

        if (!$multipart) {
            $headers[] = 'Content-type: application/x-www-form-urlencoded';
        } else {
            $headers[] = 'Content-type: multipart/form-data';
            $headers[] = 'Expect: ';
        }

        return $this->curlRequest($url, $params, $headers, $method, $multipart);
    }

    /**
     * Performs a OAuth curl request.
     *
     * @param string $url
     * @param array  $params
     * @param array  $headers
     * @param string $method
     * @param bool   $multipart
     *
     * @return OAuthResponse
     */
    protected function curlRequest($url, $params = array(), $headers = array(), $method = 'GET', $multipart = false)
    {
        $requestUrl = $this->baseUrl . $url;
        if ($method != 'POST') {
            $requestUrl = $this->baseUrl . $url . '?' . $this->formatQueryString($params);    
        }

        $curl = curl_init();
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);

        curl_setopt_array($curl, array(
            CURLOPT_USERAGENT      => $this->userAgent,
            CURLOPT_CONNECTTIMEOUT => 30,
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_URL            => $requestUrl,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_HEADER         => false,
            CURLINFO_HEADER_OUT    => true,
        ));

        if ($method == 'POST') {
            curl_setopt($curl, CURLOPT_POST, true);
            curl_setopt($curl, CURLOPT_POSTFIELDS, $this->formatQueryString($params));
            curl_setopt($curl, CURLOPT_TIMEOUT, 0);
        }

        $response = new OAuthResponse();

        $response->setResponse(curl_exec($curl));
        $response->setCode(curl_getinfo($curl, CURLINFO_HTTP_CODE));
        $response->setInfo(curl_getinfo($curl));
        $response->setError(curl_error($curl));
        $response->setErrno(curl_errno($curl));

        curl_close($curl);

        return $response;
    }

    /**
     * Gets the OAuth signed Authorization headers
     * @param string $method
     * @param string $url
     * @param array  $params
     * @param bool   $multipart
     *
     * @return string
     */
    protected function getOAuthHeader($method, $url, $params = array(), $multipart = false)
    {
        $oauth['oauth_consumer_key']     = $this->consumerKey;
        $oauth['oauth_nonce']            = time();
        $oauth['oauth_signature_method'] = self::OAUTH_SIGNATURE_METHOD;
        $oauth['oauth_timestamp']        = time();
        $oauth['oauth_token']            = $this->token;
        $oauth['oauth_version']          = self::OAUTH_VERSION;

        if (!$multipart) {
            $signParams = array_merge($params, $oauth);
        }
        else {
            $signParams = $oauth;
        }

        uksort($signParams, 'strcmp');

        $query = $this->encodeParams($signParams);

        $queryString = implode('&', $query);

        $signature = strtoupper($method) . '&' . $this->urlencodeRfc3986($url) . '&' . $this->urlencodeRfc3986($queryString);

        $signingKey = $this->urlencodeRfc3986($this->consumerSecret) . '&' . $this->urlencodeRfc3986($this->tokenSecret);

        $hash_hmac = hash_hmac('sha1', $signature, $signingKey, true);
        $oauth['oauth_signature'] = base64_encode($hash_hmac);

        uksort($oauth, 'strcmp');
        $authParams = $this->encodeParams($oauth, true);

        return 'OAuth ' . implode(', ', $authParams);
    }

    /**
     * Encodes parameters
     * @param array $params
     * @param bool $quoted
     * @return array
     */
    protected function encodeParams(array $params = [], $quoted = false)
    {
        $encoded = array();

        foreach ($params as $key => $value) {
            if ($quoted) {
                $encodedValue = '"' . $this->urlencodeRfc3986($value) . '"';
            } else {
                $encodedValue = $this->urlencodeRfc3986($value);
            }
            $encoded[] = $this->urlencodeRfc3986($key) . '=' . $encodedValue;
        }

        return $encoded;
    }

    protected function urlencodeRfc3986($input)
    {
        if (is_array($input)) {
            return array_map(array('TTools\OAuthRequest', 'urlencodeRfc3986'), $input);
        } elseif (is_scalar($input)) {
            return str_replace('+', ' ', str_replace('%7E', '~', rawurlencode($input)));
        } else {
            return '';
        }
    }

    protected function formatQueryString(array $params)
    {
        if (!$params) {
            return '';
        }

        $keys = $this->urlencodeRfc3986(array_keys($params));
        $values = $this->urlencodeRfc3986(array_values($params));
        $params = array_combine($keys, $values);

        uksort($params, 'strcmp');

        $pairs = array();
        foreach ($params as $parameter => $value) {
            if (is_array($value)) {
                sort($value, SORT_STRING);
                foreach ($value as $duplicate_value) {
                    $pairs[] = $parameter . '=' . $duplicate_value;
                }
            } else {
                $pairs[] = $parameter . '=' . $value;
            }
        }
        return implode('&', $pairs);
    }
} 