<?php
namespace Etsy;

use ConnectorSupport\Curl\InjectVariables;

/**
*
*/
class EtsyClient
{
	private $base_url = "https://openapi.etsy.com/v2";
	private $base_path = "/private";
	private $oauth = null;
	private $authorized = false;
	private $debug = true;

	private $consumer_key = "";
	private $consumer_secret = "";

	function __construct($consumer_key, $consumer_secret)
	{
		$this->consumer_key = $consumer_key;
		$this->consumer_secret = $consumer_secret;

		$this->oauth = new \OAuth($consumer_key, $consumer_secret, OAUTH_SIG_METHOD_HMACSHA1, OAUTH_AUTH_TYPE_URI);

		if (defined('OAUTH_REQENGINE_CURL'))
		{
            $this->engine = OAUTH_REQENGINE_CURL;
            $this->oauth->setRequestEngine(OAUTH_REQENGINE_CURL);
        } elseif(defined('OAUTH_REQENGINE_STREAMS')) {
            $this->engine = OAUTH_REQENGINE_STREAMS;
			$this->oauth->setRequestEngine( OAUTH_REQENGINE_STREAMS );
		} else {
			error_log("Warning: cURL engine not present on OAuth PECL package: sudo apt-get install libcurl4-dev or sudo yum install curl-devel");
		}
	}

	public function authorize($access_token, $access_token_secret)
	{
		$this->oauth->setToken($access_token, $access_token_secret);
		$this->authorized = true;
	}

	public function request($path, $params = array(), $method = OAUTH_HTTP_METHOD_GET, $json = true)
	{
		if ($this->authorized === false)
		{
			throw new \Exception('Not authorized. Please, authorize this client with $client->authorize($access_token, $access_token_secret)');
		}
        if ($this->engine === OAUTH_REQENGINE_STREAMS) {
            foreach ($params as $key => $value) {
                if (substr($key, 0, 1) === '@') {
                    throw new \Exception('Uploading files using php_streams request engine is not supported', 1);
                }
            }
        }
	    try {
	    	if ($this->debug === true)
	        {
	        	$this->oauth->enableDebug();
	        }

	        $data = $this->oauth->fetch($this->base_url . $this->base_path . $path, $params, $method);
	        $response = $this->oauth->getLastResponse();

            ////
            $injector = InjectVariables::instance();
            $logger = $injector->logger;
            if ($logger !== null) {

                $info = $this->oauth->getLastResponseInfo();
                $http_code = $info['http_code'];
                $url = $info['url'];
                $split = explode('?', $url);
                if (count($split) >= 1) {$url = $split[0];} else {$url = null;}
                if (count($split) >= 2) {$query = $split[1];} else {$query = null;}

                if (array_key_exists('headers_sent', $this->oauth->debugInfo)) {$headersSent = $this->oauth->debugInfo['headers_sent'];} else {$headersSent = null;}
                if (array_key_exists('headers_recv', $this->oauth->debugInfo)) {$headersRecv = $this->oauth->debugInfo['headers_recv'];} else {$headersRecv = null;}
                if (array_key_exists('body_sent', $this->oauth->debugInfo)) {$bodySent = $this->oauth->debugInfo['body_sent'];} else {$bodySent = null;}
                if (array_key_exists('body_recv', $this->oauth->debugInfo)) {$bodyRecv = $this->oauth->debugInfo['body_recv'];} else {$bodyRecv = null;}

                $sent = [];
                $headers = explode("\r\n", $headersSent);
                foreach ($headers as $header) {
                    $temp = explode(':', $header, 2);
                    if (count($temp) > 1) {
                        $sent[trim($temp[0])] = trim($temp[1]);
                    }
                }

                $recv = explode("\r\n", $headersRecv);

                $logger->logRequest($method, $url, $query, $sent, $bodySent);
                $logger->logResponse($method, $url, $http_code, $recv, $bodyRecv);

            }
            ////

            return json_decode($response, !$json);
        } catch (\OAuthException $e) {
            throw new EtsyRequestException($e, $this->oauth, $params);
        }
    }

	public function getRequestToken(array $extra = array())
	{
	    $url = $this->base_url . "/oauth/request_token";
	    $callback = 'oob';
	    if (isset($extra['scope']) && !empty($extra['scope']))
	    {
	    	$url .= '?scope=' . urlencode($extra['scope']);
	    }

	    if (isset($extra['callback']) && !empty($extra['callback']))
	    {
	    	$callback = $extra['callback'];
	    }
	    try {
		return $this->oauth->getRequestToken($url, $callback, 'GET');
	    } catch (\OAuthException $e) {
	        throw new EtsyRequestException($e, $this->oauth);
	    }

	    return null;
	}

	public function getAccessToken($verifier)
	{
	    try {
			return $this->oauth->getAccessToken($this->base_url . "/oauth/access_token", null, $verifier, 'GET');
	    } catch (\OAuthException $e) {
	        throw new EtsyRequestException($e, $this->oauth);
	    }

	    return null;
	}

	public function getConsumerKey()
	{
		return $this->consumer_key;
	}

	public function getConsumerSecret()
	{
		return $this->consumer_secret;
	}

	public function getLastResponseHeaders(){
        	return $this->oauth->getLastResponseHeaders();
    	}

	public function setDebug($debug)
	{
		$this->debug = $debug;
	}
}

/**
*
*/
class EtsyResponseException extends \Exception
{
	private $response = null;

	function __construct($message, $response = array())
	{
		$this->response = $response;

		parent::__construct($message);
	}

	public function getResponse()
	{
		return $this->response;
	}
}

/**
*
*/
class EtsyRequestException extends \Exception
{
	private $lastResponse;
	private $lastResponseInfo;
	private $lastResponseHeaders;
	private $debugInfo;
	private $exception;
	private $params;

	function __construct($exception, $oauth, $params = array())
	{
		$this->lastResponse = $oauth->getLastResponse();
		$this->lastResponseInfo = $oauth->getLastResponseInfo();
		$this->lastResponseHeaders = $oauth->getLastResponseHeaders();
		$this->debugInfo = $oauth->debugInfo;
		$this->exception = $exception;
		$this->params = $params;

		parent::__construct($this->buildMessage(), 1, $exception);
	}

	private function buildMessage()
	{
		return $this->exception->getMessage().": " .
			print_r($this->params, true) .
			print_r($this->lastResponse, true) .
			print_r($this->lastResponseInfo, true) .
			// print_r($this->lastResponseHeaders, true) .
			print_r($this->debugInfo, true);
	}

	public function getLastResponse()
	{
		return $this->lastResponse;
	}

	public function getLastResponseInfo()
	{
		return $this->lastResponseInfo;
	}

	public function getLastResponseHeaders()
	{
		return $this->lastResponseHeaders;
	}

	public function getDebugInfo()
	{
		return $this->debugInfo;
	}

	public function getParams()
	{
		return $this->params;
	}

	public function __toString()
	{
		return __CLASS__ . ": [{$this->code}]: ". $this->buildMessage();
	}
}
