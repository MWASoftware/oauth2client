<?php
//Set DB Name, User and password
require_once('config.php');

// error reporting (this is a demo, after all!)
ini_set('display_errors',1);error_reporting(E_ALL);

// Autoloading (composer is preferred, but for this example let's just do this)
require_once('oauth2-server-php/src/OAuth2/Autoloader.php');
OAuth2\Autoloader::register();

// $dsn is the Data Source Name for your database, for exmaple "mysql:dbname=my_oauth2_db;host=localhost"
$storage = new OAuth2\Storage\Pdo(array('dsn' => $dsn, 'username' => $username, 'password' => $password));

// Pass a storage object or array of storage objects to the OAuth2 server class
$server = new OAuth2\Server($storage,array('allow_implicit' => true));

// Add the "Client Credentials" grant type (it is the simplest of the grant types)
$server->addGrantType(new OAuth2\GrantType\ClientCredentials($storage),array(
    'allow_credentials_in_request_body' => true
));

// Add the "Authorization Code" grant type (this is where the oauth magic happens)
$server->addGrantType(new OAuth2\GrantType\AuthorizationCode($storage),array(
    'allow_credentials_in_request_body' => true
));

$server->addGrantType(new OAuth2\GrantType\RefreshToken($storage),array(
    'allow_credentials_in_request_body' => true
));

// create some users in memory
$users = array('atester' => array('password' => 'test2021', 'first_name' => 'Anon', 'last_name' => 'Tester'));

// create a storage object for user list
$mstorage = new OAuth2\Storage\Memory(array('user_credentials' => $users));

// add User Credentials Grant
$server->addGrantType(new OAuth2\GrantType\UserCredentials($mstorage));

$defaultScope = 'basic';
$supportedScopes = array(
  'basic',
  'testing'
);
$memory = new OAuth2\Storage\Memory(array(
  'default_scope' => $defaultScope,
  'supported_scopes' => $supportedScopes
));
$scopeUtil = new OAuth2\Scope($memory);

$server->setScopeUtil($scopeUtil);

