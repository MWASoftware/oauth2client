#!/bin/sh
SERVER=localhost
echo "Client Credentials Grant"
curl http://$SERVER/oauth2/token.php -d 'client_id=OAuth2Tester&client_secret=masterkey&grant_type=client_credentials'
echo "Resource Owner Password Credentials Grant"
curl http://$SERVER/oauth2/token.php -d 'client_id=OAuth2Tester&client_secret=masterkey&grant_type=password&username=atester&password=test2021'


