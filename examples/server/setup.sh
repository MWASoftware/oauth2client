#!/bin/sh
USERNAME=oauth2
PASSWORD=4uZdvKaM
DB=oauth2_db

cd `dirname $0`

if [ ! -d "oauth2-server-php" ]; then
  git clone https://github.com/bshaffer/oauth2-server-php.git -b master
fi

(
echo "DROP DATABASE IF EXISTS $DB;"
echo "CREATE DATABASE $DB CHARACTER SET utf8;"
echo "DROP USER IF EXISTS '$USERNAME'@'localhost';"
echo "CREATE USER '$USERNAME'@'localhost' IDENTIFIED BY '$PASSWORD';"
echo "GRANT ALL on $DB.* to '$USERNAME'@'localhost';"
echo "commit;"
echo "use $DB;"
cat schema.sql
)|mysql -uroot -p

#Create Config.php
(echo "<?php"
 echo "\$dsn      = 'mysql:dbname=$DB;host=localhost';"
 echo "\$username = 'oauth2';"
 echo "\$password = '$PASSWORD';"
) >config.php

#Create (example) apache config fragment
DIR=`realpath .`
(
echo "Alias \"/oauth2/\"  \"$DIR/endpoints/\""
echo "<Directory \"$DIR\">"
echo "php_value engine on"
echo "allow from all"
echo "</Directory>"
) > "apache2.conf"



