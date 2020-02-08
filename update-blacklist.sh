#!/bin/sh
# Example usage of the script with Nginx - run in cron
# Requires you to create IPBlacklist.php with the contents of the example in README.

SCRIPT=$(readlink -f "${0}")
SCRIPTPATH=$(dirname "${SCRIPT}")

/usr/bin/php ${SCRIPTPATH}/IPBlacklist.php > /etc/nginx/snippets/blacklisted-ips.conf

if /usr/sbin/nginx -t -q
then
    /usr/sbin/service nginx reload
else
    /bin/echo "Nginx config test failed, did not reload to prevent a crash"
fi