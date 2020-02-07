# IP list downloader

Formerly used for blacklisting IP addresses at Ylilauta - mainly bots and open proxies.

Designed to be run in crontab with PHP-CLI.

Minimum PHP version is PHP 7.4.

Does not have any tests. Sorry.

## Example usage
```php
$list = new IpListDownloader();

// Prefixes announced by an ASN
$list->addAsn(9009);

// Firehol netset
$list->addFireholList('firehol_level4');

// Firehol ipset
$list->addFireholList('botscout_30d', true);

// Google App Engine
$list->addGoogleAppEngineIps('_cloud-netblocks.googleusercontent.com');

// Amazon AWS
$list->addAmazonAwsIps('https://ip-ranges.amazonaws.com/ip-ranges.json');

// Spamhaus text list
$list->addSpamhausList('https://www.spamhaus.org/drop/drop.txt');

// TOR exit nodes
$list->addTorExitNodes('https://check.torproject.org/exit-addresses');

// Stop Forum Spam list in text format
$list->addStopForumSpamTextList('https://www.stopforumspam.com/downloads/toxic_ip_cidr.txt');

// Stop Forum Spam in ZIP format
$list->addStopForumSpamZipList('https://www.stopforumspam.com/downloads/listed_ip_1.zip', 'listed_ip_1.txt');

// Output Nginx geo conf
file_put_contents('ip-geo.conf', $list->getNginxGeoList());

// Output list in text format
file_put_contents('ip-list.txt', $list->getSubnetList());
```