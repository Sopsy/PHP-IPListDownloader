<?php
declare(strict_types=1);

/**
 * IpListDownloader
 * Formerly used for blacklisting IP addresses at Ylilauta - mainly bots and open proxies.
 * Minimum PHP version: PHP 7.4
 *
 * @license MIT
 * @author Aleksi Kinnunen / Sopsy
 * @link https://github.com/Sopsy/PHP-IpListDownloader
 * @version 1.0
 */
class IpListDownloader
{
    private bool $quiet;
    private array $list = [];
    private float $startTime;

    /**
     * IpListDownloader constructor.
     *
     * @param bool $quiet Useful for piping output to text files etc. Fails quietly if enabled.
     */
    public function __construct(bool $quiet = false)
    {
        $this->quiet = $quiet;
    }

    /**
     * Returns a list of IPs and subnets that is useful with Nginx Geo.
     *
     * @param string $variableName name for the Nginx variable
     * @return string
     */
    public function getNginxGeoList(string $variableName = 'ip_list'): string
    {
        $this->removeDuplicates();
        sort($this->list);

        if (empty($this->list)) {
            $this->logWarn('List is empty');

            return '';
        }

        return "geo \${$variableName} {\n"
            . "default 0;\n"
            . implode(" 1;\n", $this->list) . " 1;\n"
            . '}';
    }

    /**
     * Returns a raw list of IPs and subnets
     *
     * @param string $separator field separator, newline by default
     * @return string
     */
    public function getSubnetList(string $separator = "\r\n"): string
    {
        $this->removeDuplicates();
        sort($this->list);

        if (empty($this->list)) {
            $this->logWarn('List is empty');

            return '';
        }

        return implode($separator, $this->list);
    }

    /**
     * Get all Google AppEngine IPs and add them to the list
     *
     * @param string $domain
     * @param bool $_recursing Function running recursively. Suppresses log output. Do not use.
     * @return void
     */
    public function addGoogleAppEngineIps(string $domain, bool $_recursing = false): void
    {
        if (!$_recursing) {
            $this->startTiming();
        }

        $domain = trim($domain);
        if (!$_recursing) {
            $this->logInfo("DNS querying AppEngine subnet list '{$domain}'...");
        }

        $dig = shell_exec('dig TXT ' . escapeshellarg($domain) . ' +short');
        $dig = preg_replace('/^"v=spf1 (.+) \?all"$/', '$1', $dig);
        $dig = str_replace(['ip4:', 'ip6:'], '', $dig);
        $dig = explode(' ', $dig);

        foreach ($dig as $ip) {
            if (strpos($ip, 'include:') === 0) {
                $this->addGoogleAppEngineIps(str_replace('include:', '', $ip), true);
                continue;
            }

            $this->validateAndAddIp($ip);
        }

        if (!$_recursing) {
            $this->endTiming();
        }
    }

    /**
     * Get all Amazon AWS IPs and add them to the list
     *
     * @param string $jsonUrl
     * @return void
     */
    public function addAmazonAwsIps(string $jsonUrl): void
    {
        $this->startTiming();
        $this->logInfo("Downloading Amazon AWS IP list '{$jsonUrl}'...");

        $data = $this->downloadList($jsonUrl);
        if (empty($data)) {
            $this->endTiming(false);
            $this->logWarn('List does not contain any data');

            return;
        }

        $data = json_decode($data, false, 512, JSON_THROW_ON_ERROR);
        if (!$data) {
            $this->endTiming(false);
            $this->logError("Failed to decode JSON for Amazon AWS IP list '{$jsonUrl}'!");

            return;
        }

        foreach ($data->prefixes AS $row) {
            $this->validateAndAddIp($row->ip_prefix);
        }

        $this->endTiming();
    }

    /**
     * Get IPs from a Spamhaus IP list and add them to the list
     *
     * @param string $listUrl
     * @return void
     */
    public function addSpamhausList(string $listUrl): void
    {
        $this->startTiming();
        $this->logInfo("Downloading Spamhaus IP list '{$listUrl}'...");

        $data = $this->downloadList($listUrl);
        if (empty($data)) {
            $this->endTiming(false);
            $this->logWarn('List does not contain any data');

            return;
        }

        foreach (explode("\n", $data) as $line) {
            // Skip comment lines
            if (strpos($line, ';') === 0) {
                continue;
            }

            // The second part is a SBL number, we do not need it.
            $this->validateAndAddIp(explode(' ; ', $line, 2)[0]);
        }

        $this->endTiming();
    }

    /**
     * Get TOR exit node IPs add them to the list
     *
     * @param string $listUrl
     * @return void
     */
    public function addTorExitNodes(string $listUrl): void
    {
        $this->startTiming();
        $this->logInfo("Downloading TOR exit node list '{$listUrl}'...");

        $data = $this->downloadList($listUrl);
        if (empty($data)) {
            $this->endTiming(false);
            $this->logWarn('List does not contain any data');

            return;
        }

        preg_match_all('/ExitAddress ((\d|\.)+) .*/', $data, $nodes);
        $nodes = $nodes[1];

        foreach ($nodes as $ip) {
            $this->validateAndAddIp($ip);
        }

        $this->endTiming();
    }

    /**
     * Download a text list from Stop Forum Spam and add the IPs
     *
     * @param string $listUrl
     * @return void
     */
    public function addStopForumSpamTextList(string $listUrl): void
    {
        $this->startTiming();
        $this->logInfo("Downloading Stop Forum Spam text list '{$listUrl}'...");

        $data = $this->downloadList($listUrl);
        if (empty($data)) {
            $this->endTiming(false);
            $this->logWarn('List does not contain any data');

            return;
        }

        foreach (explode("\n", $data) as $row) {
            $this->validateAndAddIp($row);
        }

        $this->endTiming();
    }

    /**
     * Download a ZIP list from Stop Forum Spam and add the IPs
     *
     * @param string $listUrl
     * @param string $expectedFilename
     * @return void
     */
    public function addStopForumSpamZipList(string $listUrl, string $expectedFilename): void
    {
        $this->startTiming();

        if (!$this->quiet) {
            $this->logInfo("Downloading Stop Forum Spam ZIP list '{$listUrl}'...");
        }

        $data = $this->downloadList($listUrl);
        if (empty($data)) {
            $this->endTiming(false);
            $this->logWarn('List does not contain any data');

            return;
        }

        $namezip = tempnam(sys_get_temp_dir(), 'banipzip');

        file_put_contents($namezip, $data);

        $filename = shell_exec(
            'unzip -l ' . escapeshellarg($namezip) . ' | tail -n 3 | head -n 1 | awk \'{print $4}\''
        );

        if (!$filename) {
            $this->endTiming(false);
            $this->logError('Unzip failed! Verify unzip is installed.');

            return;
        }

        if (trim($filename) !== $expectedFilename) {
            unlink($namezip);
            $this->endTiming(false);
            $this->logWarn("File '{$expectedFilename}' does not exist in Stop Forum Spam ZIP file '{$listUrl}', skipping!");

            return;
        }

        $bannedips = shell_exec('unzip -j -p ' . escapeshellarg($namezip) . ' ' . escapeshellarg($expectedFilename));
        unlink($namezip);

        foreach (explode("\n", $bannedips) as $ip) {
            $this->validateAndAddIp($ip);
        }

        $this->endTiming();
    }

    /**
     * Get a Firehol ipset or netset and add IP addresses from it to the blocklist
     *
     * @param string $listName
     * @param bool $ipset
     */
    public function addFireholList(string $listName, bool $ipset = false): void
    {
        $this->startTiming();
        $this->logInfo("Downloading Firehol list '{$listName}'...");

        if (!preg_match('/^[a-z0-9_]+$/', $listName)) {
            $this->endTiming(false);
            $this->logError("Invalid list '{$listName}'!");

            return;
        }

        $data = $this->downloadList(
            'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/' . $listName . '.' . ($ipset ? 'ipset' : 'netset')
        );

        if (empty($data)) {
            $this->endTiming(false);
            $this->logWarn('List does not contain any data');

            return;
        }

        $fp = fopen('php://temp/maxmemory:16777216', 'rb+');
        fwrite($fp, $data);
        rewind($fp);

        while ($line = fgets($fp)) {
            if (strpos($line, '#') !== false) {
                continue;
            }

            // Singular IP
            $this->validateAndAddIp($line);
        }

        $this->endTiming();
    }

    /**
     * Add all prefixes by ASN to the list
     *
     * @param int $asn
     */
    public function addAsn(int $asn): void
    {
        $this->startTiming();
        $this->logInfo("Querying WHOIS for prefixes announced by AS{$asn}...");

        $as = escapeshellarg("AS{$asn}");
        $prefixes = shell_exec("whois -h whois.radb.net -i origin {$as} | grep 'route:\|route6:' | awk '{print $2}'");

        if (empty($prefixes)) {
            $this->endTiming(false);
            $this->logWarn("No prefixes found for AS{$asn}!");

            return;
        }

        foreach (explode("\n", $prefixes) as $prefix) {
            $this->validateAndAddIp($prefix);
        }

        $this->endTiming();
    }

    protected function startTiming(): void
    {
        $this->startTime = microtime(true);
    }

    protected function endTiming(bool $ok = true): void
    {
        if (empty($this->startTime)) {
            return;
        }

        if (!$this->quiet) {
            echo '['. ($ok ? 'OK' : 'FAIL') . ' - ' . round(microtime(true) - $this->startTime, 6) . "s]\n";
        }

        unset($this->startTime);
    }

    protected function logInfo(string $str): void
    {
        if ($this->quiet) {
            return;
        }

        echo "[INFO]: {$str}\n";
    }

    protected function logWarn(string $str): void
    {
        if ($this->quiet) {
            return;
        }

        echo "[WARN]: {$str}\n";
    }

    protected function logError(string $str): void
    {
        echo "[ERROR]: {$str}\n";
    }

    /**
     * Download a file
     *
     * @todo Maybe use CURL instead
     * @param string $url
     * @return string
     */
    protected function downloadList(string $url): string
    {
        $data = file_get_contents($url);

        if (!$data || strlen($data) < 7) {
            $this->logWarn("Could not download list '{$url}'!");

            return '';
        }

        return $data;
    }

    /**
     * Trim, validate and add a given IP to the list
     *
     * @todo Add support for IPv6
     * @param string $ip
     */
    protected function validateAndAddIp(string $ip): void
    {
        $ip = trim($ip);

        if (empty($ip)) {
            return;
        }

        // Remove /32 from end to prevent duplicates
        $ip = preg_replace('#/32$#', '', $ip);

        if (!$this->validateIPv4($ip)) {
            $this->logWarn("Invalid IP address: {$ip}");

            return;
        }

        $this->list[] = $ip;
    }

    /**
     * Remove duplicate IPs from the list
     */
    protected function removeDuplicates(): void
    {
        $this->startTiming();

        $this->logInfo('Removing duplicates...');

        $this->list = array_unique($this->list);

        $this->endTiming();
    }

    /**
     * Validates an IPv4 address with CIDR notation
     *
     * @param string $ip IPv4 address
     * @return bool True on valid IP, false on invalid IP
     */
    protected function validateIPv4(string $ip): bool
    {
        return preg_match(
                '/^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[0-2]|[1-2][0-9]|[0-9]))?$/',
                $ip
            ) !== false;
    }
}