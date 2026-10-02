<?php
// Loads a real WordPress (SQLite) with the WooCommerce stand-in and the plugin. NPS_WP_DIR = the WordPress folder.
$npsWp = getenv('NPS_WP_DIR') ?: die("set NPS_WP_DIR\n");
$plugin = dirname(__DIR__);
@mkdir("$npsWp/wp-content/mu-plugins");
copy(__DIR__ . '/wc-stub.php', "$npsWp/wp-content/mu-plugins/0-wc-stub.php");
file_put_contents("$npsWp/wp-content/mu-plugins/1-nps.php", "<?php require '" . $plugin . "/product-scraper.php';");
$dropin = file_get_contents("$npsWp/wp-content/plugins/sqlite-database-integration-main/db.copy");
file_put_contents("$npsWp/wp-content/db.php", str_replace(['{SQLITE_IMPLEMENTATION_FOLDER_PATH}', '{SQLITE_PLUGIN}'],
    ["$npsWp/wp-content/plugins/sqlite-database-integration-main", 'sqlite-database-integration-main/load.php'], $dropin));
$db = sys_get_temp_dir() . '/nps-test.sqlite';
$child = (bool) getenv('NPS_INSTALL');
if (!$child) { @unlink($db); putenv('NPS_INSTALL=1'); }
file_put_contents("$npsWp/wp-config.php", "<?php
define('DB_NAME','x'); define('DB_USER','x'); define('DB_PASSWORD','x'); define('DB_HOST','localhost'); define('DB_CHARSET','utf8'); define('DB_COLLATE','');
define('DB_DIR', '" . dirname($db) . "'); define('DB_FILE', '" . basename($db) . "');
define('WP_DEBUG', false); define('DISABLE_WP_CRON', true);
define('WP_HOME', 'http://shop.test'); define('WP_SITEURL', 'http://shop.test'); define('NPS_API_BASE', 'https://api.test');
\$table_prefix = 'wp_';
if (!defined('ABSPATH')) define('ABSPATH', __DIR__ . '/');
require_once ABSPATH . 'wp-settings.php';
");
$_SERVER['HTTP_HOST'] = 'shop.test';
$_SERVER['SERVER_NAME'] = 'shop.test';
$_SERVER['REQUEST_URI'] = '/';
if ($child) {
    define('WP_INSTALLING', true);
    require "$npsWp/wp-load.php";
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    wp_install('Shop', 'admin', 'admin@shop.test', true, '', 'pass');
    exit(0);
}
passthru(PHP_BINARY . ' ' . escapeshellarg(__FILE__) . ' 2>&1', $rc);   // installs WordPress in a separate process
if ($rc) die("install failed\n");
require "$npsWp/wp-load.php";
error_reporting(E_ALL & ~E_DEPRECATED);
// Any warning in the plugin's own code fails the test that caused it.
set_error_handler(function ($no, $str, $file, $line) {
    if (strpos($file, dirname(__DIR__) . '/includes') === 0 || strpos($file, dirname(__DIR__) . '/assets') === 0) throw new ErrorException("$str ($file:$line)", 0, $no, $file, $line);
    return false;
}, E_ALL & ~E_DEPRECATED);
