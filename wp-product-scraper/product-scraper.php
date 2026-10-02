<?php
/**
 * Plugin Name: סורק מוצרים
 * Description: מדביקים קישורים למוצרים מכל אתר, ו-Claude מוצא את היצרן, כותב דף מוצר בעברית, מוריד תמונות, קטלוג ומדריך מאתר היצרן הרשמי, ומכניס כל מוצר לחנות כטיוטה.
 * Version: 1.0.0
 * Requires at least: 6.2
 * Requires PHP: 7.4
 * Requires Plugins: woocommerce
 * Text Domain: nps
 */

if (!defined('ABSPATH')) exit;

define('NPS_VERSION', '1.0.0');
define('NPS_FILE', __FILE__);
define('NPS_DIR', plugin_dir_path(__FILE__));

require_once NPS_DIR . 'includes/settings.php';
require_once NPS_DIR . 'includes/http.php';
require_once NPS_DIR . 'includes/extract.php';
require_once NPS_DIR . 'includes/claude.php';
require_once NPS_DIR . 'includes/store.php';
require_once NPS_DIR . 'includes/publish.php';
require_once NPS_DIR . 'includes/worker.php';
require_once NPS_DIR . 'includes/admin.php';

register_activation_hook(__FILE__, 'nps_install');
add_action('plugins_loaded', 'nps_maybe_upgrade');
