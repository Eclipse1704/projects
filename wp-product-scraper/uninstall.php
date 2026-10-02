<?php
// Removing the plugin removes its list and settings. The products it created stay in the shop.
if (!defined('WP_UNINSTALL_PLUGIN')) exit;
global $wpdb;
$wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->prefix . 'nps_items');
$wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE 'nps\\_%' OR option_name LIKE '\\_transient\\_nps\\_%' OR option_name LIKE '\\_transient\\_timeout\\_nps\\_%'");
if (function_exists('as_unschedule_all_actions')) as_unschedule_all_actions('nps_tick');
