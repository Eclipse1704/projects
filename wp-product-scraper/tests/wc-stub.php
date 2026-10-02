<?php
// A tiny stand-in for WooCommerce + Action Scheduler, enough for the plugin's tests (products are posts).

class WooCommerce {}

add_action('init', function () {
    register_post_type('product', ['public' => true, 'label' => 'Products', 'supports' => ['title', 'editor', 'excerpt', 'thumbnail']]);
    register_taxonomy('product_cat', 'product', ['hierarchical' => true]);
    register_taxonomy('product_tag', 'product', []);
    register_taxonomy('product_brand', 'product', ['hierarchical' => true]);
}, 0);

add_filter('user_has_cap', function ($all, $caps, $args, $user) {
    if (in_array('administrator', (array) $user->roles, true)) { $all['edit_products'] = true; $all['manage_woocommerce'] = true; }
    if (in_array('shop_manager', (array) $user->roles, true)) { $all['edit_products'] = true; }
    return $all;
}, 10, 4);

class WC_Product_Simple {
    protected $id = 0;
    protected $data = ['name' => '', 'status' => 'draft', 'description' => '', 'short_description' => '', 'category_ids' => null, 'tag_ids' => null, 'image_id' => null, 'gallery_image_ids' => null];
    protected $meta = [];
    public function __construct($id = 0) {
        if ($id && ($p = get_post($id))) {
            $this->id = (int) $id;
            $this->data['name'] = $p->post_title; $this->data['status'] = $p->post_status;
            $this->data['description'] = $p->post_content; $this->data['short_description'] = $p->post_excerpt;
        }
    }
    public function get_id() { return $this->id; }
    public function set_name($v) { $this->data['name'] = $v; }
    public function set_status($v) { $this->data['status'] = $v; }
    public function set_description($v) { $this->data['description'] = $v; }
    public function set_short_description($v) { $this->data['short_description'] = $v; }
    public function set_category_ids($v) { $this->data['category_ids'] = $v; }
    public function set_tag_ids($v) { $this->data['tag_ids'] = $v; }
    public function set_image_id($v) { $this->data['image_id'] = $v; }
    public function set_gallery_image_ids($v) { $this->data['gallery_image_ids'] = $v; }
    public function update_meta_data($k, $v) { $this->meta[$k] = $v; }
    public function save() {
        $post = ['post_type' => 'product', 'post_title' => $this->data['name'], 'post_status' => $this->data['status'],
            'post_content' => $this->data['description'], 'post_excerpt' => $this->data['short_description']];
        if ($this->id) { $post['ID'] = $this->id; wp_update_post(wp_slash($post)); }
        else $this->id = wp_insert_post(wp_slash($post));
        if ($this->data['category_ids'] !== null) wp_set_object_terms($this->id, array_map('intval', $this->data['category_ids']), 'product_cat');
        if ($this->data['tag_ids'] !== null) wp_set_object_terms($this->id, array_map('intval', $this->data['tag_ids']), 'product_tag');
        if ($this->data['image_id'] !== null) update_post_meta($this->id, '_thumbnail_id', $this->data['image_id']);
        if ($this->data['gallery_image_ids'] !== null) update_post_meta($this->id, '_product_image_gallery', implode(',', $this->data['gallery_image_ids']));
        foreach ($this->meta as $k => $v) update_post_meta($this->id, $k, $v);
        return $this->id;
    }
}

function wc_get_product($id) { return get_post($id) ? new WC_Product_Simple($id) : false; }

// Action Scheduler
class ActionScheduler_Store { const STATUS_PENDING = 'pending'; }
$GLOBALS['as_queue'] = [];
function as_enqueue_async_action($hook, $args = [], $group = '') { $GLOBALS['as_queue'][] = ['hook' => $hook, 'time' => 0]; return count($GLOBALS['as_queue']); }
function as_schedule_single_action($t, $hook, $args = [], $group = '') { $GLOBALS['as_queue'][] = ['hook' => $hook, 'time' => $t]; return count($GLOBALS['as_queue']); }
function as_get_scheduled_actions($q, $ret = 'ids') { return array_keys(array_filter($GLOBALS['as_queue'], function ($a) use ($q) { return $a['hook'] === $q['hook']; })); }
function as_unschedule_all_actions($hook, $args = [], $group = '') { $GLOBALS['as_queue'] = array_values(array_filter($GLOBALS['as_queue'], function ($a) use ($hook) { return $a['hook'] !== $hook; })); }
