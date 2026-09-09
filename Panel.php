<?php

/**
 * 「控制台 → 两步认证」面板
 *
 * 由 admin/extending.php 在 admin/common.php 之后 require，所以此时
 * $options / $user / $security / $menu / $request / $response 都已在作用域内，
 * 后台登录判定和本插件的 2FA 拦截也都已经跑过了。
 *
 * 这一页只处理「当前登录用户自己的」两步验证：绑定、轮换、可信设备、恢复码。
 * 站点级策略（容差倍率、XML-RPC）仍在 设置 → GAuthenticator。
 */

use TypechoPlugin\GAuthenticator\Plugin as GAuthenticator;

if (!defined('__TYPECHO_ROOT_DIR__')) {
    exit;
}

/** @var \Widget\Options $options */
/** @var \Widget\User $user */

/**
 * Menu 已经按面板注册时声明的等级拦过一道，这里再自己确认一次：
 * 面板文件是被 require 进来的，不应该依赖调用方一定做过鉴权。
 */
$user->pass('subscriber');

$gaAdminDir = __TYPECHO_ROOT_DIR__ . (defined('__TYPECHO_ADMIN_DIR__') ? __TYPECHO_ADMIN_DIR__ : '/admin/');

/**
 * 表单必须在 header.php 之前构建：它会消费「新恢复码只显示一次」的一次性
 * Cookie，而 header.php 一旦开始输出，就再也发不出清除该 Cookie 的响应头了。
 */
$gaForm = GAuthenticator::setupForm();
$gaEnabled = GAuthenticator::userIsEnabled((int) $user->uid, false);

include $gaAdminDir . 'header.php';
include $gaAdminDir . 'menu.php';
?>

<main class="main">
    <div class="body container">
        <?php include $gaAdminDir . 'page-title.php'; ?>
        <div class="row typecho-page-main">
            <div class="col-mb-12 col-tb-8 col-tb-offset-2 typecho-content-panel" role="form">
                <section>
                    <h3><?php _e('两步验证'); ?></h3>
                    <p class="description">
                        <?php if ($gaEnabled): ?>
                            <?php _e('当前账号已启用两步验证。登录时在密码之后需要再输入一次验证器上的六位验证码。'); ?>
                        <?php else: ?>
                            <?php _e('当前账号尚未启用两步验证，目前只用密码即可登录。绑定之后会多一层保护。'); ?>
                        <?php endif; ?>
                    </p>
                    <?php $gaForm->render(); ?>
                </section>
            </div>
        </div>
    </div>
</main>

<?php
include $gaAdminDir . 'copyright.php';
include $gaAdminDir . 'common-js.php';
include $gaAdminDir . 'form-js.php';
include $gaAdminDir . 'footer.php';
