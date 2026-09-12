<?php

/**
 * 两步验证页面
 *
 * 由 GAuthenticator\Action 在「密码已通过、尚未登录」的状态下渲染。
 * 此时 __TYPECHO_ADMIN__ 未定义、Menu 组件也没有初始化，
 * 所以这里不复用 admin/header.php，自带一份最小样式。
 *
 * 作用域内可用：$options $error $formAction $remaining $challenge
 */

if (!defined('__TYPECHO_ROOT_DIR__')) {
    exit;
}

/** @var \Widget\Options $options */
/** @var string $error */
/** @var string $formAction */
/** @var int $remaining */
?>
<!DOCTYPE HTML>
<html>
<head>
    <meta charset="<?php $options->charset(); ?>">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex, nofollow">
    <title><?php _e('两步验证 - %s', $options->title); ?></title>
    <link rel="stylesheet" href="<?php echo $options->adminStaticUrl('css', 'normalize.css', true); ?>">
    <link rel="stylesheet" href="<?php echo $options->adminStaticUrl('css', 'grid.css', true); ?>">
    <link rel="stylesheet" href="<?php echo $options->adminStaticUrl('css', 'style.css', true); ?>">
</head>
<body class="body-100">
<div class="typecho-login-wrap">
    <div class="typecho-login">
        <h1><a href="<?php $options->siteUrl(); ?>" class="i-logo">Typecho</a></h1>

        <?php if ($error !== ''): ?>
            <div class="message error"><ul><li><?php echo htmlspecialchars($error, ENT_QUOTES, $options->charset); ?></li></ul></div>
        <?php endif; ?>

        <form action="<?php echo htmlspecialchars($formAction, ENT_QUOTES, $options->charset); ?>" method="post" name="otp" role="form">
            <p>
                <label for="code" class="sr-only"><?php _e('验证码或恢复码'); ?></label>
                <input type="text" autofocus="autofocus" id="code" name="code" class="text-l w-100"
                       maxlength="11" autocomplete="one-time-code"
                       placeholder="<?php _e('六位验证码或恢复码'); ?>"/>
            </p>
            <p class="submit">
                <button type="submit" class="btn btn-l w-100 primary"><?php _e('验证'); ?></button>
            </p>
            <p>
                <label for="remember">
                    <input type="checkbox" name="remember" class="checkbox" value="1" id="remember"/>
                    <?php _e('记住本机 (保持一个月)'); ?>
                </label>
            </p>
        </form>

        <p class="more-link">
            <?php _e('剩余机会 %d 次', $remaining); ?>
        </p>
        <p class="more-link">
            <a href="<?php echo htmlspecialchars($options->loginUrl, ENT_QUOTES, $options->charset); ?>"><?php _e('重新登录'); ?></a>
            &bull;
            <a href="<?php $options->siteUrl(); ?>"><?php _e('返回首页'); ?></a>
        </p>
    </div>
</div>
</body>
</html>
