<?php
if (!defined('__TYPECHO_ADMIN__')) {
    exit;
}

$bodyClass = 'body-100';
$_adminDir = __TYPECHO_ROOT_DIR__ . '/admin/';

/** @var \Widget\Options $options */
$options = \Widget\Options::alloc();
/** @var \Typecho\Widget\Request $request */
$request = $options->request;

$url = \Typecho\Router::url('do', ['action' => 'GAuthenticator'], $options->index);

include $_adminDir . 'header.php';
?>
<div class="typecho-login-wrap">
    <div class="typecho-login">
        <h1><a href="http://typecho.org" class="i-logo">Typecho</a></h1>
        <form action="<?= $url ?>" method="post" name="login" role="form" id="ga-otp-form">
            <p>
                <label for="otp" class="sr-only"><?php _e('两步验证密码'); ?></label>
                <input type="text" autofocus="autofocus" id="otp" name="otp" class="text-l w-100" inputmode="numeric"
                       maxlength="6" autocomplete="new-field" oninput="this.value = this.value.replace(/[^0-9]/g, '')" placeholder="<?php _e('两步验证密码'); ?>"/>
            </p>
            <p class="submit">
                <button type="submit" class="btn btn-l w-100 primary" id="ga-otp-submit"><?php _e('登录'); ?></button>
                <input type="hidden" name="referer" value="<?php echo $request->filter('html')->get('referer'); ?>"/>
            </p>
            <p>
                <label for="remember"><input type="checkbox" name="remember" class="checkbox" value="1" id="remember"
                                             checked/> <?php _e('记住本机 (一个月内免验证)'); ?></label>
            </p>
        </form>

        <p class="more-link">
            <a href="<?php $options->siteUrl(); ?>"><?php _e('返回首页'); ?></a>
            <?php if ($options->allowRegister): ?>
                &bull;
                <a href="<?php $options->registerUrl(); ?>"><?php _e('用户注册'); ?></a>
            <?php endif; ?>
            &bull;
            <a href="<?php $options->logoutUrl(); ?>" title="Logout"><?php _e('退出'); ?></a>
        </p>
    </div>
</div>
<?php
include $_adminDir . 'common-js.php';
?>
<script>
(function () {
    function showPopup(type, msg) {
        // mimic Typecho admin/common-js.php popup style
        var head = $('.typecho-head-nav');
        var p = $('<div class="message popup ' + type + '"><ul><li></li></ul></div>');
        p.find('li').text(msg);

        if (head.length > 0) {
            p.insertAfter(head);
        } else {
            p.prependTo(document.body);
        }

        p.hide().slideDown(function () {
            var t = $(this), color = '#C6D880';
            if (t.hasClass('error')) {
                color = '#FBC2C4';
            } else if (t.hasClass('notice')) {
                color = '#FFD324';
            }

            t.effect('highlight', {color: color})
                .delay(5000)
                .fadeOut(function () { $(this).remove(); });
        });
    }

    $(function () {
        var $form = $('#ga-otp-form');
        var $btn = $('#ga-otp-submit');

        $form.on('submit', function (e) {
            e.preventDefault();

            var otp = $.trim($('#otp').val());
            if (!otp) {
                showPopup('error', '<?php echo addslashes(_t('请输入令牌')); ?>');
                return;
            }

            $btn.prop('disabled', true).addClass('disabled');

            $.ajax({
                url: $form.attr('action'),
                type: 'POST',
                dataType: 'json',
                data: {
                    otp: otp,
                    remember: $('#remember').is(':checked') ? 1 : 0,
                    referer: $form.find('input[name=referer]').val()
                }
            }).done(function (res) {
                if (res && res.ok) {
                    if (res.redirect) {
                        window.location.href = res.redirect;
                    } else {
                        window.location.reload();
                    }
                    return;
                }

                var msg = (res && res.message) ? res.message : '<?php echo addslashes(_t('令牌错误')); ?>';
                showPopup('error', msg);
            }).fail(function () {
                showPopup('error', '<?php echo addslashes(_t('请求失败，请重试')); ?>');
            }).always(function () {
                $btn.prop('disabled', false).removeClass('disabled');
            });
        });
    });
})();
</script>
<?php
include $_adminDir . 'footer.php';
exit;
?>
