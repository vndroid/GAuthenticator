<?php

namespace TypechoPlugin\GAuthenticator;

use Typecho\Db\Exception as DbException;
use Typecho\Plugin\PluginInterface;
use Typecho\Plugin\Exception as PluginException;
use Typecho\Cookie;
use Typecho\Request;
use Typecho\Widget\Helper\Form;
use Typecho\Widget\Helper\Form\Element\Text;
use Typecho\Widget\Helper\Form\Element\Radio;
use Utils\Helper;
use Widget\Options;
use Widget\User;

if (!defined('__TYPECHO_ROOT_DIR__')) {
    exit;
}

/**
 * Google Authenticator for Typecho
 *
 * @package GAuthenticator
 * @author Vex
 * @version 0.1.1
 * @link https://github.com/vndroid/GAuthenticator
 */
class Plugin implements PluginInterface
{
    /**
     * 激活插件方法,如果激活失败,直接抛出异常
     *
     * @return string
     * @throws PluginException
     */
    public static function activate(): string
    {
        if (!str_ends_with(trim(__DIR__, '/\\'), 'GAuthenticator')) {
            throw new PluginException(_t('插件目录名必须为 GAuthenticator，且首字母大写，请检查插件目录名是否正确'));
        }

        Helper::addAction('GAuthenticator', __NAMESPACE__ . '\Action');

        \Typecho\Plugin::factory('admin/menu.php')->navBar = [self::class, 'authenticatorSafe'];
        \Typecho\Plugin::factory('admin/common.php')->begin = [self::class, 'authenticatorVerification'];

        $configLink = '<a href="' . Helper::options()->adminUrl('options-plugin.php?config=' . basename(__DIR__), true) . '">' . _t('前往设置') . '</a>';

        return _t('当前 2FA 尚未启用，请进行初始化设置，') . $configLink;
    }

    /**
     * 禁用插件方法,如果禁用失败,直接抛出异常
     *
     * @return string
     */
    public static function deactivate(): string
    {
        Helper::removeAction('GAuthenticator');

        return _t('两步验证已关闭');
    }

    /**
     * 获取插件配置面板
     *
     * @param Form $form 配置面板
     */
    public static function config(Form $form): void
    {
        $options = Options::alloc();
        $user = User::alloc();
        $qrurl = 'otpauth://totp/' . urlencode($options->title . ':' . $user->mail) . '?secret=';

        $element = new Text('SecretKey', null, '', _t('SecretKey'), '
    安装的时候自动计算密钥，手动修改无效，如需要修改请卸载重新安装或者手动修改数据库<br>
    <div style="font-weight: bold; color: #000; text-align: center; display: block;padding: 30px 0 30px 0;font-size: 24px;">
      请扫描下方二维码进行绑定<br>
      <div style="width: 300px; height: 300px; margin: 20px auto; padding: 20px; background-color: #fff"><span id="qrcode"></span></div>
    </div>
    <script>
      window.onload = function () {
        // https://github.com/jeromeetienne/jquery-qrcode/
        $.getScript("' . $options->pluginUrl . '/GAuthenticator/jquery.qrcode.min.js", function () {
          $("#qrcode").qrcode({width: 300, height: 300, text: "' . $qrurl . '"+$("input[name=SecretKey]").val()});
        });
      }
    </script>');
        $form->addInput($element);

        $element = new Text('SecretQRInfo', null, '', _t('二维码原始信息'), '与上方图片信息一致，如果二维码生成失败，可以复制本条使用其他工具生成二维码');
        $form->addInput($element);

        $element = new Text('SecretTime', null, '2', _t('容差倍率'), '容差时间，输入的值为30秒的倍数（如果输入2，那么容差时间为 2 × 30秒 = 1分钟）');
        $form->addInput($element);

        $element = new Text('SecretCode', null, '', _t('客户端代码'), '六位验证码，用兼容 TOTP 协议的 APP 扫描二维码或者手动输入第一行的 SecretKey 即可生成。');
        $form->addInput($element);

        $element = new Radio('SecretOn', ['1' => '开启', '0' => '关闭'], '0', _t('插件开关'), '启用插件并不会自动启用 2FA，需要手动填写客户端验证码并开启此功能');
        $form->addInput($element);
    }

    /**
     * 手动保存配置面板
     *
     * @param array $config 插件配置
     * @param bool $is_init 是否初始化
     * @throws PluginException
     */
    public static function configHandle(array $config, bool $is_init): void
    {
        if ($is_init) {
            require_once __DIR__ . '/GoogleAuthenticator.php';
            $authenticator = new \PHPGangsta_GoogleAuthenticator();
            $config['SecretKey'] = $authenticator->createSecret();
            $config['SecretQRInfo'] = urlencode('otpauth://totp/' . urlencode(Options::alloc()->title . ':' . User::alloc()->mail) . '?secret=' . $config['SecretKey']);
        } else {
            $configOld = Helper::options()->plugin(basename(__DIR__));
            if ($config['SecretOn'] == 1 && $config['SecretCode'] != '') {
                require_once __DIR__ . '/GoogleAuthenticator.php';
                $authenticator = new \PHPGangsta_GoogleAuthenticator();
                if (!$authenticator->verifyCode($config['SecretKey'], $config['SecretCode'], $config['SecretTime'])) {
                    throw new PluginException('2FA 代码校验失败，请重试或关闭');
                }
                $config['SecretOn'] = 1;
            }
            $config['SecretKey'] = $configOld->SecretKey;
            $config['SecretQRInfo'] = $configOld->SecretQRInfo;
        }
        $config['SecretCode'] = '';
        Helper::configPlugin('GAuthenticator', $config);
    }

    /**
     * 个人用户的配置面板
     *
     * @param Form $form
     */
    public static function personalConfig(Form $form): void
    {
    }

    /**
     * 在后台导航栏显示 2FA 状态
     * @throws PluginException
     */
    public static function authenticatorSafe(): void
    {
        $config = Helper::options()->plugin(basename(__DIR__));
        if ($config->SecretOn == 1) {
            echo '<span class="message success">' . htmlspecialchars('2FA 已启用') . '</span>';
        } else {
            echo '<span class="message error">' . htmlspecialchars('2FA 未启用') . '</span>';
        }
    }

    /**
     * 拦截未经 OTP 验证的已登录用户
     * @throws DbException
     * @throws PluginException
     */
    public static function authenticatorVerification(): void
    {
        static $initialized = false;
        if ($initialized) {
            return;
        }
        $initialized = true;

        // 跳过自身路由、action 入口和登录页面
        $pathInfo = (string) Request::getInstance()->getPathInfo();
        if ($pathInfo) {
            if (str_contains($pathInfo, 'GAuthenticator')) {
                return;
            }
            if (str_starts_with($pathInfo, '/action/')) {
                return;
            }
            if (str_contains($pathInfo, '/admin/login.php')) {
                return;
            }
        }

        $user = User::alloc();
        if (!$user->hasLogin()) {
            return;
        }

        $config = Helper::options()->plugin(basename(__DIR__));

        if (isset($_SESSION['GAuthenticator']) && $_SESSION['GAuthenticator']) {
            return;
        }

        if (Cookie::get('__typecho_GAuthenticator') === md5($config->SecretKey . Cookie::getPrefix() . $user->uid)) {
            return;
        }

        if ($config->SecretOn == 1) {
            require_once __DIR__ . '/verification.php';
        }
    }
}
