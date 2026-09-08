<?php

namespace TypechoPlugin\GAuthenticator;

use Typecho\Db;
use Typecho\Db\Exception as DbException;
use Typecho\Plugin\PluginInterface;
use Typecho\Plugin\Exception as PluginException;
use Typecho\Cookie;
use Typecho\Router;
use Typecho\Widget\Exception as WidgetException;
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
 * @version 0.2.1
 * @link https://github.com/vndroid/GAuthenticator
 */
class Plugin implements PluginInterface
{
    /** 待验证挑战的有效期(秒) */
    public const CHALLENGE_TTL = 300;

    /** 单个挑战允许的验证次数 */
    public const MAX_ATTEMPTS = 5;

    /** 挑战在 session 中的键名 */
    public const CHALLENGE_KEY = 'GAuthenticator_pending';

    /** 「本次登录态已通过 OTP」的标记 cookie */
    public const SESSION_COOKIE = '__typecho_GAuthenticator_v';

    /** 「记住本机」cookie */
    public const DEVICE_COOKIE = '__typecho_GAuthenticator';

    /** 记住本机的有效期(秒) */
    public const DEVICE_TTL = 30 * 24 * 3600;

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

        /**
         * 关键钩子：密码校验通过之后立刻接管，避免 Typecho 在 OTP 之前就发出完整登录凭据
         */
        \Typecho\Plugin::factory('Widget\User')->loginSucceed = [self::class, 'onLoginSucceed'];

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

        $element = new Text('SecretTime', null, '1', _t('容差倍率'), '容差时间，输入的值为30秒的倍数（如果输入1，那么容差时间为 1 × 30秒 = 30秒），只接受 0-2，推荐 1');
        $form->addInput($element);

        $element = new Text('SecretCode', null, '', _t('客户端代码'), '六位验证码，用兼容 TOTP 协议的 APP 扫描二维码或者手动输入第一行的 SecretKey 即可生成。');
        $form->addInput($element);

        $element = new Radio(
            'SecretXmlRpc',
            ['0' => '拒绝（推荐）', '1' => '允许'],
            '0',
            _t('XML-RPC 密码登录'),
            'XML-RPC / MetaWeblog 接口只能用用户名和密码认证，无法参与两步验证。保持「拒绝」时，2FA 开启期间这些接口会拒绝一切密码认证（pingback 不受影响）。'
        );
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

            /** 密钥不允许从表单修改，先把存量值取回来再做校验 */
            $config['SecretKey'] = $configOld->SecretKey;
            $config['SecretQRInfo'] = $configOld->SecretQRInfo;

            if ($config['SecretOn'] == 1 && $config['SecretCode'] != '') {
                require_once __DIR__ . '/GoogleAuthenticator.php';
                $authenticator = new \PHPGangsta_GoogleAuthenticator();
                if (!$authenticator->verifyCode($config['SecretKey'], $config['SecretCode'], self::discrepancy($config['SecretTime'] ?? 1))) {
                    throw new PluginException('2FA 代码校验失败，请重试或关闭');
                }
                $config['SecretOn'] = 1;
            }
        }

        $config['SecretTime'] = (string) self::discrepancy($config['SecretTime'] ?? 1);
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
        if (self::isEnabled()) {
            echo '<span class="message success">' . htmlspecialchars('2FA 已启用') . '</span>';
        } else {
            echo '<span class="message error">' . htmlspecialchars('2FA 未启用') . '</span>';
        }
    }

    // ------------------------------------------------------------------
    // 登录状态机
    // ------------------------------------------------------------------

    /**
     * 密码校验通过后立刻接管
     *
     * Typecho 在 login() 里先 commitLogin() 再触发本钩子，也就是说进到这里时
     * 完整登录凭据已经生成。这里的职责是：在响应发出之前把这份凭据作废，
     * 换成一个短期、一次性的待验证挑战，等 OTP 通过后再重新签发。
     *
     * @param User $user
     * @param string $name
     * @param string $password
     * @param bool $temporarily 临时登录(不落 cookie)，目前只有 XML-RPC 走这条路
     * @param int $expire
     * @throws DbException|WidgetException|PluginException
     */
    public static function onLoginSucceed(User $user, string $name, string $password, bool $temporarily, int $expire): void
    {
        if (!self::isEnabled()) {
            return;
        }

        /** XML-RPC 之类的密码认证接口没有第二因素通道，只能拒绝 */
        if ($temporarily) {
            if (self::pluginConfig()->SecretXmlRpc == 1) {
                return;
            }

            throw new WidgetException(_t('该站点已启用两步验证, 不接受 XML-RPC 密码认证'), 403);
        }

        $uid = (int) $user->uid;

        /** 可信设备：跳过 OTP，但仍然要给这次登录态盖上「已验证」的章 */
        if (self::verifyDeviceToken(Cookie::get(self::DEVICE_COOKIE), $uid, (string) $user->password)) {
            self::issueSessionToken($uid, (string) $user->authCode, $expire);
            return;
        }

        /**
         * 作废刚刚签发的登录凭据。
         * 只删 cookie 是不够的 —— Set-Cookie 头已经排进响应队列，
         * 非浏览器客户端能直接把第一份读走，所以必须让服务端的 authCode 失效。
         */
        self::revokeCommittedLogin($uid);

        self::startSession();
        session_regenerate_id(true);

        $_SESSION[self::CHALLENGE_KEY] = [
            'uid'      => $uid,
            'expire'   => $expire,
            'deadline' => time() + self::CHALLENGE_TTL,
            'tries'    => 0,
            'referer'  => self::safeReferer(\Typecho\Request::getInstance()->get('referer')),
        ];

        Helper::options()->response->redirect(self::otpUrl());
    }

    /**
     * 后台拦截：兜底防线
     *
     * 新的登录流程里，能拿到有效 __typecho_authCode 就意味着已经过了 OTP，
     * 所以这里只负责挡住升级之前遗留的、没有验证标记的登录态。
     *
     * @throws DbException|PluginException
     */
    public static function authenticatorVerification(): void
    {
        static $initialized = false;
        if ($initialized) {
            return;
        }
        $initialized = true;

        if (!self::isEnabled()) {
            return;
        }

        $user = User::alloc();
        if (!$user->hasLogin()) {
            return;
        }

        $uid = (int) $user->uid;

        if (self::verifySessionToken(Cookie::get(self::SESSION_COOKIE), $uid, (string) $user->authCode)) {
            return;
        }

        if (self::verifyDeviceToken(Cookie::get(self::DEVICE_COOKIE), $uid, (string) $user->password)) {
            self::issueSessionToken($uid, (string) $user->authCode, 0);
            return;
        }

        /** 这个登录态没有经过两步验证(多半是启用 2FA 之前留下的)，请重新登录 */
        $user->logout();
        Helper::options()->response->redirect(Helper::options()->loginUrl);
    }

    // ------------------------------------------------------------------
    // 令牌
    // ------------------------------------------------------------------

    /**
     * 「本次登录态已通过 OTP」标记
     *
     * 绑定 authCode(只存在于数据库，cookie 里存的是它的散列)，
     * 因此无法离线伪造，并且用户登出、改密码、重新登录后自动失效。
     *
     * @param int $uid
     * @param string $authCode
     * @return string
     */
    public static function sessionToken(int $uid, string $authCode): string
    {
        return hash_hmac('sha256', 'ga2fa-session|' . $uid . '|' . $authCode, self::serverKey());
    }

    /**
     * @param int $uid
     * @param string $authCode
     * @param int $expire
     */
    public static function issueSessionToken(int $uid, string $authCode, int $expire = 0): void
    {
        self::setCookie(self::SESSION_COOKIE, self::sessionToken($uid, $authCode), $expire);
    }

    /**
     * @param string|null $value
     * @param int $uid
     * @param string $authCode
     * @return bool
     */
    public static function verifySessionToken(?string $value, int $uid, string $authCode): bool
    {
        if (!is_string($value) || $value === '' || $authCode === '') {
            return false;
        }

        return hash_equals(self::sessionToken($uid, $authCode), $value);
    }

    /**
     * 「记住本机」令牌: <到期时间>:<签名>
     *
     * 签名里带上用户当前的密码散列，所以改密码会一次性吊销全部可信设备。
     *
     * @param int $uid
     * @param string $passwordHash
     * @param int $deadline
     * @return string
     */
    public static function deviceToken(int $uid, string $passwordHash, int $deadline): string
    {
        $sign = hash_hmac(
            'sha256',
            'ga2fa-device|' . $uid . '|' . $deadline . '|' . $passwordHash,
            self::serverKey()
        );

        return $deadline . ':' . $sign;
    }

    /**
     * @param string|null $value
     * @param int $uid
     * @param string $passwordHash
     * @return bool
     */
    public static function verifyDeviceToken(?string $value, int $uid, string $passwordHash): bool
    {
        if (!is_string($value) || !str_contains($value, ':') || $passwordHash === '') {
            return false;
        }

        [$deadline, ] = explode(':', $value, 2);
        if (!ctype_digit($deadline) || intval($deadline) <= time()) {
            return false;
        }

        return hash_equals(self::deviceToken($uid, $passwordHash, intval($deadline)), $value);
    }

    // ------------------------------------------------------------------
    // 工具
    // ------------------------------------------------------------------

    /**
     * 读取插件配置
     *
     * @return \Typecho\Config
     * @throws PluginException
     */
    public static function pluginConfig()
    {
        return Helper::options()->plugin('GAuthenticator');
    }

    /**
     * @return bool
     * @throws PluginException
     */
    public static function isEnabled(): bool
    {
        return 1 == self::pluginConfig()->SecretOn;
    }

    /**
     * 容差只接受 0-2
     *
     * @param mixed $value
     * @return int
     */
    public static function discrepancy($value): int
    {
        return max(0, min(2, intval($value)));
    }

    /**
     * @return string
     */
    private static function serverKey(): string
    {
        return (string) Helper::options()->secret;
    }

    /**
     * @return string
     */
    public static function otpUrl(): string
    {
        return Router::url('do', ['action' => 'GAuthenticator'], Helper::options()->index);
    }

    /**
     * 作废 commitLogin 刚刚签发的那份凭据
     *
     * @param int $uid
     * @throws DbException
     */
    private static function revokeCommittedLogin(int $uid): void
    {
        Cookie::delete('__typecho_uid');
        Cookie::delete('__typecho_authCode');

        $db = Db::get();
        $db->query($db->update('table.users')
            ->rows(['authCode' => bin2hex(random_bytes(16))])
            ->where('uid = ?', $uid));
    }

    /**
     * 带 SameSite 的 cookie 写入(Typecho 自带的 Cookie::set 不支持 SameSite)
     *
     * @param string $key
     * @param string $value
     * @param int $expire 0 表示随会话结束
     */
    public static function setCookie(string $key, string $value, int $expire = 0): void
    {
        $name = Cookie::getPrefix() . $key;
        $_COOKIE[$name] = $value;

        if (headers_sent()) {
            return;
        }

        /** 与 Typecho\Response::sendHeaders 保持一致：小于「昨天」的值按相对秒数处理 */
        if ($expire > 0) {
            $now = time();
            $expire += $expire > $now - 86400 ? 0 : $now;
        } else {
            $expire = 0;
        }

        setcookie($name, $value, [
            'expires'  => $expire,
            'path'     => Cookie::getPath(),
            'domain'   => Cookie::getDomain(),
            'secure'   => \Typecho\Request::getInstance()->isSecure(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }

    /**
     * @param string $key
     */
    public static function deleteCookie(string $key): void
    {
        $name = Cookie::getPrefix() . $key;
        unset($_COOKIE[$name]);

        if (headers_sent()) {
            return;
        }

        setcookie($name, '', [
            'expires'  => 1,
            'path'     => Cookie::getPath(),
            'domain'   => Cookie::getDomain(),
            'secure'   => \Typecho\Request::getInstance()->isSecure(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }

    /**
     * 未登录状态下 Typecho 不会开 session，这里自己开
     */
    public static function startSession(): void
    {
        if (PHP_SESSION_ACTIVE !== session_status() && !headers_sent()) {
            @session_start();
        }
    }

    /**
     * 取出当前的待验证挑战，过期的直接丢弃
     *
     * @return array|null
     */
    public static function getChallenge(): ?array
    {
        self::startSession();

        $challenge = $_SESSION[self::CHALLENGE_KEY] ?? null;
        if (!is_array($challenge) || empty($challenge['uid'])) {
            return null;
        }

        if (($challenge['deadline'] ?? 0) < time()) {
            self::clearChallenge();
            return null;
        }

        return $challenge;
    }

    /**
     * @param array $challenge
     */
    public static function saveChallenge(array $challenge): void
    {
        self::startSession();
        $_SESSION[self::CHALLENGE_KEY] = $challenge;
    }

    /**
     * 挑战一次性：成功、超时、次数用尽都要立刻作废
     */
    public static function clearChallenge(): void
    {
        self::startSession();
        unset($_SESSION[self::CHALLENGE_KEY]);
    }

    /**
     * 一次性提示信息
     *
     * @param string $message
     */
    public static function setFlash(string $message): void
    {
        self::startSession();
        $_SESSION[self::CHALLENGE_KEY . '_flash'] = $message;
    }

    /**
     * @return string
     */
    public static function takeFlash(): string
    {
        self::startSession();
        $message = (string) ($_SESSION[self::CHALLENGE_KEY . '_flash'] ?? '');
        unset($_SESSION[self::CHALLENGE_KEY . '_flash']);

        return $message;
    }

    /**
     * 回跳地址校验：严格比对 scheme / host / port / 路径前缀
     *
     * @param mixed $referer
     * @return string
     */
    public static function safeReferer($referer): string
    {
        $options = Helper::options();
        $referer = trim((string) $referer);

        if ($referer !== '' && !str_contains($referer, 'GAuthenticator')) {
            foreach ([$options->adminUrl, $options->siteUrl] as $base) {
                if (self::sameOrigin($referer, (string) $base)) {
                    return $referer;
                }
            }
        }

        return $options->adminUrl;
    }

    /**
     * @param string $url
     * @param string $base
     * @return bool
     */
    private static function sameOrigin(string $url, string $base): bool
    {
        $a = parse_url($url);
        $b = parse_url($base);

        if (!is_array($a) || !is_array($b) || empty($a['host']) || empty($b['host'])) {
            return false;
        }

        if (strtolower($a['scheme'] ?? '') !== strtolower($b['scheme'] ?? '')) {
            return false;
        }

        if (strtolower($a['host']) !== strtolower($b['host'])) {
            return false;
        }

        if (($a['port'] ?? null) !== ($b['port'] ?? null)) {
            return false;
        }

        $basePath = rtrim($b['path'] ?? '/', '/') . '/';

        return str_starts_with($a['path'] ?? '/', $basePath);
    }
}
