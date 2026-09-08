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
use Typecho\Widget\Helper\Form\Element\Textarea;
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
 * @version 0.3.0
 * @link https://github.com/vndroid/GAuthenticator
 */
class Plugin implements PluginInterface
{
    /** 待验证挑战的有效期(秒) */
    public const CHALLENGE_TTL = 300;

    /** 单个挑战允许的验证次数 */
    public const MAX_ATTEMPTS = 5;

    /** 待验证挑战的随机凭据 cookie */
    public const CHALLENGE_COOKIE = '__typecho_GAuthenticator_c';

    /** 「本次登录态已通过 OTP」的标记 cookie */
    public const SESSION_COOKIE = '__typecho_GAuthenticator_v';

    /** 「记住本机」cookie */
    public const DEVICE_COOKIE = '__typecho_GAuthenticator';

    /** 记住本机的有效期(秒) */
    public const DEVICE_TTL = 30 * 24 * 3600;

    /** 每个用户保存 2FA 状态的 option 名 */
    public const PERSONAL_OPTION = '_plugin:GAuthenticator';

    /** 最多保留的可信设备数 */
    public const MAX_DEVICES = 10;

    /** 一次生成的恢复码数量 */
    public const RECOVERY_CODE_COUNT = 8;

    /** 恢复码仅显示一次时使用的加密 cookie */
    private const RECOVERY_FLASH_COOKIE = '__typecho_GAuthenticator_r';

    /** 每个请求只执行一次旧全局配置清理 */
    private static bool $globalMigrated = false;

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
        \Typecho\Plugin::factory('Widget\Register')->finishRegister = [self::class, 'onFinishRegister'];

        /** 为存量用户补齐个人配置。旧的全局密钥不会迁移，未绑定用户默认放行。 */
        self::provisionAllUsers();

        $configLink = '<a href="' . Helper::options()->adminUrl('options-plugin.php?config=' . basename(__DIR__), true) . '">' . _t('前往设置') . '</a>';

        return _t('两步验证已按用户启用，请让各用户在个人设置中自行绑定。') . ' ' . $configLink;
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
        $element = new Text('SecretTime', null, '1', _t('容差倍率'), '容差时间，输入的值为30秒的倍数（如果输入1，那么容差时间为 1 × 30秒 = 30秒），只接受 0-2，推荐 1');
        $form->addInput($element);

        $element = new Radio(
            'SecretXmlRpc',
            ['0' => '拒绝（推荐）', '1' => '允许'],
            '0',
            _t('XML-RPC 密码登录'),
            'XML-RPC / MetaWeblog 无法输入第二因素。保持「拒绝」时，已绑定 2FA 的用户不能通过这些接口使用密码登录；未绑定用户仍可使用。'
        );
        $form->addInput($element);

        /** 升级时阻止旧全局密钥被配置组件重新渲染到 HTML。 */
        try {
            $legacy = self::pluginConfig();
            foreach (['SecretKey', 'SecretQRInfo', 'SecretCode', 'SecretOn'] as $key) {
                unset($legacy[$key]);
            }
        } catch (PluginException $e) {
            // 首次启用时配置尚不存在。
        }
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
        self::saveGlobalConfig([
            'SecretTime'   => (string) self::discrepancy($config['SecretTime'] ?? 1),
            'SecretXmlRpc' => 1 == ($config['SecretXmlRpc'] ?? 0) ? '1' : '0',
        ]);
    }

    /**
     * 个人用户的配置面板
     *
     * @param Form $form
     */
    public static function personalConfig(Form $form): void
    {
        $user = User::alloc();
        $uid = (int) $user->uid;
        $state = self::userConfig($uid, true);

        if (!preg_match('/^[A-Z2-7]{16,128}$/D', $state['SetupSecret'])) {
            $state['SetupSecret'] = self::newSecret();
            self::saveUserConfig($uid, $state);
        }

        $uri = self::otpAuthUri((string) $user->mail, $state['SetupSecret']);
        $enabled = 1 === (int) $state['SecretOn'];
        $description = ($enabled
            ? '当前账号已启用 2FA。下方二维码是新的候选密钥，只有选择「轮换密钥」并用新验证码确认后才会生效。'
            : '当前账号尚未绑定 2FA，默认允许直接登录。请扫描二维码，再输入验证码并选择开启。')
            . '<div style="font-weight:bold;text-align:center;padding:20px 0">'
            . '<div style="width:260px;height:260px;margin:15px auto;padding:15px;background:#fff"><span id="ga-personal-qrcode"></span></div>'
            . '</div><script>(function(){var load=function(){var run=function(){'
            . '$("#ga-personal-qrcode").empty().qrcode({width:260,height:260,text:' . json_encode($uri) . '});};'
            . 'if($.fn.qrcode){run();}else{$.getScript(' . json_encode(Options::alloc()->pluginUrl . '/GAuthenticator/jquery.qrcode.min.js') . ',run);}};'
            . 'if(document.readyState==="loading"){document.addEventListener("DOMContentLoaded",load);}else{load();}})();</script>';

        $secret = new Text('SetupSecret', null, $state['SetupSecret'], _t('待绑定密钥'), $description);
        $secret->input->setAttribute('readonly', 'readonly');
        $form->addInput($secret);

        $form->addInput(new Text('SecretCode', null, '', _t('验证码'), '开启或轮换时必须填写新密钥产生的六位验证码。'));
        $form->addInput(new Radio('SecretOn', ['1' => '开启', '0' => '关闭'], $enabled ? '1' : '0', _t('当前账号 2FA'), '从关闭切换到开启时，只有验证码验证成功才会保存。'));
        $form->addInput(new Radio('RotateSecret', ['0' => '保持现有密钥', '1' => '轮换为上方新密钥'], '0', _t('密钥轮换'), '轮换会撤销全部可信设备和旧恢复码，并生成一组新恢复码。'));
        $form->addInput(new Radio('RevokeDevices', ['0' => '不操作', '1' => '注销其他可信设备'], '0', _t('可信设备'), sprintf('当前记录了 %d 台有效可信设备。当前浏览器如果本身受信任会被保留。', self::trustedDeviceCount($state))));
        $form->addInput(new Radio('RegenerateRecovery', ['0' => '不操作', '1' => '重新生成'], '0', _t('恢复码'), sprintf('当前剩余 %d 个恢复码。重新生成会立即作废旧恢复码。', count($state['RecoveryCodes']))));

        $codes = self::takeRecoveryCodes();
        if ($codes) {
            $view = new Textarea('RecoveryCodesView', null, implode("\n", $codes), _t('新恢复码（仅显示一次）'), '请立即保存到密码管理器。每个恢复码只能使用一次。');
            $view->input->setAttribute('readonly', 'readonly');
            $form->addInput($view);
        }

        /** Typecho 会自动把个人 option 的每个字段灌回表单；这里只暴露安全的表单字段。 */
        Options::alloc()->{self::PERSONAL_OPTION} = json_encode([
            'SetupSecret' => $state['SetupSecret'],
            'SecretOn'    => $enabled ? '1' : '0',
        ]);
    }

    /**
     * 保存当前用户的个人 2FA 设置。
     *
     * @throws PluginException|DbException
     */
    public static function personalConfigHandle(array $config, bool $is_init): void
    {
        if ($is_init) {
            self::provisionAllUsers();
            return;
        }

        $user = User::alloc();
        $uid = (int) $user->uid;
        $state = self::userConfig($uid, true);
        $wasEnabled = 1 === (int) $state['SecretOn'];
        $enable = 1 == ($config['SecretOn'] ?? 0);
        $rotate = 1 == ($config['RotateSecret'] ?? 0);
        $changedSecret = false;

        if ((!$wasEnabled && $enable) || ($wasEnabled && $enable && $rotate)) {
            $otp = (string) ($config['SecretCode'] ?? '');
            $slice = self::matchTotpSlice($state['SetupSecret'], $otp, -1);
            if ($slice === null) {
                throw new PluginException(_t('新密钥的验证码校验失败，设置未保存'));
            }

            [$hashes, $plainCodes] = self::generateRecoveryCodes();
            $state['SecretOn'] = 1;
            $state['SecretKey'] = $state['SetupSecret'];
            $state['SetupSecret'] = self::newSecret();
            $state['LastSlice'] = $slice;
            $state['TrustedDevices'] = [];
            $state['RecoveryCodes'] = $hashes;
            self::rememberRecoveryCodes($plainCodes);
            self::deleteCookie(self::DEVICE_COOKIE);
            self::issueSessionToken($uid, (string) $user->authCode, 0);
            $changedSecret = true;
        } elseif ($wasEnabled && !$enable) {
            $state = self::defaultUserConfig();
            $state['SetupSecret'] = self::newSecret();
            self::deleteCookie(self::DEVICE_COOKIE);
            self::deleteCookie(self::SESSION_COOKIE);
        }

        if ($enable && 1 == ($config['RevokeDevices'] ?? 0)) {
            $state = self::keepCurrentDeviceOnly($state, Cookie::get(self::DEVICE_COOKIE), (string) $user->password);
        }

        if ($enable && !$changedSecret && 1 == ($config['RegenerateRecovery'] ?? 0)) {
            [$hashes, $plainCodes] = self::generateRecoveryCodes();
            $state['RecoveryCodes'] = $hashes;
            self::rememberRecoveryCodes($plainCodes);
        }

        self::saveUserConfig($uid, $state);
    }

    /**
     * 在后台导航栏显示 2FA 状态
     * @throws PluginException
     */
    public static function authenticatorSafe(): void
    {
        $user = User::alloc();
        if ($user->hasLogin() && self::userIsEnabled((int) $user->uid)) {
            echo '<span class="message success">' . htmlspecialchars('2FA 已启用') . '</span>';
        } else {
            echo '<span class="message error">' . htmlspecialchars('当前账号未启用 2FA') . '</span>';
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
        $uid = (int) $user->uid;
        if (!self::userIsEnabled($uid)) {
            /** 产品策略：没有绑定 2FA 的用户默认放行。 */
            return;
        }

        /** XML-RPC 之类的密码认证接口没有第二因素通道，只能拒绝 */
        if ($temporarily) {
            if (self::xmlRpcAllowed()) {
                return;
            }

            throw new WidgetException(_t('该站点已启用两步验证, 不接受 XML-RPC 密码认证'), 403);
        }

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

        $token = bin2hex(random_bytes(32));
        $state = self::userConfig($uid, false);
        $state['Challenge'] = [
            'hash'     => self::challengeHash($token, $uid),
            'uid'      => $uid,
            'expire'   => $expire,
            'deadline' => time() + self::CHALLENGE_TTL,
            'tries'    => 0,
            'referer'  => self::safeReferer(\Typecho\Request::getInstance()->get('referer')),
            'flash'    => '',
        ];
        self::saveUserConfig($uid, $state);
        self::setCookie(self::CHALLENGE_COOKIE, $uid . ':' . $token, time() + self::CHALLENGE_TTL);

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

        $user = User::alloc();
        if (!$user->hasLogin()) {
            return;
        }

        $uid = (int) $user->uid;
        if (!self::userIsEnabled($uid)) {
            return;
        }

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
     * 签发一个可单独撤销的可信设备令牌。Cookie 保存 id 和随机 token，服务端只保存散列。
     * 密码散列参与计算，因此修改密码仍会让全部设备自动失效。
     */
    public static function issueDeviceToken(int $uid, string $passwordHash): void
    {
        $state = self::userConfig($uid, false);
        if (1 !== (int) $state['SecretOn']) {
            return;
        }

        $now = time();
        $id = bin2hex(random_bytes(8));
        $token = bin2hex(random_bytes(32));
        $deadline = $now + self::DEVICE_TTL;
        $devices = self::validDevices($state['TrustedDevices']);
        $devices[] = [
            'id'      => $id,
            'hash'    => self::deviceHash($token, $passwordHash),
            'created' => $now,
            'expires' => $deadline,
        ];
        $state['TrustedDevices'] = array_slice($devices, -self::MAX_DEVICES);
        self::saveUserConfig($uid, $state);
        self::setCookie(self::DEVICE_COOKIE, $id . ':' . $token, $deadline);
    }

    public static function verifyDeviceToken(?string $value, int $uid, string $passwordHash): bool
    {
        if (!is_string($value) || !preg_match('/^[0-9a-f]{16}:[0-9a-f]{64}$/D', $value) || $passwordHash === '') {
            return false;
        }

        [$id, $token] = explode(':', $value, 2);
        $state = self::userConfig($uid, false);
        $devices = self::validDevices($state['TrustedDevices']);
        $dirty = count($devices) !== count($state['TrustedDevices']);
        $valid = false;

        foreach ($devices as $device) {
            if (hash_equals((string) $device['id'], $id)
                && hash_equals((string) $device['hash'], self::deviceHash($token, $passwordHash))) {
                $valid = true;
            }
        }

        if ($dirty) {
            $state['TrustedDevices'] = $devices;
            self::saveUserConfig($uid, $state);
        }

        return $valid;
    }

    private static function deviceHash(string $token, string $passwordHash): string
    {
        return hash_hmac('sha256', 'ga2fa-device|' . $token . '|' . $passwordHash, self::serverKey());
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

    private static function xmlRpcAllowed(): bool
    {
        try {
            return 1 == (self::pluginConfig()->SecretXmlRpc ?? 0);
        } catch (PluginException $e) {
            /** 配置缺失时保持安全默认值。 */
            return false;
        }
    }

    public static function userIsEnabled(int $uid): bool
    {
        $state = self::userConfig($uid, true);
        return 1 === (int) $state['SecretOn'] && $state['SecretKey'] !== '';
    }

    /** 新注册用户预置关闭状态；后台新增用户则由读取时兜底。 */
    public static function onFinishRegister($registration): void
    {
        $uid = (int) $registration->uid;
        if ($uid > 0) {
            self::userConfig($uid, true);
        }
    }

    /**
     * @return array{SecretOn:int,SecretKey:string,SetupSecret:string,LastSlice:int,TrustedDevices:array,RecoveryCodes:array,Challenge:array}
     */
    public static function defaultUserConfig(): array
    {
        return [
            'SecretOn'       => 0,
            'SecretKey'      => '',
            'SetupSecret'    => '',
            'LastSlice'      => -1,
            'TrustedDevices' => [],
            'RecoveryCodes'  => [],
            'Challenge'      => [],
        ];
    }

    /**
     * 按 uid 读取个人配置。缺行、旧格式或损坏数据都安全降级为「未绑定并放行」。
     *
     * @return array
     */
    public static function userConfig(int $uid, bool $create = true): array
    {
        self::migrateGlobalConfig();
        $defaults = self::defaultUserConfig();
        if ($uid <= 0) {
            return $defaults;
        }

        $db = Db::get();
        $row = $db->fetchRow($db->select('value')->from('table.options')
            ->where('name = ? AND user = ?', self::PERSONAL_OPTION, $uid)
            ->limit(1));

        if (!$row) {
            if ($create) {
                self::saveUserConfig($uid, $defaults);
            }
            return $defaults;
        }

        $decoded = json_decode((string) $row['value'], true);
        if (!is_array($decoded)) {
            if ($create) {
                self::saveUserConfig($uid, $defaults);
            }
            return $defaults;
        }

        $state = array_merge($defaults, $decoded);
        $state['SecretOn'] = 1 === (int) $state['SecretOn'] ? 1 : 0;
        $state['SecretKey'] = is_string($state['SecretKey']) ? $state['SecretKey'] : '';
        $state['SetupSecret'] = is_string($state['SetupSecret']) ? $state['SetupSecret'] : '';
        $state['LastSlice'] = (int) $state['LastSlice'];
        $state['TrustedDevices'] = is_array($state['TrustedDevices']) ? $state['TrustedDevices'] : [];
        $state['RecoveryCodes'] = is_array($state['RecoveryCodes']) ? array_values(array_filter($state['RecoveryCodes'], 'is_string')) : [];
        $state['Challenge'] = is_array($state['Challenge']) ? $state['Challenge'] : [];

        return $state;
    }

    public static function saveUserConfig(int $uid, array $state): void
    {
        if ($uid <= 0) {
            return;
        }

        $state = array_merge(self::defaultUserConfig(), $state);
        $value = json_encode($state, JSON_UNESCAPED_SLASHES);
        if (!is_string($value)) {
            throw new PluginException(_t('无法保存两步验证配置'));
        }

        $db = Db::get();
        $exists = $db->fetchRow($db->select('name')->from('table.options')
            ->where('name = ? AND user = ?', self::PERSONAL_OPTION, $uid)
            ->limit(1));

        if ($exists) {
            $db->query($db->update('table.options')->rows(['value' => $value])
                ->where('name = ? AND user = ?', self::PERSONAL_OPTION, $uid));
        } else {
            $db->query($db->insert('table.options')->rows([
                'name'  => self::PERSONAL_OPTION,
                'value' => $value,
                'user'  => $uid,
            ]));
        }
    }

    public static function provisionAllUsers(): void
    {
        $db = Db::get();
        foreach ($db->fetchAll($db->select('uid')->from('table.users')) as $row) {
            self::userConfig((int) $row['uid'], true);
        }
    }

    /** 只保留新的全局策略配置，升级时直接废弃旧的全站共享密钥。 */
    private static function saveGlobalConfig(array $config): void
    {
        $db = Db::get();
        $value = json_encode($config, JSON_UNESCAPED_SLASHES);
        $exists = $db->fetchRow($db->select('name')->from('table.options')
            ->where('name = ? AND user = 0', 'plugin:GAuthenticator')->limit(1));

        if ($exists) {
            $db->query($db->update('table.options')->rows(['value' => $value])
                ->where('name = ? AND user = 0', 'plugin:GAuthenticator'));
        } else {
            $db->query($db->insert('table.options')->rows([
                'name' => 'plugin:GAuthenticator', 'value' => $value, 'user' => 0,
            ]));
        }
    }

    /** 第一次运行新版本时从数据库中实际移除旧的全站共享密钥。 */
    private static function migrateGlobalConfig(): void
    {
        if (self::$globalMigrated) {
            return;
        }
        self::$globalMigrated = true;

        try {
            $old = self::pluginConfig();
            $values = $old->toArray();
            if (!array_intersect(['SecretKey', 'SecretQRInfo', 'SecretCode', 'SecretOn'], array_keys($values))) {
                return;
            }
            self::saveGlobalConfig([
                'SecretTime'   => (string) self::discrepancy($old->SecretTime ?? 1),
                'SecretXmlRpc' => 1 == ($old->SecretXmlRpc ?? 0) ? '1' : '0',
            ]);
        } catch (PluginException $e) {
            // 首次启用时由 configHandle 创建全局配置。
        }
    }

    private static function newSecret(): string
    {
        require_once __DIR__ . '/GoogleAuthenticator.php';
        return (new \PHPGangsta_GoogleAuthenticator())->createSecret();
    }

    private static function otpAuthUri(string $mail, string $secret): string
    {
        $issuer = (string) Options::alloc()->title;
        $label = $issuer . ':' . $mail;
        return 'otpauth://totp/' . rawurlencode($label) . '?' . http_build_query([
            'secret' => $secret,
            'issuer' => $issuer,
            'period' => 30,
            'digits' => 6,
        ], '', '&', PHP_QUERY_RFC3986);
    }

    /** 返回匹配且未使用的时间片。 */
    public static function matchTotpSlice(string $secret, string $otp, int $lastSlice): ?int
    {
        if ($secret === '' || !preg_match('/^\d{6}$/D', $otp)) {
            return null;
        }

        require_once __DIR__ . '/GoogleAuthenticator.php';
        $authenticator = new \PHPGangsta_GoogleAuthenticator();
        try {
            $discrepancy = self::discrepancy(self::pluginConfig()->SecretTime ?? 1);
        } catch (PluginException $e) {
            $discrepancy = 1;
        }

        $nowSlice = (int) floor(time() / 30);
        $matched = null;
        for ($i = -$discrepancy; $i <= $discrepancy; $i++) {
            $candidate = $nowSlice + $i;
            $equal = hash_equals((string) $authenticator->getCode($secret, $candidate), $otp);
            if ($equal && $candidate > $lastSlice) {
                $matched = $candidate;
            }
        }

        return $matched;
    }

    /** 成功后立即写回 LastSlice，避免同一 TOTP 在有效窗口内再次使用。 */
    public static function consumeTotp(int $uid, string $otp): bool
    {
        $state = self::userConfig($uid, false);
        if (1 !== (int) $state['SecretOn']) {
            return false;
        }

        $slice = self::matchTotpSlice($state['SecretKey'], $otp, (int) $state['LastSlice']);
        if ($slice === null) {
            return false;
        }

        $state['LastSlice'] = $slice;
        self::saveUserConfig($uid, $state);
        return true;
    }

    /**
     * @return array{0:array,1:array}
     */
    private static function generateRecoveryCodes(): array
    {
        $hashes = [];
        $plain = [];
        for ($i = 0; $i < self::RECOVERY_CODE_COUNT; $i++) {
            $raw = strtoupper(bin2hex(random_bytes(5)));
            $code = substr($raw, 0, 5) . '-' . substr($raw, 5);
            $plain[] = $code;
            $hashes[] = password_hash($raw, PASSWORD_DEFAULT);
        }
        return [$hashes, $plain];
    }

    public static function consumeRecoveryCode(int $uid, string $code): bool
    {
        $normalized = strtoupper(str_replace(['-', ' '], '', trim($code)));
        if (!preg_match('/^[0-9A-F]{10}$/D', $normalized)) {
            return false;
        }

        $state = self::userConfig($uid, false);
        if (1 !== (int) $state['SecretOn']) {
            return false;
        }

        foreach ($state['RecoveryCodes'] as $index => $hash) {
            if (password_verify($normalized, $hash)) {
                unset($state['RecoveryCodes'][$index]);
                $state['RecoveryCodes'] = array_values($state['RecoveryCodes']);
                self::saveUserConfig($uid, $state);
                return true;
            }
        }

        return false;
    }

    private static function rememberRecoveryCodes(array $codes): void
    {
        $plain = json_encode(array_values($codes), JSON_UNESCAPED_SLASHES);
        if (!is_string($plain)) {
            throw new PluginException(_t('无法暂存恢复码'));
        }

        $iv = random_bytes(12);
        $tag = '';
        $cipher = openssl_encrypt(
            $plain,
            'aes-256-gcm',
            self::flashKey(),
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            self::RECOVERY_FLASH_COOKIE
        );
        if (!is_string($cipher)) {
            throw new PluginException(_t('无法加密恢复码'));
        }

        self::setCookie(
            self::RECOVERY_FLASH_COOKIE,
            self::base64UrlEncode($iv . $tag . $cipher),
            time() + self::CHALLENGE_TTL
        );
    }

    private static function takeRecoveryCodes(): array
    {
        $encoded = Cookie::get(self::RECOVERY_FLASH_COOKIE);
        self::deleteCookie(self::RECOVERY_FLASH_COOKIE);
        if (!is_string($encoded) || $encoded === '') {
            return [];
        }

        $packed = self::base64UrlDecode($encoded);
        if ($packed === null || strlen($packed) < 29) {
            return [];
        }

        $iv = substr($packed, 0, 12);
        $tag = substr($packed, 12, 16);
        $cipher = substr($packed, 28);
        $plain = openssl_decrypt(
            $cipher,
            'aes-256-gcm',
            self::flashKey(),
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            self::RECOVERY_FLASH_COOKIE
        );
        if (!is_string($plain)) {
            return [];
        }

        $codes = json_decode($plain, true);
        return is_array($codes) ? array_values(array_filter($codes, 'is_string')) : [];
    }

    private static function validDevices($devices): array
    {
        if (!is_array($devices)) {
            return [];
        }
        $now = time();
        return array_values(array_filter($devices, static function ($device) use ($now): bool {
            return is_array($device)
                && !empty($device['id'])
                && !empty($device['hash'])
                && (int) ($device['expires'] ?? 0) > $now;
        }));
    }

    private static function trustedDeviceCount(array $state): int
    {
        return count(self::validDevices($state['TrustedDevices']));
    }

    private static function keepCurrentDeviceOnly(array $state, ?string $cookie, string $passwordHash): array
    {
        $parts = is_string($cookie) ? explode(':', $cookie, 2) : [];
        $currentId = count($parts) === 2 ? $parts[0] : '';
        $currentHash = count($parts) === 2 ? self::deviceHash($parts[1], $passwordHash) : '';
        $state['TrustedDevices'] = array_values(array_filter(
            self::validDevices($state['TrustedDevices']),
            static fn(array $device): bool => $currentId !== ''
                && hash_equals((string) $device['id'], $currentId)
                && hash_equals((string) $device['hash'], $currentHash)
        ));
        return $state;
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
     * 取出当前的待验证挑战，过期的直接丢弃
     *
     * @return array|null
     */
    public static function getChallenge(): ?array
    {
        $cookie = Cookie::get(self::CHALLENGE_COOKIE);
        if (!is_string($cookie) || !preg_match('/^([1-9][0-9]*):([0-9a-f]{64})$/D', $cookie, $parts)) {
            return null;
        }

        $uid = (int) $parts[1];
        $state = self::userConfig($uid, false);
        $challenge = $state['Challenge'];
        if (!is_array($challenge)
            || (int) ($challenge['uid'] ?? 0) !== $uid
            || !isset($challenge['hash'])
            || !hash_equals((string) $challenge['hash'], self::challengeHash($parts[2], $uid))) {
            self::deleteCookie(self::CHALLENGE_COOKIE);
            return null;
        }

        if (($challenge['deadline'] ?? 0) < time()) {
            self::clearChallenge($uid);
            return null;
        }

        return $challenge;
    }

    /**
     * @param array $challenge
     */
    public static function saveChallenge(array $challenge): void
    {
        $uid = (int) ($challenge['uid'] ?? 0);
        if ($uid <= 0 || self::getChallenge() === null) {
            return;
        }

        $state = self::userConfig($uid, false);
        $hash = (string) ($state['Challenge']['hash'] ?? '');
        $challenge['hash'] = $hash;
        $state['Challenge'] = $challenge;
        self::saveUserConfig($uid, $state);
    }

    /**
     * 挑战一次性：成功、超时、次数用尽都要立刻作废
     */
    public static function clearChallenge(int $uid = 0): void
    {
        if ($uid <= 0) {
            $cookie = Cookie::get(self::CHALLENGE_COOKIE);
            if (is_string($cookie) && preg_match('/^([1-9][0-9]*):/', $cookie, $parts)) {
                $uid = (int) $parts[1];
            }
        }

        if ($uid > 0) {
            $state = self::userConfig($uid, false);
            $state['Challenge'] = [];
            self::saveUserConfig($uid, $state);
        }
        self::deleteCookie(self::CHALLENGE_COOKIE);
    }

    /**
     * 一次性提示信息
     *
     * @param string $message
     */
    public static function setFlash(string $message): void
    {
        $challenge = self::getChallenge();
        if ($challenge !== null) {
            $challenge['flash'] = $message;
            self::saveChallenge($challenge);
        }
    }

    /**
     * @return string
     */
    public static function takeFlash(): string
    {
        $challenge = self::getChallenge();
        if ($challenge === null) {
            return '';
        }

        $message = (string) ($challenge['flash'] ?? '');
        $challenge['flash'] = '';
        self::saveChallenge($challenge);
        return $message;
    }

    private static function challengeHash(string $token, int $uid): string
    {
        return hash_hmac('sha256', 'ga2fa-challenge|' . $uid . '|' . $token, self::serverKey());
    }

    private static function flashKey(): string
    {
        return hash('sha256', 'ga2fa-recovery-flash|' . self::serverKey(), true);
    }

    private static function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private static function base64UrlDecode(string $value): ?string
    {
        if (!preg_match('/^[A-Za-z0-9_-]+$/D', $value)) {
            return null;
        }
        $decoded = base64_decode(strtr($value, '-_', '+/'), true);
        return is_string($decoded) ? $decoded : null;
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
