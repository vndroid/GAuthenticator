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
use Typecho\Widget\Helper\Layout;
use Typecho\Widget\Helper\Form\Element\Text;
use Typecho\Widget\Helper\Form\Element\Radio;
use Typecho\Widget\Helper\Form\Element\Select;
use Typecho\Widget\Helper\Form\Element\Textarea;
use Utils\Helper;
use Widget\Options;
use Widget\Security;
use Widget\User;

if (!defined('__TYPECHO_ROOT_DIR__')) {
    exit;
}

/**
 * Google Authenticator for Typecho
 *
 * @package GAuthenticator
 * @author Vex
 * @version 0.3.3
 * @since 1.2.0
 * @link https://github.com/vndroid/GAuthenticator
 */
class Plugin implements PluginInterface
{
    /** 允许的 TOTP 容差倍率(每倍 30 秒)，2 以上仅为特殊场景保留 */
    public const TOLERANCE_CHOICES = [1, 2, 3];

    /** 容差倍率的推荐值，同时也是所有非法取值的收敛目标 */
    public const TOLERANCE_DEFAULT = 1;

    /** 「控制台 → 两步认证」面板，相对于插件目录的父级 */
    public const PANEL_FILE = 'GAuthenticator/Panel.php';

    /** 面板表单的提交路由，只能用字母（路由规则是 /action/[action:alpha]） */
    public const SETUP_ACTION = 'GAuthenticatorSetup';

    /** 待验证挑战的有效期(秒) */
    public const CHALLENGE_TTL = 300;

    /** 单个挑战允许的验证次数 */
    public const MAX_ATTEMPTS = 5;

    /** 跨挑战累计失败的统计窗口(秒) */
    public const FAILURE_WINDOW = 600;

    /** 统计窗口内允许的二次验证失败次数 */
    public const MAX_FAILURES = 5;

    /** 达到失败上限后的账号锁定时间(秒) */
    public const LOCK_TTL = 600;

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

    /** consumeTotp 的返回值：码不对 */
    public const TOTP_INVALID = 0;

    /** consumeTotp 的返回值：码正确且本次消费成功 */
    public const TOTP_OK = 1;

    /** consumeTotp 的返回值：码正确但该时间片已经用过 */
    public const TOTP_REUSED = 2;

    /** 每个请求只执行一次旧全局配置清理 */
    private static bool $globalMigrated = false;

    /** 每个请求只从主库读一次全局策略配置 */
    private static ?array $globalConfigCache = null;

    /** 运行本插件所需的最低 PHP 版本 */
    public const MIN_PHP_VERSION = '8.2.0';

    /** 运行本插件所必需的扩展 */
    public const REQUIRED_EXTENSIONS = ['openssl'];

    /**
     * 激活插件方法,如果激活失败,直接抛出异常
     *
     * @return string
     * @throws PluginException
     */
    public static function activate(): string
    {
        /** 先检查运行环境，缺什么在这里说清楚，不要等到用户绑定到一半才崩 */
        self::checkEnvironment();

        if (!str_ends_with(trim(__DIR__, '/\\'), 'GAuthenticator')) {
            throw new PluginException(_t('插件目录名必须为 GAuthenticator，且首字母大写，请检查插件目录名是否正确'));
        }

        Helper::addAction('GAuthenticator', __NAMESPACE__ . '\Action');
        Helper::addAction(self::SETUP_ACTION, __NAMESPACE__ . '\Setup');

        /**
         * 绑定入口独立成「控制台 → 两步认证」。
         * 等级取 subscriber：每个人绑的都是自己的密钥，不能只给管理员看。
         * addPanel 是追加语义，先移除一次避免重复启用时留下两条同样的菜单。
         */
        Helper::removePanel(1, self::PANEL_FILE);
        Helper::addPanel(1, self::PANEL_FILE, _t('两步认证'), _t('两步认证'), 'subscriber');

        \Typecho\Plugin::factory('admin/menu.php')->navBar = [self::class, 'authenticatorSafe'];
        \Typecho\Plugin::factory('admin/common.php')->begin = [self::class, 'authenticatorVerification'];

        /**
         * 关键钩子：密码校验通过之后立刻接管，避免 Typecho 在 OTP 之前就发出完整登录凭据
         */
        \Typecho\Plugin::factory('Widget\User')->loginSucceed = [self::class, 'onLoginSucceed'];
        \Typecho\Plugin::factory('Widget\Register')->finishRegister = [self::class, 'onFinishRegister'];

        /** 为存量用户补齐个人配置。旧的全局密钥不会迁移，未绑定用户默认放行。 */
        self::provisionAllUsers();

        /**
         * 这两个链接指向的是两件不同的事，文字必须分得清：
         * 旧版本这里只有一个「前往设置」，指向站点策略页——那一页没有二维码，
         * 照着它走的人会以为绑定功能不见了。
         */
        $bindLink = '<a href="' . self::panelUrl() . '">' . _t('去绑定（控制台 → 两步认证）') . '</a>';
        $configLink = '<a href="' . Helper::options()->adminUrl('options-plugin.php?config=' . basename(__DIR__), true) . '">' . _t('站点策略设置') . '</a>';

        return _t('两步验证已按用户启用，每位用户需自行绑定。') . ' ' . $bindLink . ' &bull; ' . $configLink;
    }

    /**
     * 启用前的环境检查
     *
     * openssl 用来加密「只显示一次」的恢复码信封，缺了它并不会被优雅降级：
     * rememberRecoveryCodes() 是在事务提交之后才调用的，届时 2FA 已经开启、
     * 恢复码散列已入库，但明文永远不会显示出来 —— 用户会得到一个
     * 「有 2FA 却没有恢复码」的账号。所以必须在启用这一步就拦住。
     *
     * @throws PluginException
     */
    public static function checkEnvironment(): void
    {
        if (version_compare(PHP_VERSION, self::MIN_PHP_VERSION, '<')) {
            throw new PluginException(_t(
                '本插件需要 PHP %s 或更高版本，当前为 %s',
                self::MIN_PHP_VERSION,
                PHP_VERSION
            ));
        }

        $missing = [];
        foreach (self::REQUIRED_EXTENSIONS as $extension) {
            if (!extension_loaded($extension)) {
                $missing[] = $extension;
            }
        }

        if ($missing) {
            throw new PluginException(_t(
                '本插件需要 %s 扩展（用于加密只显示一次的恢复码），请先在 PHP 中启用',
                implode('、', $missing)
            ));
        }
    }

    /**
     * 禁用插件方法,如果禁用失败,直接抛出异常
     *
     * @return string
     */
    public static function deactivate(): string
    {
        Helper::removeAction('GAuthenticator');
        Helper::removeAction(self::SETUP_ACTION);
        Helper::removePanel(1, self::PANEL_FILE);

        return _t('两步验证已关闭');
    }

    /**
     * 获取插件配置面板
     *
     * @param Form $form 配置面板
     */
    public static function config(Form $form): void
    {
        /**
         * 这一页只有站点级策略，绑定入口在别处。不写清楚的话，
         * 管理员点开「设置 → GAuthenticator」看不到二维码，
         * 第一反应就是「绑定功能没了」。
         */
        $notice = new Layout('div');
        $notice->setAttribute('class', 'message notice');
        $notice->html(
            _t('本页是<strong>站点级策略</strong>，对全站生效。')
            . _t('绑定验证器、轮换密钥、恢复码和可信设备属于每位用户自己的设置，请前往 ')
            . '<a href="' . self::panelUrl() . '">' . _t('控制台 → 两步认证') . '</a>。'
        );
        $form->addItem($notice);

        $element = new Select(
            'SecretTime',
            [
                '1' => '1 × 30 秒（推荐）',
                '2' => '2 × 30 秒',
                '3' => '3 × 30 秒（不推荐）',
            ],
            (string) self::TOLERANCE_DEFAULT,
            _t('容差倍率'),
            '允许验证码与服务器时间相差几个 30 秒周期。推荐保持 1，它已经能吸收输入验证码的几秒延迟；'
            . '只有在服务器长期不校时、确实存在明显时钟漂移时才调大。'
            . '每调大一档，盲猜命中率和验证码被截获后的可用时间都会同步上升，因此不推荐 2 以上。'
        );
        $element->addRule('enum', _t('容差倍率只能是 1、2 或 3'), array_map('strval', self::TOLERANCE_CHOICES));
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
            'SecretTime'   => (string) self::discrepancy($config['SecretTime'] ?? self::TOLERANCE_DEFAULT),
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
        /**
         * 故意留空。PluginInterface 要求存在这个方法，但 Typecho 的 parseInfo
         * 是靠「方法体里有没有东西」来判断要不要在个人设置页渲染这一节的，
         * 空实现＝个人设置页不再出现 GAuthenticator。绑定界面已经移到
         * 「控制台 → 两步认证」(Panel.php)，由 setupForm() 构建。
         *
         * 同时这也让核心的 Widget\Users\Profile::updatePersonal() 不再接管保存，
         * 保存改走 Setup 这个自有 action —— 核心那条路径写死了保存后跳回
         * profile.php，面板搬走之后会把人跳丢。
         */
    }

    /**
     * 「控制台 → 两步认证」面板上的表单
     *
     * 注意：这个方法有副作用——它会消费「新恢复码只显示一次」的一次性 Cookie，
     * 所以每次请求最多只能调用一次，且必须在开始输出 HTML 之前调用。
     *
     * @return Form
     * @throws PluginException|DbException
     */
    public static function setupForm(): Form
    {
        $form = new Form(self::setupAction(), Form::POST_METHOD);
        $form->setAttribute('name', 'GAuthenticator');
        $form->setAttribute('id', 'GAuthenticator');

        $user = User::alloc();
        $uid = (int) $user->uid;
        $state = self::withUserConfigTransaction($uid, static function (array $state): array {
            if (preg_match('/^[A-Z2-7]{16,128}$/D', $state['SetupSecret'])) {
                return [null, $state];
            }

            $state['SetupSecret'] = self::newSecret();
            return [$state, $state];
        });

        $uri = self::otpAuthUri((string) $user->mail, $state['SetupSecret']);
        $enabled = 1 === (int) $state['SecretOn'];
        $description = ($enabled
            ? '当前账号已启用 2FA。下方二维码是新的候选密钥，只有选择「轮换密钥」并用新验证码确认后才会生效。'
            : '当前账号尚未绑定 2FA，默认允许直接登录。请扫描二维码，再输入验证码并选择开启。')
            /** 二维码跟着表单左对齐，不再居中：正文列已经是左起排版，居中会让它孤零零飘在中间。 */
            . '<div style="font-weight:bold;padding:20px 0">'
            . '<div style="width:260px;height:260px;margin:15px 0;padding:15px;background:#fff"><span id="ga-personal-qrcode"></span></div>'
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

        $submit = new Form\Element\Submit('submit', null, _t('保存设置'));
        $submit->input->setAttribute('class', 'btn primary');
        $form->addItem($submit);

        return $form;
    }

    /**
     * 面板表单的提交目标（带 CSRF 令牌）
     *
     * @return string
     */
    public static function setupAction(): string
    {
        return Security::alloc()->getIndex('/action/' . self::SETUP_ACTION);
    }

    /**
     * 「控制台 → 两步认证」面板地址
     *
     * @return string
     */
    public static function panelUrl(): string
    {
        return Helper::options()->adminUrl('extending.php?panel=' . urlencode(self::PANEL_FILE), true);
    }

    /**
     * 保存当前用户的个人 2FA 设置。
     *
     * @throws PluginException|DbException
     */
    public static function handleSetup(array $config): void
    {
        $user = User::alloc();
        $uid = (int) $user->uid;
        $enable = 1 == ($config['SecretOn'] ?? 0);
        $rotate = 1 == ($config['RotateSecret'] ?? 0);
        $revokeDevices = $enable && 1 == ($config['RevokeDevices'] ?? 0);
        $regenerateRecovery = $enable && 1 == ($config['RegenerateRecovery'] ?? 0);
        $otp = (string) ($config['SecretCode'] ?? '');
        $deviceCookie = Cookie::get(self::DEVICE_COOKIE);
        $passwordHash = (string) $user->password;

        /**
         * 必须在锁内重新读取并只修改目标字段。否则个人设置页打开后发生的
         * TOTP 消费、挑战计数或可信设备更新，会被表单提交时的旧 JSON 覆盖。
         * 回调只描述提交后的响应副作用，绝不在事务中发送或删除 Cookie。
         */
        $effects = self::withUserConfigTransaction(
            $uid,
            static function (array $state) use (
                $enable,
                $rotate,
                $revokeDevices,
                $regenerateRecovery,
                $otp,
                $deviceCookie,
                $passwordHash
            ): array {
                $wasEnabled = 1 === (int) $state['SecretOn'];
                $changedSecret = false;
                $effects = [
                    'recoveryCodes' => [],
                    'deleteDeviceCookie' => false,
                    'deleteSessionCookie' => false,
                    'issueSessionToken' => false,
                ];

                if ((!$wasEnabled && $enable) || ($wasEnabled && $enable && $rotate)) {
                    $slice = self::matchTotpSlice($state['SetupSecret'], $otp);
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
                    $effects['recoveryCodes'] = $plainCodes;
                    $effects['deleteDeviceCookie'] = true;
                    $effects['issueSessionToken'] = true;
                    $changedSecret = true;
                } elseif ($wasEnabled && !$enable) {
                    $state = self::defaultUserConfig();
                    $state['SetupSecret'] = self::newSecret();
                    $effects['deleteDeviceCookie'] = true;
                    $effects['deleteSessionCookie'] = true;
                }

                if ($revokeDevices) {
                    $state = self::keepCurrentDeviceOnly($state, $deviceCookie, $passwordHash);
                }

                if ($regenerateRecovery && !$changedSecret) {
                    [$hashes, $plainCodes] = self::generateRecoveryCodes();
                    $state['RecoveryCodes'] = $hashes;
                    $effects['recoveryCodes'] = $plainCodes;
                }

                return [$state, $effects];
            }
        );

        /** 数据已提交后再改变浏览器状态，事务失败不会留下半生效的 Cookie。 */
        if ($effects['recoveryCodes']) {
            self::rememberRecoveryCodes($effects['recoveryCodes']);
        }
        if ($effects['deleteDeviceCookie']) {
            self::deleteCookie(self::DEVICE_COOKIE);
        }
        if ($effects['deleteSessionCookie']) {
            self::deleteCookie(self::SESSION_COOKIE);
        }
        if ($effects['issueSessionToken']) {
            self::issueSessionToken($uid, (string) $user->authCode, 0);
        }
    }

    /**
     * 在后台导航栏显示 2FA 状态
     * @throws PluginException
     */
    public static function authenticatorSafe(): void
    {
        $user = User::alloc();
        /** 导航栏只是状态展示，不参与放行判定，可以使用普通读连接。 */
        $enabled = $user->hasLogin() && self::userIsEnabled((int) $user->uid, false);

        /**
         * 这里只输出一个裸 span，用 Typecho 自带的 .message/.success/.error，
         * 一条样式覆盖都不要加——0.1.0 起就是这个写法。
         *
         * 曾经把它改成指向绑定面板的 <a>，结果连着踩了四个坑：后台有一条
         * `.typecho-head-nav a{padding:0 20px;height:36px;line-height:36px;color:#BBB}`
         * 对导航里的每个 a 生效，四个声明各坏一次（字被压成浅灰、左右多出深色内边距、
         * 行内背景盒错位露出下缘、行被撑高时不跟着长），要靠十来条内联样式才压得住。
         * 而绑定入口已经有三条路可走（控制台菜单里的「两步认证」、插件设置页顶部的指引、
         * 启用插件时的「去绑定」链接），不值得为此把全站样式最脆的一处放在这儿。
         *
         * 结论：这个元素保持无样式。要改成可点击之前，先想清楚上面那条规则。
         */
        if ($enabled) {
            echo '<span class="message success">' . htmlspecialchars(_t('2FA 已启用')) . '</span>';
        } else {
            echo '<span class="message error">' . htmlspecialchars(_t('当前账号未启用 2FA')) . '</span>';
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
        try {
            $enabled = self::userIsEnabled($uid);
        } catch (\Throwable $e) {
            /**
             * 非临时登录到达此钩子前，Typecho 已提交完整登录凭据。
             * 主库安全状态无法读取时，必须先撤销它，不能把异常当作未绑定放行。
             */
            if (!$temporarily) {
                self::revokeCommittedLogin($uid);
            }
            throw $e;
        }

        if (!$enabled) {
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
        $lockedUntil = self::createChallenge($uid, [
            'hash'     => self::challengeHash($token, $uid),
            'uid'      => $uid,
            'expire'   => $expire,
            'deadline' => time() + self::CHALLENGE_TTL,
            'tries'    => 0,
            'referer'  => self::safeReferer(\Typecho\Request::getInstance()->get('referer')),
            'flash'    => '',
        ]);
        if ($lockedUntil > time()) {
            self::deleteCookie(self::CHALLENGE_COOKIE);
            $minutes = max(1, (int) ceil(($lockedUntil - time()) / 60));
            throw new WidgetException(_t('两步验证失败次数过多，请 %d 分钟后重试', $minutes), 403);
        }
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
        $now = time();
        $id = bin2hex(random_bytes(8));
        $token = bin2hex(random_bytes(32));
        $deadline = $now + self::DEVICE_TTL;
        $saved = (bool) self::withUserConfigTransaction(
            $uid,
            static function (array $state) use ($id, $token, $passwordHash, $now, $deadline): array {
                if (1 !== (int) $state['SecretOn']) {
                    return [null, false];
                }

                $devices = self::validDevices($state['TrustedDevices']);
                $devices[] = [
                    'id'      => $id,
                    'hash'    => self::deviceHash($token, $passwordHash),
                    'created' => $now,
                    'expires' => $deadline,
                ];
                $state['TrustedDevices'] = array_slice($devices, -self::MAX_DEVICES);
                return [$state, true];
            }
        );
        if ($saved) {
            self::setCookie(self::DEVICE_COOKIE, $id . ':' . $token, $deadline);
        }
    }

    public static function verifyDeviceToken(?string $value, int $uid, string $passwordHash): bool
    {
        if (!is_string($value) || !preg_match('/^[0-9a-f]{16}:[0-9a-f]{64}$/D', $value) || $passwordHash === '') {
            return false;
        }

        [$id, $token] = explode(':', $value, 2);
        return (bool) self::withUserConfigTransaction(
            $uid,
            static function (array $state) use ($id, $token, $passwordHash): array {
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
                    return [$state, $valid];
                }

                return [null, $valid];
            }
        );
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

    /**
     * 从主库读全局策略配置，每个请求只读一次。
     *
     * 不能用 Helper::options()->plugin()：Options 组件是通过 READ 连接加载的，
     * 读写分离时那份数据可能落后，而这里的值要用来做放行判定。
     *
     * @return array
     * @throws DbException|PluginException
     */
    private static function primaryGlobalConfig(): array
    {
        if (is_array(self::$globalConfigCache)) {
            return self::$globalConfigCache;
        }

        $row = self::primaryOptionRow('plugin:GAuthenticator', 0);
        if (!$row) {
            /** 首次启用、尚未保存全局设置时使用安全默认值。 */
            return self::$globalConfigCache = [];
        }

        $config = json_decode((string) $row['value'], true);
        if (!is_array($config)) {
            throw new PluginException(_t('两步验证全局安全配置损坏，已拒绝认证'));
        }

        return self::$globalConfigCache = $config;
    }

    private static function xmlRpcAllowed(): bool
    {
        try {
            return 1 == (self::primaryGlobalConfig()['SecretXmlRpc'] ?? 0);
        } catch (\Throwable $e) {
            /** XML-RPC 无法反馈第二因素；读取失败或配置损坏时直接拒绝。 */
            return false;
        }
    }

    /** 容差倍率同样属于验证参数，必须来自主库。 */
    private static function tolerance(): int
    {
        return self::discrepancy(self::primaryGlobalConfig()['SecretTime'] ?? self::TOLERANCE_DEFAULT);
    }

    /**
     * $primary 同时决定「读哪条连接」和「缺行时补不补」。
     *
     * 两者必须一致：展示路径读的是可能落后的副本，如果还允许它补建行，
     * saveUserConfig 会拿默认值去覆盖主库上真实的 2FA 状态（密钥、恢复码、
     * 可信设备一起丢），等于静默关掉这个账号的两步验证。
     * 补建行本来也只需要发生在认证路径上。
     */
    public static function userIsEnabled(int $uid, bool $primary = true): bool
    {
        $state = self::userConfig($uid, $primary, $primary);
        return 1 === (int) $state['SecretOn'] && $state['SecretKey'] !== '';
    }

    /** 新注册用户预置关闭状态；后台新增用户则由读取时兜底。 */
    public static function onFinishRegister($registration): void
    {
        $uid = (int) $registration->uid;
        if ($uid > 0) {
            self::userConfig($uid, true, true);
        }
    }

    /**
     * @return array{SecretOn:int,SecretKey:string,SetupSecret:string,LastSlice:int,TrustedDevices:array,RecoveryCodes:array,Challenge:array,FailureCount:int,FailureWindowStarted:int,LockedUntil:int}
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
            'FailureCount'   => 0,
            'FailureWindowStarted' => 0,
            'LockedUntil'    => 0,
        ];
    }

    /**
     * 按 uid 读取个人配置。$primary 只用于认证关键路径，强制复用 Typecho 的写连接；
     * 主库查询失败会抛出异常，不能降级为「未绑定并放行」。
     *
     * @return array
     */
    public static function userConfig(int $uid, bool $create = true, bool $primary = false): array
    {
        self::migrateGlobalConfig();
        $defaults = self::defaultUserConfig();
        if ($uid <= 0) {
            return $defaults;
        }

        $db = Db::get();
        $row = $primary
            ? self::primaryOptionRow(self::PERSONAL_OPTION, $uid)
            : $db->fetchRow($db->select('value')->from('table.options')
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
            if ($primary) {
                throw new PluginException(_t('两步验证安全配置损坏，已拒绝登录'));
            }
            if ($create) {
                self::saveUserConfig($uid, $defaults);
            }
            return $defaults;
        }

        return self::normalizeUserConfig($decoded);
    }

    private static function normalizeUserConfig(array $state): array
    {
        $state = array_merge(self::defaultUserConfig(), $state);
        $state['SecretOn'] = 1 === (int) $state['SecretOn'] ? 1 : 0;
        $state['SecretKey'] = is_string($state['SecretKey']) ? $state['SecretKey'] : '';
        $state['SetupSecret'] = is_string($state['SetupSecret']) ? $state['SetupSecret'] : '';
        $state['LastSlice'] = (int) $state['LastSlice'];
        $state['TrustedDevices'] = is_array($state['TrustedDevices']) ? $state['TrustedDevices'] : [];
        $state['RecoveryCodes'] = is_array($state['RecoveryCodes']) ? array_values(array_filter($state['RecoveryCodes'], 'is_string')) : [];
        $state['Challenge'] = is_array($state['Challenge']) ? $state['Challenge'] : [];
        $state['FailureCount'] = max(0, (int) $state['FailureCount']);
        $state['FailureWindowStarted'] = max(0, (int) $state['FailureWindowStarted']);
        $state['LockedUntil'] = max(0, (int) $state['LockedUntil']);

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
        /** 写入前的存在性判断也必须看主库，避免副本延迟导致重复 INSERT。 */
        $exists = self::primaryOptionRow(self::PERSONAL_OPTION, $uid);

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

    /**
     * 在同一个写连接中锁住用户配置、更新并提交。
     *
     * 回调返回 [新状态或 null, 返回值]。即使底层是 MyISAM，value 条件更新也会作为
     * 乐观锁阻止覆盖并发写；SQLite 使用 BEGIN IMMEDIATE，其余数据库使用行锁。
     *
     * @return mixed
     * @throws DbException|PluginException
     */
    private static function withUserConfigTransaction(int $uid, callable $callback)
    {
        if ($uid <= 0) {
            throw new PluginException(_t('无效的用户配置'));
        }

        /** 先确保记录存在，事务中的 SELECT 才能锁到确定的一行。 */
        self::userConfig($uid, true, true);
        $db = Db::get();

        for ($attempt = 0; $attempt < 5; $attempt++) {
            self::beginTransaction($db);
            try {
                $row = self::lockedUserConfigRow($db, $uid);
                if (!$row) {
                    self::rollbackTransaction($db);
                    self::saveUserConfig($uid, self::defaultUserConfig());
                    continue;
                }

                $decoded = json_decode((string) $row['value'], true);
                $state = self::normalizeUserConfig(is_array($decoded) ? $decoded : []);
                [$newState, $result] = $callback($state);

                if (is_array($newState)) {
                    $value = json_encode(self::normalizeUserConfig($newState), JSON_UNESCAPED_SLASHES);
                    if (!is_string($value)) {
                        throw new PluginException(_t('无法保存两步验证配置'));
                    }

                    /**
                     * 值没变就不要发 UPDATE。
                     * Typecho 的 Pdo_Mysql 没有设 PDO::MYSQL_ATTR_FOUND_ROWS，
                     * 所以 MySQL 的 rowCount 返回「实际改变的行数」——写回相同内容会得到 0，
                     * 被这里的乐观锁误判成并发冲突，重试耗尽后抛异常(SQLite 返回 1，测不出来)。
                     */
                    if ($value !== (string) $row['value']) {
                        $updated = $db->query($db->update('table.options')->rows(['value' => $value])
                            ->where('name = ? AND user = ? AND value = ?', self::PERSONAL_OPTION, $uid, (string) $row['value']));
                        if (1 !== (int) $updated) {
                            self::rollbackTransaction($db);
                            continue;
                        }
                    }
                }

                self::commitTransaction($db);
                return $result;
            } catch (\Throwable $e) {
                self::rollbackTransaction($db);
                throw $e;
            }
        }

        throw new PluginException(_t('两步验证配置正在被并发修改，请重试'));
    }

    private static function beginTransaction(Db $db): void
    {
        $sql = 'sqlite' === $db->getAdapter()->getDriver() ? 'BEGIN IMMEDIATE' : 'START TRANSACTION';
        $db->query($sql, Db::WRITE, '');
    }

    private static function commitTransaction(Db $db): void
    {
        $db->query('COMMIT', Db::WRITE, '');
    }

    private static function rollbackTransaction(Db $db): void
    {
        try {
            $db->query('ROLLBACK', Db::WRITE, '');
        } catch (\Throwable $ignored) {
            // 保留触发回滚的原始异常。
        }
    }

    private static function lockedUserConfigRow(Db $db, int $uid): ?array
    {
        $adapter = $db->getAdapter();
        $table = $adapter->quoteColumn($db->getPrefix() . 'options');
        $sql = 'SELECT value FROM ' . $table
            . ' WHERE name = ' . $adapter->quoteValue(self::PERSONAL_OPTION)
            . ' AND user = ' . $uid;
        if ('sqlite' !== $adapter->getDriver()) {
            $sql .= ' FOR UPDATE';
        }

        return $adapter->fetch($db->query($sql, Db::WRITE));
    }

    /**
     * 通过 Typecho 已配置的 WRITE 连接读取 option；不会创建额外数据库连接。
     *
     * @throws DbException
     */
    private static function primaryOptionRow(string $name, int $uid): ?array
    {
        $db = Db::get();
        $adapter = $db->getAdapter();
        $table = $adapter->quoteColumn($db->getPrefix() . 'options');
        $sql = 'SELECT value FROM ' . $table
            . ' WHERE name = ' . $adapter->quoteValue($name)
            . ' AND user = ' . $uid
            . ' LIMIT 1';

        return $adapter->fetch($db->query($sql, Db::WRITE));
    }

    public static function provisionAllUsers(): void
    {
        $db = Db::get();
        $adapter = $db->getAdapter();
        $table = $adapter->quoteColumn($db->getPrefix() . 'users');
        $rows = $adapter->fetchAll($db->query('SELECT uid FROM ' . $table, Db::WRITE));

        foreach ($rows as $row) {
            /** 预置属于写操作，存在性判断和补建都必须以主库为准。 */
            self::userConfig((int) $row['uid'], true, true);
        }
    }

    /** 只保留新的全局策略配置，升级时直接废弃旧的全站共享密钥。 */
    private static function saveGlobalConfig(array $config): void
    {
        $db = Db::get();
        $value = json_encode($config, JSON_UNESCAPED_SLASHES);
        $exists = self::primaryOptionRow('plugin:GAuthenticator', 0);

        if ($exists) {
            $db->query($db->update('table.options')->rows(['value' => $value])
                ->where('name = ? AND user = 0', 'plugin:GAuthenticator'));
        } else {
            $db->query($db->insert('table.options')->rows([
                'name' => 'plugin:GAuthenticator', 'value' => $value, 'user' => 0,
            ]));
        }

        /** 本请求内再读到的必须是刚写进去的值 */
        self::$globalConfigCache = null;
    }

    /**
     * 第一次运行新版本时从数据库中实际移除旧的全站共享密钥，
     * 并把不在允许范围内的容差倍率就地收敛为推荐值。
     */
    private static function migrateGlobalConfig(): void
    {
        if (self::$globalMigrated) {
            return;
        }
        self::$globalMigrated = true;

        try {
            /**
             * 这里要往主库写，判断依据也必须来自主库。
             * 用 Options 组件(READ 连接)读到的可能是落后的副本，会拿旧值覆盖主库；
             * 而且 config() 为了不把旧密钥渲染进 HTML，会先把这些键从那份 Config 上摘掉，
             * 同一请求里再去读就什么都看不到了。
             */
            $values = self::primaryGlobalConfig();
            $legacyKeys = (bool) array_intersect(['SecretKey', 'SecretQRInfo', 'SecretCode', 'SecretOn'], array_keys($values));

            /**
             * 0.3.2 之前容差是 clamp(0,2)，所以库里可能留着 0（只认当前时间片，
             * 用户输码稍慢就会失败）或别的越界值。tolerance() 读的时候已经会收敛，
             * 这里再把库里那份也一并写正，免得设置页显示的和实际生效的长期对不上。
             */
            $needsToleranceFix = array_key_exists('SecretTime', $values)
                && (string) $values['SecretTime'] !== (string) self::discrepancy($values['SecretTime']);

            /**
             * 没有这一行(全新安装、还没保存过设置)时什么都不写。
             * 这个方法挂在 userConfig() 上、几乎每个请求都会经过，
             * 在读写分离下平白多一次主库写没有意义 —— tolerance() 读取时本来就会兜底到推荐值。
             */
            if (!$legacyKeys && !$needsToleranceFix) {
                return;
            }
            self::saveGlobalConfig([
                'SecretTime'   => (string) self::discrepancy($values['SecretTime'] ?? self::TOLERANCE_DEFAULT),
                'SecretXmlRpc' => 1 == ($values['SecretXmlRpc'] ?? 0) ? '1' : '0',
            ]);
        } catch (\Throwable $e) {
            /** 迁移只是清理历史遗留字段，失败不该阻断请求；认证路径自己会因读不到主库而拒绝。 */
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

    /**
     * 返回容差窗口内匹配的时间片。
     *
     * 这里只回答「这个码对不对」，不判断有没有用过 —— 是否重放交给 consumeTotp，
     * 这样才能把「码错了」和「码对但已经用过」区分开。
     */
    public static function matchTotpSlice(string $secret, string $otp): ?int
    {
        /**
         * 这个提前返回必须留在 tolerance() 之前，不要为了省事调换顺序。
         *
         * tolerance() 在全局配置行损坏时会抛异常，而恢复码不是六位数字，
         * 会在这里就被挡掉、走不到那一步 —— 这正是全局配置损坏时用户还能
         * 用恢复码登进后台、再从插件设置页把配置存回去的原因。
         * 一旦让 tolerance() 先执行，那条自救路径就会一起断掉，
         * 全站将只能靠数据库权限恢复。
         */
        if ($secret === '' || !preg_match('/^\d{6}$/D', $otp)) {
            return null;
        }

        require_once __DIR__ . '/GoogleAuthenticator.php';
        $authenticator = new \PHPGangsta_GoogleAuthenticator();
        $discrepancy = self::tolerance();

        $nowSlice = (int) floor(time() / 30);
        $matched = null;
        for ($i = -$discrepancy; $i <= $discrepancy; $i++) {
            $candidate = $nowSlice + $i;
            $equal = hash_equals((string) $authenticator->getCode($secret, $candidate), $otp);
            if ($equal) {
                $matched = $candidate;
            }
        }

        return $matched;
    }

    /**
     * 在行锁事务中检查并写回 LastSlice，保证同一时间片只能成功一次。
     *
     * 返回 TOTP_OK / TOTP_REUSED / TOTP_INVALID。区分出 REUSED 是有必要的：
     * 验证器 30 秒内一直显示同一个数字，用户刚绑定完(或刚登录过)马上再登，
     * 手上那个码必然已经被消费掉。若和「码错了」混为一谈，用户会看到莫名其妙的
     * 「令牌错误」并反复重试，5 次就把自己锁 10 分钟。
     */
    public static function consumeTotp(int $uid, string $otp): int
    {
        return (int) self::withUserConfigTransaction($uid, static function (array $state) use ($otp): array {
            if (1 !== (int) $state['SecretOn']) {
                return [null, self::TOTP_INVALID];
            }

            $slice = self::matchTotpSlice($state['SecretKey'], $otp);
            if ($slice === null) {
                return [null, self::TOTP_INVALID];
            }

            /** 码是对的，但这个时间片已经用过：拒绝登录，但这不是一次猜测。 */
            if ($slice <= (int) $state['LastSlice']) {
                return [null, self::TOTP_REUSED];
            }

            $state['LastSlice'] = $slice;
            return [$state, self::TOTP_OK];
        });
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

        return (bool) self::withUserConfigTransaction($uid, static function (array $state) use ($normalized): array {
            if (1 !== (int) $state['SecretOn']) {
                return [null, false];
            }

            foreach ($state['RecoveryCodes'] as $index => $hash) {
                if (password_verify($normalized, $hash)) {
                    unset($state['RecoveryCodes'][$index]);
                    $state['RecoveryCodes'] = array_values($state['RecoveryCodes']);
                    return [$state, true];
                }
            }

            return [null, false];
        });
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
     * 容差只接受 1、2、3，其余一律收敛为推荐值 1
     *
     * 这里刻意用白名单而不是 clamp。理由是失败模式：
     * clamp 会把打错的字（intval('abc') === 0）压成 0，也就是最严格的那一档，
     * 而 0 意味着只认当前这一个时间片 —— 用户看到码再输入完这几秒里一旦跨过
     * 30 秒边界就会失败，实测「读码后 5 秒提交」的失败率是 5/30；服务器和手机
     * 差满 30 秒则是 100% 登不进去，连绑定都做不了。这种间歇性故障没人查得出来。
     * 白名单让所有非法输入落到 1（RFC 6238 建议的一个步长），失败模式从
     * 「悄悄变成最脆的配置」变成「悄悄回到推荐配置」。
     *
     * 上限 3 是为极端场景（长期不校时的服务器）保留的，不推荐：
     * 每宽一片，盲猜命中率就从 (2d+1)/10^6 线性上升，验证码被截获后的可用时间
     * 也按 (d+1)*30 秒线性变长。
     *
     * @param mixed $value
     * @return int
     */
    public static function discrepancy($value): int
    {
        $value = intval($value);

        return in_array($value, self::TOLERANCE_CHOICES, true) ? $value : self::TOLERANCE_DEFAULT;
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
        $parts = self::challengeCookieParts();
        if ($parts === null) {
            return null;
        }

        [$uid, $token] = $parts;
        /** 挑战属于认证状态，必须从主库读取，不能接受副本上的旧挑战。 */
        $state = self::userConfig($uid, false, true);
        $challenge = self::challengeFromState($state, $uid, $token);
        if ($challenge === null) {
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
     * 每次 POST 先在事务中增加尝试次数，不能用旧 Cookie 回滚计数。
     *
     * @return array|null
     */
    public static function recordChallengeAttempt(): ?array
    {
        $parts = self::challengeCookieParts();
        if ($parts === null) {
            return null;
        }

        [$uid, $token] = $parts;
        return self::withUserConfigTransaction($uid, static function (array $state) use ($uid, $token): array {
            $challenge = self::challengeFromState($state, $uid, $token);
            if ($challenge === null || (int) ($challenge['deadline'] ?? 0) < time()) {
                return [null, null];
            }

            if ((int) $state['LockedUntil'] > time()) {
                $challenge['_locked_until'] = (int) $state['LockedUntil'];
                return [null, $challenge];
            }

            $challenge['tries'] = (int) ($challenge['tries'] ?? 0) + 1;
            $state['Challenge'] = $challenge;
            return [$state, $challenge];
        });
    }

    /** 记录一次失败；计数不会因为重新输入正确密码并创建新挑战而重置。 */
    public static function recordSecondFactorFailure(int $uid): int
    {
        return (int) self::withUserConfigTransaction($uid, static function (array $state): array {
            $now = time();
            $windowStarted = (int) $state['FailureWindowStarted'];
            if ($windowStarted <= 0 || $windowStarted + self::FAILURE_WINDOW <= $now) {
                $state['FailureCount'] = 0;
                $state['FailureWindowStarted'] = $now;
                $state['LockedUntil'] = 0;
            }

            $state['FailureCount'] = (int) $state['FailureCount'] + 1;
            if ($state['FailureCount'] >= self::MAX_FAILURES) {
                $state['LockedUntil'] = $now + self::LOCK_TTL;
            }

            return [$state, (int) $state['LockedUntil']];
        });
    }

    /**
     * 挑战一次性：成功、超时、次数用尽都要立刻作废
     */
    public static function clearChallenge(int $uid = 0, bool $resetFailures = false): bool
    {
        $parts = self::challengeCookieParts();
        if ($parts === null || ($uid > 0 && $uid !== $parts[0])) {
            self::deleteCookie(self::CHALLENGE_COOKIE);
            return false;
        }

        [$cookieUid, $token] = $parts;
        $cleared = (bool) self::withUserConfigTransaction(
            $cookieUid,
            static function (array $state) use ($cookieUid, $token, $resetFailures): array {
                if (self::challengeFromState($state, $cookieUid, $token) === null) {
                    return [null, false];
                }

                $state['Challenge'] = [];
                if ($resetFailures) {
                    $state['FailureCount'] = 0;
                    $state['FailureWindowStarted'] = 0;
                    $state['LockedUntil'] = 0;
                }
                return [$state, true];
            }
        );
        self::deleteCookie(self::CHALLENGE_COOKIE);
        return $cleared;
    }

    private static function createChallenge(int $uid, array $challenge): int
    {
        return (int) self::withUserConfigTransaction($uid, static function (array $state) use ($challenge): array {
            $now = time();
            if ((int) $state['LockedUntil'] > $now) {
                return [null, (int) $state['LockedUntil']];
            }

            if ((int) $state['FailureWindowStarted'] + self::FAILURE_WINDOW <= $now) {
                $state['FailureCount'] = 0;
                $state['FailureWindowStarted'] = 0;
                $state['LockedUntil'] = 0;
            }
            $state['Challenge'] = $challenge;
            return [$state, 0];
        });
    }

    private static function challengeCookieParts(): ?array
    {
        $cookie = Cookie::get(self::CHALLENGE_COOKIE);
        if (!is_string($cookie) || !preg_match('/^([1-9][0-9]*):([0-9a-f]{64})$/D', $cookie, $parts)) {
            return null;
        }

        return [(int) $parts[1], $parts[2]];
    }

    private static function challengeFromState(array $state, int $uid, string $token): ?array
    {
        $challenge = $state['Challenge'] ?? null;
        if (!is_array($challenge)
            || (int) ($challenge['uid'] ?? 0) !== $uid
            || !isset($challenge['hash'])
            || !hash_equals((string) $challenge['hash'], self::challengeHash($token, $uid))) {
            return null;
        }

        return $challenge;
    }

    private static function updateChallengeFlash(string $message, bool $take)
    {
        $parts = self::challengeCookieParts();
        if ($parts === null) {
            return $take ? '' : null;
        }

        [$uid, $token] = $parts;
        return self::withUserConfigTransaction($uid, static function (array $state) use ($uid, $token, $message, $take): array {
            $challenge = self::challengeFromState($state, $uid, $token);
            if ($challenge === null || (int) ($challenge['deadline'] ?? 0) < time()) {
                return [null, $take ? '' : null];
            }

            $old = (string) ($challenge['flash'] ?? '');
            if (($take && $old === '') || (!$take && hash_equals($old, $message))) {
                return [null, $take ? $old : null];
            }
            $challenge['flash'] = $take ? '' : $message;
            $state['Challenge'] = $challenge;
            return [$state, $take ? $old : null];
        });
    }

    /**
     * 一次性提示信息
     *
     * @param string $message
     */
    public static function setFlash(string $message): void
    {
        self::updateChallengeFlash($message, false);
    }

    /**
     * @return string
     */
    public static function takeFlash(): string
    {
        return (string) self::updateChallengeFlash('', true);
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
