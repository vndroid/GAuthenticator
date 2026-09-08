<?php

namespace TypechoPlugin\GAuthenticator;

use Typecho\Db\Exception as DbException;
use Typecho\Plugin\Exception as PluginException;
use Typecho\Widget;
use Utils\Helper;
use Widget\ActionInterface;
use Widget\User;

if (!defined('__TYPECHO_ROOT_DIR__')) {
    exit;
}

/**
 * GAuthenticator OTP 验证 Action
 *
 * 这个路由只服务「密码已通过、等待第二因素」的挑战：
 * 没有挑战就没有任何可验证的东西，接口直接把人送回登录页。
 *
 * @package GAuthenticator
 */
class Action extends Widget implements ActionInterface
{
    /**
     * 入口函数
     *
     * @throws PluginException|DbException
     */
    public function action(): void
    {
        $this->response
            ->setHeader('Cache-Control', 'no-store, no-cache, must-revalidate')
            ->setHeader('Referrer-Policy', 'same-origin')
            ->setHeader('X-Robots-Tag', 'noindex, nofollow');

        if (!Plugin::isEnabled()) {
            $this->response->redirect(Helper::options()->siteUrl);
        }

        $challenge = Plugin::getChallenge();

        if (empty($challenge)) {
            $this->finish(false, _t('验证会话已失效, 请重新登录'), Helper::options()->loginUrl);
        }

        if ($this->request->isPost()) {
            $this->verify($challenge);
        }

        $this->render($challenge);
    }

    /**
     * 校验令牌
     *
     * @param array $challenge
     * @throws PluginException|DbException
     */
    private function verify(array $challenge): void
    {
        /** 先记账再校验，保证「猜一次就算一次」 */
        $challenge['tries'] = intval($challenge['tries'] ?? 0) + 1;

        if ($challenge['tries'] > Plugin::MAX_ATTEMPTS) {
            Plugin::clearChallenge();
            $this->finish(false, _t('尝试次数过多, 请重新登录'), Helper::options()->loginUrl);
        }

        Plugin::saveChallenge($challenge);

        $otp = (string) $this->request->get('otp');

        /** 统一的失败回执，不区分「格式不对」和「码不对」 */
        if (!preg_match('/^\d{6}$/D', $otp) || !$this->verifyOtp($otp)) {
            $this->finish(false, _t('令牌错误'));
        }

        $uid = intval($challenge['uid']);
        $expire = intval($challenge['expire'] ?? 0);
        $referer = Plugin::safeReferer($challenge['referer'] ?? '');

        /** 挑战一次性 */
        Plugin::clearChallenge();
        session_regenerate_id(true);

        $user = User::alloc();
        if (!$user->simpleLogin($uid, false, $expire)) {
            $this->finish(false, _t('验证会话已失效, 请重新登录'), Helper::options()->loginUrl);
        }

        /** 到这一步才真正签发 Typecho 登录凭据 */
        Plugin::issueSessionToken($uid, (string) $user->authCode, $expire);

        if (1 == $this->request->get('remember')) {
            $deadline = time() + Plugin::DEVICE_TTL;
            Plugin::setCookie(
                Plugin::DEVICE_COOKIE,
                Plugin::deviceToken($uid, (string) $user->password, $deadline),
                $deadline
            );
        }

        $this->finish(true, _t('验证成功'), $referer);
    }

    /**
     * 恒定轮次地比对整个容差窗口，比对本身用 hash_equals
     *
     * @param string $otp
     * @return bool
     * @throws PluginException
     */
    private function verifyOtp(string $otp): bool
    {
        require_once __DIR__ . '/GoogleAuthenticator.php';

        $config = Plugin::pluginConfig();
        $authenticator = new \PHPGangsta_GoogleAuthenticator();

        $discrepancy = Plugin::discrepancy($config->SecretTime);
        $slice = floor(time() / 30);
        $matched = false;

        for ($i = -$discrepancy; $i <= $discrepancy; $i++) {
            if (hash_equals((string) $authenticator->getCode($config->SecretKey, $slice + $i), $otp)) {
                $matched = true;
            }
        }

        return $matched;
    }

    /**
     * 输出结果并结束请求
     *
     * @param bool $ok
     * @param string $message
     * @param string $redirect
     */
    private function finish(bool $ok, string $message = '', string $redirect = ''): void
    {
        $isAjax = $this->request->isAjax()
            || 'XMLHttpRequest' === (string) $this->request->getHeader('X-Requested-With');

        if ($isAjax) {
            $this->response->throwJson([
                'ok'       => $ok,
                'message'  => $message,
                'redirect' => $redirect,
            ]);
        }

        if ($redirect !== '') {
            $this->response->redirect($redirect);
        }

        /** 无 JS 的普通表单：把提示放进 session 闪存，回到 OTP 页面再显示 */
        Plugin::setFlash($message);
        $this->response->redirect(Plugin::otpUrl());
    }

    /**
     * 渲染 OTP 页面
     *
     * 这个页面在「未登录」状态下渲染，所以不能复用 admin/header.php 那一套
     * （它依赖 __TYPECHO_ADMIN__ 和已经初始化好的 Menu 组件）。
     *
     * @param array $challenge
     * @throws PluginException
     */
    private function render(array $challenge): void
    {
        $options = Helper::options();
        $error = Plugin::takeFlash();
        $formAction = Plugin::otpUrl();
        $remaining = max(0, Plugin::MAX_ATTEMPTS - intval($challenge['tries'] ?? 0));

        require __DIR__ . '/verification.php';
        exit;
    }
}
