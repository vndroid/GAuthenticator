<?php

namespace TypechoPlugin\GAuthenticator;

use Typecho\Db\Exception as DbException;
use Typecho\Plugin\Exception as PluginException;
use Typecho\Widget;
use Utils\Helper;
use Widget\ActionInterface;
use Widget\Notice;
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
        $challenge = Plugin::recordChallengeAttempt();
        if ($challenge === null) {
            $this->finish(false, _t('验证会话已失效, 请重新登录'), Helper::options()->loginUrl);
        }

        if ($challenge['tries'] > Plugin::MAX_ATTEMPTS) {
            Plugin::clearChallenge((int) $challenge['uid']);
            $this->finish(false, _t('尝试次数过多, 请重新登录'), Helper::options()->loginUrl);
        }

        $code = trim((string) $this->request->get('code'));
        $uid = intval($challenge['uid']);

        /** OTP 和恢复码共用统一回执，不泄露使用的是哪种凭据。 */
        $validTotp = Plugin::consumeTotp($uid, $code);
        $usedRecoveryCode = false;
        if (!$validTotp) {
            $usedRecoveryCode = Plugin::consumeRecoveryCode($uid, $code);
        }
        if (!$validTotp && !$usedRecoveryCode) {
            $this->finish(false, _t('令牌错误'));
        }

        $expire = intval($challenge['expire'] ?? 0);
        $referer = Plugin::safeReferer($challenge['referer'] ?? '');

        /** 挑战一次性 */
        if (!Plugin::clearChallenge($uid)) {
            $this->finish(false, _t('验证会话已失效, 请重新登录'), Helper::options()->loginUrl);
        }

        $user = User::alloc();
        if (!$user->simpleLogin($uid, false, $expire)) {
            $this->finish(false, _t('验证会话已失效, 请重新登录'), Helper::options()->loginUrl);
        }

        /** 到这一步才真正签发 Typecho 登录凭据 */
        Plugin::issueSessionToken($uid, (string) $user->authCode, $expire);

        if (1 == $this->request->get('remember')) {
            Plugin::issueDeviceToken($uid, (string) $user->password);
        }

        if ($usedRecoveryCode) {
            $remaining = count(Plugin::userConfig($uid, false)['RecoveryCodes']);
            Notice::alloc()->set(_t('已使用一个恢复码，剩余 %d 个；请尽快检查或轮换两步验证密钥', $remaining), 'notice');
        }

        $this->finish(true, _t('验证成功'), $referer);
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

        /** 无 JS 的普通表单：把提示放进服务端挑战状态，回到 OTP 页面再显示 */
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
