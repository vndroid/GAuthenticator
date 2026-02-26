<?php

namespace TypechoPlugin\GAuthenticator;

use Typecho\Cookie;
use Typecho\Plugin\Exception;
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
 * @package GAuthenticator
 */
class Action extends Widget implements ActionInterface
{
    /**
     * OTP ajax/json 响应助手
     *
     * @param bool   $ok
     * @param string $message
     * @param string $redirect
     */
    private function jsonResult(bool $ok, string $message = '', string $redirect = ''): void
    {
        header('Content-Type: application/json; charset=UTF-8');
        echo json_encode([
            'ok'       => $ok,
            'message'  => $message,
            'redirect' => $redirect,
        ]);
    }

    /**
     * 验证 OTP 令牌
     * @throws Exception
     */
    public function auth(): void
    {
        $otp = $this->request->get('otp');
        $isAjax = (
            $this->request->isAjax()
            || 'XMLHttpRequest' === (string) $this->request->getHeader('X-Requested-With')
        );

        if (intval($otp) <= 0) {
            if ($isAjax) {
                $this->jsonResult(false, _t('请输入令牌'));
            }
            return;
        }

        // 已经通过验证
        if (isset($_SESSION['GAuthenticator']) && $_SESSION['GAuthenticator']) {
            if ($isAjax) {
                $this->jsonResult(true);
            }
            return;
        }

        $config = Helper::options()->plugin('GAuthenticator');
        require_once __DIR__ . '/GoogleAuthenticator.php';

        // 计算回跳地址
        $referer = trim((string) $this->request->get('referer'));
        if ($referer === '') {
            $referer = (string) $this->request->getReferer();
        }

        $options = Helper::options();
        if (
            empty($referer)
            || str_contains($referer, '/GAuthenticator')
            || !(
                str_starts_with($referer, $options->adminUrl)
                || str_starts_with($referer, $options->siteUrl)
            )
        ) {
            $referer = $options->adminUrl;
        }

        $authenticator = new \PHPGangsta_GoogleAuthenticator();
        if ($authenticator->verifyCode($config->SecretKey, intval($otp), $config->SecretTime)) {
            $expire = 1 == $this->request->get('remember')
                ? $options->time + $options->timezone + 30 * 24 * 3600
                : 0;

            $_SESSION['GAuthenticator'] = true;
            Cookie::set(
                '__typecho_GAuthenticator',
                md5($config->SecretKey . Cookie::getPrefix() . User::alloc()->uid),
                $expire
            );

            if ($isAjax) {
                $this->jsonResult(true, _t('验证成功'), $referer);
                return;
            }
        } else {
            if ($isAjax) {
                $this->jsonResult(false, _t('令牌错误'));
                return;
            }
            Notice::alloc()->set(_t('令牌错误'), 'error');
        }

        $this->response->redirect($referer);
    }

    /**
     * 入口函数
     * @throws Exception
     */
    public function action(): void
    {
        $this->on($this->request->is('otp'))->auth();
    }
}
