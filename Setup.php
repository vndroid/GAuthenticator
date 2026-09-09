<?php

namespace TypechoPlugin\GAuthenticator;

use Typecho\Db\Exception as DbException;
use Typecho\Plugin\Exception as PluginException;
use Typecho\Widget;
use Widget\ActionInterface;
use Widget\Notice;
use Widget\Security;
use Widget\User;

if (!defined('__TYPECHO_ROOT_DIR__')) {
    exit;
}

/**
 * 「控制台 → 两步认证」面板的保存入口
 *
 * 0.3.3 之前绑定表单挂在 Typecho 的个人设置页上，由核心的
 * Widget\Users\Profile::updatePersonal() 保存。那条路径有两个问题：
 * 保存完固定跳回 profile.php（面板搬走后就跳丢了），而且绑定失败时
 * PluginException 会直接冒成一个异常页。所以这里自己收这个 POST。
 *
 * @package GAuthenticator
 */
class Setup extends Widget implements ActionInterface
{
    /** 表单提交的字段，只认这几个 */
    private const FIELDS = ['SecretCode', 'SecretOn', 'RotateSecret', 'RevokeDevices', 'RegenerateRecovery'];

    /**
     * 入口函数
     *
     * @throws PluginException|DbException
     */
    public function action(): void
    {
        /**
         * 这个路由不经过 admin/common.php，登录与来源都要自己确认。
         * Typecho\Widget 只提供 $request/$response，user 和 security 得自己取。
         */
        $user = User::alloc();
        $user->pass('subscriber');
        Security::alloc()->protect();

        if (!$this->request->isPost()) {
            $this->response->redirect(Plugin::panelUrl());
        }

        /**
         * 这里刻意不重建表单来取值。setupForm() 会消费「新恢复码只显示一次」
         * 的一次性 Cookie，在 POST 上再调一次就会把用户还没看到的那组恢复码吃掉。
         */
        $settings = [];
        foreach (self::FIELDS as $field) {
            $settings[$field] = (string) $this->request->get($field, '');
        }

        try {
            Plugin::handleSetup($settings);
        } catch (PluginException $e) {
            /** 验证码不对之类的可预期失败，回到面板上给一句话，不要抛异常页 */
            Notice::alloc()->set($e->getMessage(), 'error');
            $this->response->redirect(Plugin::panelUrl());
        }

        Notice::alloc()->set(
            Plugin::userIsEnabled((int) $user->uid, true)
                ? _t('两步验证设置已保存')
                : _t('两步验证已关闭'),
            'success'
        );
        $this->response->redirect(Plugin::panelUrl());
    }
}
