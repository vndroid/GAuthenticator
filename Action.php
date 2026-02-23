<?php
/**
 * GAuthenticator Plugin
 *
 * @copyright  Copyright (c) 2018 WeiCN (https://cuojue.org)
 * @license	GNU General Public License 2.0
 * 
 */
class GAuthenticator_Action extends Typecho_Widget implements Widget_Interface_Do
{

	public function __construct($request, $response, $params = NULL)
	{
		parent::__construct($request, $response, $params);
	}
	/**
	 * OTP ajax/json response helper
	 * @param bool $ok
	 * @param string $message
	 * @param string $redirect
	 */
	private function jsonResult($ok, $message = '', $redirect = '')
	{
		// try our best to return JSON without depending on Typecho namespaces
		header('Content-Type: application/json; charset=UTF-8');
		echo json_encode([
			'ok' => (bool)$ok,
			'message' => (string)$message,
			'redirect' => (string)$redirect
		]);
	}

	/**
	 * 验证GAuthenticator POST
	 * 
	 */
	public function auth(){
		$otp = $this->request->get('otp');
		$isAjax = (
			$this->request->isAjax()
			|| 'XMLHttpRequest' === (string)$this->request->getHeader('X-Requested-With')
		);

		if (intval($otp) <= 0) {
			if ($isAjax) {
				$this->jsonResult(false, _t('请输入令牌'), '');
			}
			return;
		}

		//获取到CODE
		if (isset($_SESSION['GAuthenticator']) && $_SESSION['GAuthenticator']) {
			if ($isAjax) {
				$this->jsonResult(true, '', '');
			}
			return;
		}

		$config = Helper::options()->plugin('GAuthenticator');
		require_once 'GoogleAuthenticator.php';

		// Typecho 1.3.0 core login uses a POSTed `referer` field and validates redirect urls.
		$referer = trim((string)$this->request->get('referer'));
		if ($referer === '') {
			$referer = (string)$this->request->getReferer();
		}

		$options = Helper::options();
		if (
			empty($referer)
			|| false !== strpos($referer, '/GAuthenticator')
			|| !(
				0 === strpos($referer, $options->adminUrl)
				|| 0 === strpos($referer, $options->siteUrl)
			)
		) {
			$referer = $options->adminUrl;
		}

		$Authenticator = new PHPGangsta_GoogleAuthenticator();//初始化生成类
		$oneCode = intval($otp);//手机端生成的一次性代码
		if($Authenticator->verifyCode($config->SecretKey, $oneCode, $config->SecretTime)){
			$expire = 1 == $this->request->get('remember') ? Helper::options()->time + Helper::options()->timezone + 30*24*3600 : 0;
			$_SESSION['GAuthenticator'] = true;//session保存
			Typecho_Cookie::set('__typecho_GAuthenticator', md5($config->SecretKey.Typecho_Cookie::getPrefix().Typecho_Widget::widget('Widget_User')->uid), $expire);//cookie保存

			if ($isAjax) {
				$this->jsonResult(true, _t('验证成功'), $referer);
				return;
			}
		} else {
			if ($isAjax) {
				$this->jsonResult(false, _t('令牌错误'), '');
				return;
			}
			// non-ajax: show popup message via notice cookie
			Typecho_Widget::widget('Widget_Notice')->set(_t('令牌错误'), 'error');
		}

		$this->response->redirect($referer);
	}

	public function action(){
		$this->widget('Widget_User')->pass('administrator');
		$this->on($this->request->is('otp'))->auth();
	}
}
