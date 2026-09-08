# GAuthenticator

二次认证插件 for Typecho

## 插件亮点

感谢原作者 [@WeiCN](https://github.com/naicfeng) ，在此基础上修复 Typecho 新版本的兼容性问题。

相对于旧版，新版的验证逻辑**全部更新**，推荐升级！

- **真正的两步**：密码通过后不会立刻签发 Typecho 登录凭据，先进入一次性挑战，OTP 通过才登录；
- 2FA 开启期间拒绝 XML-RPC 密码认证（pingback 不受影响），可在设置里显式放行；
- 支持验证态保持，成功登录后，在 cookie 有效期内无需再次验证；
- 采用插件内注册的 Route 来处理 OTP，无需等待 TP 返回的 2s 后验证；

请注意：

- 从 **0.0.1** 升级到 **0.0.2**+ 版本需要**卸载重新安装**！
- 从 **0.1.x** 升级到 **0.2.0** 后，必须在后台把插件**禁用再启用**一次，新增的登录钩子才会注册（不重新启用的话，2FA 仍然只能拦住后台页面）。重新启用会重新生成密钥，需要重新扫码绑定。
- 升级后所有已有的登录态都会被要求重新登录，这是预期行为。

兼容所有符合 [**RFC 6238**](https://tools.ietf.org/html/rfc6238 "rfc6238") 规范的 AuthOTP 软件。

- Microsoft Authenticator
- Google Authenticator
- 1Password
- Authy
- KeePass
- LastPass
- ...

## 更新说明

### 0.2.0
- [security] 重构登录状态机：密码校验通过后立即作废 Typecho 刚签发的凭据，改为建立 5 分钟、最多 5 次的一次性挑战，OTP 通过后才真正 `commitLogin`
- [security] 2FA 开启时拒绝 XML-RPC / MetaWeblog 的密码认证（新增开关，默认拒绝）；pingback 不受影响
- [security] OTP 接口必须先有挑战才能访问，去掉了原来无需登录、无限速的公开校验入口
- [security] 「记住本机」改为带到期时间的 HMAC，并绑定当前密码散列（改密码即吊销全部可信设备），不再是可离线伪造的 md5 拼接
- [security] 后台拦截不再用 pathInfo 子串白名单（此前 `/admin/preview.php/GAuthenticator` 之类可绕过）
- [security] 开启 2FA 时用**已存储**的密钥校验验证码，不再用表单提交上来的密钥
- [security] 令牌比对改用 `hash_equals` 且恒定轮次，容差限制在 0-2；OTP 成功后轮换会话 ID
- [security] 插件自身 cookie 增加 `SameSite=Lax`，并按当前连接决定 `Secure`
- [change] OTP 页面改为独立渲染，不再依赖 `admin/header.php`（此前会产生 `$menu` 未定义告警），无 JS 也可用

### 0.1.1
- [change] 优化插件提示，将 cookie 配置 httpOnly 属性（阻止 JavaScript 读取该 cookie，并不等于「防止 XSS」）

### 0.1.0
- [refactor] 重构插件，全面替换为新版 Hook 方法，只兼容 PHP 8.0+ 及 Typecho 1.2+，不再兼容旧版本

### 0.0.9
- [change] 改为使用 `ajax` 方式提交表单

### 0.0.8
- [fix] 修复 1.3 版本兼容问题（输错后跳转空白页）

### 0.0.7
- [fix] 修复 1.2 版本报错问题

### 0.0.6
- [change] 使用 `jquery-qrcode` 插件在浏览器端生成二维码（不依赖外站生成二维码，提高安全性）

### 0.0.5
- [fix] 修复启用插件 500 错误，改为使用 jQuery 获取 SecretKey 显示二维码

### 0.0.4
- [add] 支持后台直接显示二维码
- [fix] 修改为使用联图API显示二维码
- [fix] 修复博客名称为中文时扫描二维码提示错误
- [fix] 修复卸载的时候没有删除路由
- [fix] 登录成功后主动访问路由地址会显示一条msg 验证失败

### 0.0.3
- [add] 更新支持记住本机

### 0.0.2
- [add] 支持 Typecho 1.0 正式版
- [feature] 流程优化，符合大多数网站逻辑