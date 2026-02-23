# GAuthenticator

一个 Typecho 二次认证插件

## 本版特点

感谢原作者 [@WeiCN](https://github.com/naicfeng) ，修复了 Typecho 新版本的兼容性问题。

相对于旧版，新版的验证逻辑**全部更新**，推荐升级！

- 支持验证态保持，成功登录后，在 session 或 cookie 有效期内无需再次验证；
- 采用插件内注册的 Route 来处理 OTP，无需等待 TP 返回的 2s 后验证；

请注意：从 0.0.1 升级到 0.0.2+ 版本需要**卸载重新安装**！

兼容所有符合 [**RFC 6238**](https://tools.ietf.org/html/rfc6238 "rfc6238") 规范的 AuthOTP 软件。

- Microsoft Authenticator
- Google Authenticator
- 1Password
- Authy
- KeePass
- LastPass
- ...

## 更新说明

### 0.0.9
- [change] 使用 `ajax` 方式内部沟通

### 0.0.8
- [fix] 修复 1.3 版本兼容问题（输错后跳转空白页）

### 0.0.7
- [fix] 修复 1.2 版本报错问题

### 0.0.6
- [change] 使用 `jquery-qrcode` 插件在浏览器端生成二维码(不再使用外站的API来生成二维码,保证Key的安全性).

### 0.0.5
- [fix] 修复启用插件500错误，改为使用jQuery获取SecretKey显示二维码

### 0.0.4
- [add] 支持后台直接显示二维码
- [fix] 修改为使用联图API显示二维码
- [fix] 修复博客名称为中文时扫描二维码提示错误
- [fix] 修复卸载的时候没有删除路由
- [fix] 登录成功后主动访问路由地址会显示一条msg 验证失败

### 0.0.3
- [add] 更新支持记住本机

### 0.0.2
- [add] 支持typecho最新版
- [feature] 流程优化，符合大多数网站逻辑
