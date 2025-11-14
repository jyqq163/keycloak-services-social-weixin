# keycloak-services-social-weixin

To install the social weixin one has to:

* Add the jar to the Keycloak server:
  * `$ cp target/keycloak-services-social-weixin-*.jar _KEYCLOAK_HOME_/providers/`

  
* 20251114
1 升级至keycloak-26.4.4版本
2 新增WeiXin OAuth2属于可自定义设置url.
3 原有WeiXin降级处理只支持扫描登录,不支持微信浏览器授权登录等方式,如有需求请使用新增的WeiXin OAuth2
