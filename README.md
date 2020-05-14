# keycloak-services-social-weixin

> Wechat Login for Keycloak

## Live Example

- [Login In to UniSSO](https://keycloak.jiwai.win/auth/realms/UniHeart/protocol/openid-connect/auth?response_type=code&redirect_uri=http%3A%2F%2Fsso.jiwai.win%2Fkeycloak%2Flogin&client_id=UniHeart-Client-Local-3000)

## How to use it

To install the social weixin one has to:

* Add the jar to the Keycloak server:
  * `cp target/keycloak-services-social-weixin-*.jar _KEYCLOAK_HOME_/providers/`

* Add three templates to the Keycloak server:
  * `cp templates/realm-identity-provider-weixin.html _KEYCLOAK_HOME_/themes/base/admin/resources/partials`
  * `cp templates/realm-identity-provider-weixin-ext.html _KEYCLOAK_HOME_/themes/base/admin/resources/partials`
  
## How to build

```shell script
mvn install
```

## Release Notes

* 20180730

1 增加自适应微信登录功能。

2 账号关联默认使用微信unionid，如unionid不存在则使用openId

3 pc和wechat使用同一套账号则必须绑定同一个开放平台，否则会绑定不同账号

4 wechat信息非必填,默认使用pc方式登录

* 20200514

1 增加 customizedLoginUrlForPc 功能。