# keycloak-services-social-weixin

[English](README_en-US.md)

> Wechat Login for Keycloak

![Java CI with Maven](https://github.com/Jeff-Tian/keycloak-services-social-weixin/workflows/Java%20CI%20with%20Maven/badge.svg)
![Maven Package](https://github.com/Jeff-Tian/keycloak-services-social-weixin/workflows/Maven%20Package/badge.svg)

## Live Example

- [Login In to UniSSO](https://keycloak.jiwai.win/auth/realms/UniHeart/protocol/openid-connect/auth?response_type=code&redirect_uri=http%3A%2F%2Fsso.jiwai.win%2Fkeycloak%2Flogin&client_id=UniHeart-Client-Local-3000)

## How to use it

To install the social weixin one has to:

* Add the jar to the Keycloak server:
    * `cp target/keycloak-services-social-weixin-*.jar _KEYCLOAK_HOME_/providers/`

* Add three templates to the Keycloak server:
    * `cp templates/realm-identity-provider-weixin.html _KEYCLOAK_HOME_/themes/base/admin/resources/partials`
    * `cp templates/realm-identity-provider-weixin-ext.html _KEYCLOAK_HOME_/themes/base/admin/resources/partials`

## 本地开发

```shell script
mvn install
```

## 跑测试

```shell script
mvn clean test
```

## Maven 包

- 支持 jboss/keycloak 16，你可以使用我打的包：https://github.com/Jeff-Tian/keycloak-services-social-weixin/packages/225091
- 支持 quay.io/keycloak 18.0.2 的代码版本：https://github.com/Jeff-Tian/keycloak-services-social-weixin/tree/8069d7b32cb225742d7566d61e7ca0d0e0e389a5
- 支持 quay.io/keycloak 21.1 的版本：https://github.com/Jeff-Tian/keycloak-services-social-weixin/tree/dev-keycloak-21
- 支持 quay.io/keycloak 22 的版本： https://github.com/Jeff-Tian/keycloak-services-social-weixin/tree/dev-keycloak-22

## 打包

```shell
mvn package
ls target
```

## 使用截图

![image](https://user-images.githubusercontent.com/3367820/82117152-fdfd0300-97a0-11ea-8e10-02c9d9838a0a.png)

## Docker 镜像

我也打包了一个包含[微信 idp 的 keycloak server docker 镜像](https://hub.docker.com/repository/docker/jefftian/keycloak-heroku)：

```shell script
docker pull jefftian/keycloak-heroku:latest
```

## 一键部署

点击这个按钮，可以部署一个包含微信登录的Keycloak到你自己的 Heroku：
[![Deploy to Heroku](https://www.herokucdn.com/deploy/button.svg)](https://dashboard.heroku.com/new?button-url=https%3A%2F%2Fgithub.com%2FJeff-Tian%2Fkeycloak-heroku&template=https%3A%2F%2Fgithub.com%2FJeff-Tian%2Fkeycloak-heroku)

## Release Notes

* 2022090

1 适配 quay.io/keycloak 18.0.2

* 20180730

1 增加自适应微信登录功能。

2 账号关联默认使用微信unionid，如unionid不存在则使用openId

3 pc和wechat使用同一套账号则必须绑定同一个开放平台，否则会绑定不同账号

4 wechat信息非必填,默认使用pc方式登录

* 20200514

1 增加 customizedLoginUrlForPc 功能。

* 20230820

1 适配 quay.io/keycloak 21.1 的版本（由于 21 既不支持老的配置页，又没有新的方式增加自定义配置页，所以只能通过导入老的 Keycloak 版本中的 微信 identity provider 配置）
