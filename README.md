# keycloak-services-social-weixin

[English](README_en-US.md)

> Keycloak 的微信登录插件

![Java CI with Maven](https://github.com/Jeff-Tian/keycloak-services-social-weixin/workflows/Java%20CI%20with%20Maven/badge.svg)
![Maven Package](https://github.com/Jeff-Tian/keycloak-services-social-weixin/workflows/Maven%20Package/badge.svg)

## 在线体验

- [点击我并选择使用微信登录](https://keycloak.jiwai.win/auth/realms/UniHeart/protocol/openid-connect/auth?response_type=code&redirect_uri=http%3A%2F%2Fsso.jiwai.win%2Fkeycloak%2Flogin&client_id=UniHeart-Client-Local-3000)

## 如何使用

To install the social weixin one has to:

* Add the jar to the Keycloak server:
    * `cp target/keycloak-services-social-weixin-*.jar _KEYCLOAK_HOME_/providers/`

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

## 配置截图

### Keycloak 16

![image](https://user-images.githubusercontent.com/3367820/82117152-fdfd0300-97a0-11ea-8e10-02c9d9838a0a.png)

### Keycloak 22

![](./assets/config.png)

Client ID 和 公众号 App Id；Client Secret 和 公众号 App Secret 都可以是一样的，即通过手机或者 PC 的微信登录时，都使用同一个公众号。但是以上截图用了两个不同的，其中公众号 App Id 使用了我的个人测试公众号，在关注人数在 100 以内时可以使用。而手机端，则必须使用经过认证的企业公众号（特别感谢知友 [hhhnnn](https://www.zhihu.com/people/hhhnnn-78) 帮我提供，没有该服务号我没法调通手机端）。

## Docker 镜像

我也打包了一个包含[微信 idp 的 keycloak server docker 镜像](https://hub.docker.com/repository/docker/jefftian/keycloak-heroku)：

```shell script
docker pull jefftian/keycloak-heroku:latest
```

## 一键部署

### 部署到 Heroku

点击这个按钮，可以部署一个包含微信登录的 Keycloak 到你自己的 Heroku：
[![Deploy to Heroku](https://www.herokucdn.com/deploy/button.svg)](https://dashboard.heroku.com/new?button-url=https%3A%2F%2Fgithub.com%2FJeff-Tian%2Fkeycloak-heroku&template=https%3A%2F%2Fgithub.com%2FJeff-Tian%2Fkeycloak-heroku)

### 部署到 Okteto

[【免费架构】Heroku 不免费了，何去何从之 Keycloak 的容器化部署之路 - Jeff Tian的文章 - 知乎](https://zhuanlan.zhihu.com/p/611823061)

## 谁在使用

| URL                        | 说明                                           | 源码                                           |
|----------------------------|----------------------------------------------|----------------------------------------------|
| https://keycloak.jiwai.win | 我部署在 heroku 上的 Keycloak 实例                   | https://github.com/jeff-tian/keycloak-heroku |
| https://www.da-yi-jia.com  | 感谢[答疑家](https://www.da-yi-jia.com)对本项目的大力支持！ |

## 💵 欢迎问我！

有任何相关问题，欢迎来知乎咨询：

<a href="https://www.zhihu.com/consult/people/1073548674713423872" target="blank"><img src="https://first-go-vercel.vercel.app/api/dynamicimage" alt="向我咨询"/></a>

## Release Notes

* 2022090
    - 适配 quay.io/keycloak 18.0.2

* 20180730
    - 增加自适应微信登录功能。
    - 账号关联默认使用微信unionid，如unionid不存在则使用openId
    - pc和wechat使用同一套账号则必须绑定同一个开放平台，否则会绑定不同账号
    - wechat信息非必填,默认使用pc方式登录

* 20200514
    - 增加 customizedLoginUrlForPc 功能。

* 20230820
    - 适配 quay.io/keycloak 21.1 的版本（由于 21 既不支持老的配置页，又没有新的方式增加自定义配置页，所以只能通过导入老的 Keycloak 版本中的 微信 identity provider 配置）

* 20230823
    - 适配 quay.io/keycloak 22.0.1 的版本，可以正常显示所有的配置了！![](./assets/config.png)

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Jeff-Tian/keycloak-services-social-weixin&type=Date)](https://star-history.com/#Jeff-Tian/keycloak-services-social-weixin&Date)
