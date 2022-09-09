# keycloak-services-social-weixin

[中文](README.md)

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
  
## How to build

```shell script
mvn install
```

## Develop

```shell script
mvn clean test
```

## Maven package

- For Keycloak 7.0.0: https://github.com/Jeff-Tian/keycloak-services-social-weixin/packages/225091?version=0.0.6

- For Keycloak 15.0.2: https://github.com/Jeff-Tian/keycloak-services-social-weixin/packages/225091?version=0.0.22

## Screenshots

![image](https://user-images.githubusercontent.com/3367820/82117152-fdfd0300-97a0-11ea-8e10-02c9d9838a0a.png)

## Docker images

[keycloak server docker](https://hub.docker.com/repository/docker/jefftian/keycloak-heroku)：

```shell script
docker pull jefftian/keycloak-heroku:latest
```

## Deploy by one click

Deploy to your own Heroku：
[![Deploy to Heroku](https://www.herokucdn.com/deploy/button.svg)](https://dashboard.heroku.com/new?button-url=https%3A%2F%2Fgithub.com%2FJeff-Tian%2Fkeycloak-heroku&template=https%3A%2F%2Fgithub.com%2FJeff-Tian%2Fkeycloak-heroku)

## Release Notes

* 20210805

1 Support Keycloak 15.0.2
