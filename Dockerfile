FROM quay.io/keycloak/keycloak:18.0.2

COPY target/keycloak-services-social-weixin-0.1.1.jar /opt/keycloak/providers/

CMD ["start-dev", "--hostname-strict=false"]