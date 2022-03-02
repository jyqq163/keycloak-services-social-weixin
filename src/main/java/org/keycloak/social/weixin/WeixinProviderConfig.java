package org.keycloak.social.weixin;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

public class WeixinProviderConfig extends OAuth2IdentityProviderConfig {
    public WeixinProviderConfig() {
    }

    public WeixinProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    public void setCustomizedLoginUrlForPc(String customizedLoginUrlForPc) {
        this.getConfig().put(WeiXinIdentityProvider.CUSTOMIZED_LOGIN_URL_FOR_PC, customizedLoginUrlForPc);
    }

    public String getCustomizedLoginUrlForPc() {
        return this.getConfig().get(WeiXinIdentityProvider.CUSTOMIZED_LOGIN_URL_FOR_PC);
    }

    public void setClientId2(String clientId2) {
        this.getConfig().put("clientId2", clientId2);
    }

    public void setWmpClientId(String clientId) {
        this.getConfig().put("wmpClientId", clientId);
    }
}
