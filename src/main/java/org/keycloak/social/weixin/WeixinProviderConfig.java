package org.keycloak.social.weixin;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

import static org.keycloak.social.weixin.WeiXinIdentityProvider.CUSTOMIZED_LOGIN_URL_FOR_PC;

public class WeixinProviderConfig extends OAuth2IdentityProviderConfig {
    public WeixinProviderConfig() {
    }

    public WeixinProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    public void setCustomizedLoginUrlForPc(String customizedLoginUrlForPc) {
        this.getConfig().put(CUSTOMIZED_LOGIN_URL_FOR_PC, customizedLoginUrlForPc);
    }

    public String getCustomizedLoginUrlForPc() {
        return this.getConfig().get(CUSTOMIZED_LOGIN_URL_FOR_PC);
    }

    public void setClientId2(String clientId2) {
        this.getConfig().put("clientId2", clientId2);
    }
}
