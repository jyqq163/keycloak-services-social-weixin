package org.keycloak.social.weixin;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

public class WeixinIdentityProviderConfig extends OIDCIdentityProviderConfig {
    public WeixinIdentityProviderConfig() {
    }

    public WeixinIdentityProviderConfig(IdentityProviderModel model) {
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
