package org.keycloak.social.weixin;

import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Collection;
import java.util.Map;

public class WMPUserSessionModel implements UserSessionModel {
    private final BrokeredIdentityContext context;
    private final UserModel federatedUser;
    private final AuthenticationSessionModel authSession;

    public WMPUserSessionModel(BrokeredIdentityContext context, UserModel federatedUser, AuthenticationSessionModel authSession) {
        this.context = context;
        this.federatedUser = federatedUser;
        this.authSession = authSession;
    }

    @Override
    public String getId() {
        return context.getId();
    }

    @Override
    public RealmModel getRealm() {
        return authSession.getRealm();
    }

    @Override
    public String getBrokerSessionId() {
        return context.getBrokerSessionId();
    }

    @Override
    public String getBrokerUserId() {
        return context.getBrokerUserId();
    }

    @Override
    public UserModel getUser() {
        return federatedUser;
    }

    @Override
    public String getLoginUsername() {
        return context.getUsername();
    }

    @Override
    public String getIpAddress() {
        return "0.0.0.0";
    }

    @Override
    public String getAuthMethod() {
        return "WMP";
    }

    @Override
    public boolean isRememberMe() {
        return false;
    }

    @Override
    public int getStarted() {
        return 0;
    }

    @Override
    public int getLastSessionRefresh() {
        return 0;
    }

    @Override
    public void setLastSessionRefresh(int i) {

    }

    @Override
    public boolean isOffline() {
        return false;
    }

    @Override
    public Map<String, AuthenticatedClientSessionModel> getAuthenticatedClientSessions() {
        return null;
    }

    @Override
    public void removeAuthenticatedClientSessions(Collection<String> collection) {

    }

    @Override
    public String getNote(String s) {
        return s;
    }

    @Override
    public void setNote(String s, String s1) {

    }

    @Override
    public void removeNote(String s) {

    }

    @Override
    public Map<String, String> getNotes() {
        return null;
    }

    @Override
    public State getState() {
        return null;
    }

    @Override
    public void setState(State state) {

    }

    @Override
    public void restartSession(RealmModel realmModel, UserModel userModel, String s, String s1, String s2, boolean b, String s3, String s4) {

    }
}
