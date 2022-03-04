package org.keycloak.social.weixin;

import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

import java.util.Map;
import java.util.Set;

public class WechatMiniProgramSession implements AuthenticationSessionModel {
    private KeycloakSession session;
    private final RealmModel realmModel;
    private final UserModel authenticatedUser;

    public WechatMiniProgramSession(KeycloakSession session, RealmModel realmModel, UserModel userModel) {
        this.session = session;
        this.realmModel = realmModel;
        this.authenticatedUser = userModel;
    }

    @Override
    public String getRedirectUri() {
        return "/stop";
    }

    @Override
    public void setRedirectUri(String s) {

    }

    @Override
    public RealmModel getRealm() {
        return this.realmModel;
    }

    @Override
    public ClientModel getClient() {
        return this.realmModel.getClientByClientId(Constants.BROKER_SERVICE_CLIENT_ID);
    }

    @Override
    public String getAction() {
        System.out.println("getting action, I returned null");
        return null;
    }

    @Override
    public void setAction(String s) {

    }

    @Override
    public String getProtocol() {
        return "protocol";
    }

    @Override
    public void setProtocol(String s) {

    }

    @Override
    public String getTabId() {
        return "QRrSfbxHzaM";
    }

    @Override
    public RootAuthenticationSessionModel getParentSession() {
        System.out.println("getParentSession = null, creating...");
        var root =  this.session.authenticationSessions().createRootAuthenticationSession(this.realmModel);

        System.out.println(Util.inspect("root = ", root));

        return root;
    }

    @Override
    public Map<String, ExecutionStatus> getExecutionStatus() {
        return null;
    }

    @Override
    public void setExecutionStatus(String s, ExecutionStatus executionStatus) {

    }

    @Override
    public void clearExecutionStatus() {

    }

    @Override
    public UserModel getAuthenticatedUser() {
        return this.authenticatedUser;
    }

    @Override
    public void setAuthenticatedUser(UserModel userModel) {

    }

    @Override
    public Set<String> getRequiredActions() {
        System.out.println("getRequiredActions is null to switch to respond directly");
        return Set.of();
    }

    @Override
    public void addRequiredAction(String s) {

    }

    @Override
    public void removeRequiredAction(String s) {

    }

    @Override
    public void addRequiredAction(UserModel.RequiredAction requiredAction) {

    }

    @Override
    public void removeRequiredAction(UserModel.RequiredAction requiredAction) {

    }

    @Override
    public void setUserSessionNote(String s, String s1) {

    }

    @Override
    public Map<String, String> getUserSessionNotes() {
        return Map.of("user", "session");
    }

    @Override
    public void clearUserSessionNotes() {

    }

    @Override
    public String getAuthNote(String s) {
        if(s.equals(AbstractIdpAuthenticator.EXISTING_USER_INFO)){
            return "null";
        }

        if(s.equals(WeiXinIdentityBrokerService.LINKING_IDENTITY_PROVIDER)){
            return "";
        }

        System.out.println("Getting auth note with s = " + s + ", and I returned false for it");
        return "false";
    }

    @Override
    public void setAuthNote(String s, String s1) {

    }

    @Override
    public void removeAuthNote(String s) {

    }

    @Override
    public void clearAuthNotes() {

    }

    @Override
    public String getClientNote(String s) {
        if(s.equals(Constants.KC_ACTION)) {
            System.out.println("Getting client note with s = " + s + ", and I returned null");
            return null;
        }

        return "note";
    }

    @Override
    public void setClientNote(String s, String s1) {

    }

    @Override
    public void removeClientNote(String s) {

    }

    @Override
    public Map<String, String> getClientNotes() {
        return Map.of("note1", "note2");
    }

    @Override
    public void clearClientNotes() {

    }

    @Override
    public Set<String> getClientScopes() {
        return Set.of("client_credential");
    }

    @Override
    public void setClientScopes(Set<String> set) {

    }
}
