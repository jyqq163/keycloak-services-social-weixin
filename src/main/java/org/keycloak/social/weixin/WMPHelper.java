package org.keycloak.social.weixin;

import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.util.IdentityBrokerState;
import org.keycloak.models.*;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.*;

public class WMPHelper {
    public static String createStateForWMP(String clientId, String tabId) {
        return IdentityBrokerState.decoded("wmp", clientId, tabId).getEncoded();
    }

    public static UserSessionModel getUserSessionModel(BrokeredIdentityContext context, UserModel federatedUser, AuthenticationSessionModel authSession, String providerId, KeycloakSession session){
        return new UserSessionModel() {
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
        };
    }

    static ClientSessionCode getClientSessionCode(WeiXinIdentityBrokerService weiXinIdentityBrokerService, RealmModel realmModel, KeycloakSession session, BrokeredIdentityContext context) {
        final UserModel userModel = new UserModel() {
            @Override
            public String getId() {
                return context.getId();
            }

            @Override
            public String getUsername() {
                return context.getUsername();
            }

            @Override
            public void setUsername(String s) {

            }

            @Override
            public Long getCreatedTimestamp() {
                return null;
            }

            @Override
            public void setCreatedTimestamp(Long aLong) {

            }

            @Override
            public boolean isEnabled() {
                return true;
            }

            @Override
            public void setEnabled(boolean b) {

            }

            @Override
            public void setSingleAttribute(String s, String s1) {

            }

            @Override
            public void setAttribute(String s, List<String> list) {

            }

            @Override
            public void removeAttribute(String s) {

            }

            @Override
            public String getFirstAttribute(String s) {
                return null;
            }

            @Override
            public List<String> getAttribute(String s) {
                return Collections.singletonList(context.getUserAttribute(s));
            }

            @Override
            public Map<String, List<String>> getAttributes() {
                return null;
            }

            @Override
            public Set<String> getRequiredActions() {
                return null;
            }

            @Override
            public void addRequiredAction(String s) {

            }

            @Override
            public void removeRequiredAction(String s) {

            }

            @Override
            public String getFirstName() {
                return context.getFirstName();
            }

            @Override
            public void setFirstName(String s) {

            }

            @Override
            public String getLastName() {
                return context.getLastName();
            }

            @Override
            public void setLastName(String s) {

            }

            @Override
            public String getEmail() {
                return context.getEmail();
            }

            @Override
            public void setEmail(String s) {

            }

            @Override
            public boolean isEmailVerified() {
                return true;
            }

            @Override
            public void setEmailVerified(boolean b) {

            }

            @Override
            public Set<GroupModel> getGroups() {
                return null;
            }

            @Override
            public void joinGroup(GroupModel groupModel) {

            }

            @Override
            public void leaveGroup(GroupModel groupModel) {

            }

            @Override
            public boolean isMemberOf(GroupModel groupModel) {
                return false;
            }

            @Override
            public String getFederationLink() {
                return null;
            }

            @Override
            public void setFederationLink(String s) {

            }

            @Override
            public String getServiceAccountClientLink() {
                return null;
            }

            @Override
            public void setServiceAccountClientLink(String s) {

            }

            @Override
            public Set<RoleModel> getRealmRoleMappings() {
                return null;
            }

            @Override
            public Set<RoleModel> getClientRoleMappings(ClientModel clientModel) {
                return null;
            }

            @Override
            public boolean hasRole(RoleModel roleModel) {
                return false;
            }

            @Override
            public void grantRole(RoleModel roleModel) {

            }

            @Override
            public Set<RoleModel> getRoleMappings() {
                return null;
            }

            @Override
            public void deleteRoleMapping(RoleModel roleModel) {

            }
        };
        final WechatMiniProgramSession wmpSession = new WechatMiniProgramSession(session, weiXinIdentityBrokerService.realmModel, userModel);

        return new ClientSessionCode(session, realmModel, wmpSession);
    }
}
