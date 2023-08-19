package org.keycloak.social.weixin;

import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.util.IdentityBrokerState;
import org.keycloak.models.*;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.*;
import java.util.stream.Stream;

public class WMPHelper {
    public static String createStateForWMP(String clientId, String tabId) {
        return IdentityBrokerState.decoded("wmp", clientId, clientId, tabId).getEncoded();
    }

    public static UserSessionModel getUserSessionModel(BrokeredIdentityContext context, UserModel federatedUser, AuthenticationSessionModel authSession) {
        return new WMPUserSessionModel(context, federatedUser, authSession);
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
            public Stream<String> getAttributeStream(String s) {
                List<String> attributeValues = this.getAttribute(s);

                return attributeValues.stream();
            }

            private List<String> getAttribute(String s) {
                return Collections.singletonList(context.getUserAttribute(s));
            }

            @Override
            public Map<String, List<String>> getAttributes() {
                return context.getAttributes();
            }

            @Override
            public Stream<String> getRequiredActionsStream() {
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
            public Stream<GroupModel> getGroupsStream() {
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
            public SubjectCredentialManager credentialManager() {
                return null;
            }

            @Override
            public Stream<RoleModel> getRealmRoleMappingsStream() {
                return null;
            }

            @Override
            public Stream<RoleModel> getClientRoleMappingsStream(ClientModel clientModel) {
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
            public Stream<RoleModel> getRoleMappingsStream() {
                return Stream.<RoleModel>builder().build();
            }

            @Override
            public void deleteRoleMapping(RoleModel roleModel) {

            }
        };
        final AuthenticatedWMPSession wmpSession = new AuthenticatedWMPSession(session, weiXinIdentityBrokerService.realmModel, userModel);

        return new ClientSessionCode(session, realmModel, wmpSession);
    }
}
