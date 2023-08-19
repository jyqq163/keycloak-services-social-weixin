package org.keycloak.social.weixin;

import org.junit.Assert;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

class JsonHelperTest {

    @Test
    void stringify() {
        UserModel federatedUser = new UserModel() {
            @Override
            public String getId() {
                return "hello";
            }

            @Override
            public String getUsername() {
                return "test user";
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
                return false;
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
                return null;
            }

            @Override
            public Map<String, List<String>> getAttributes() {
                return null;
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
                return null;
            }

            @Override
            public void setFirstName(String s) {

            }

            @Override
            public String getLastName() {
                return null;
            }

            @Override
            public void setLastName(String s) {

            }

            @Override
            public String getEmail() {
                return null;
            }

            @Override
            public void setEmail(String s) {

            }

            @Override
            public boolean isEmailVerified() {
                return false;
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
                return null;
            }

            @Override
            public void deleteRoleMapping(RoleModel roleModel) {

            }
        };

        Assert.assertEquals("{\n" +
                "  \"username\": \"test user\",\n" +
                "  \"id\": \"hello\",\n" +
                "  \"email\": null,\n" +
                "  \"enabled\": false,\n" +
                "  \"firstName\": null,\n" +
                "  \"lastName\": null,\n" +
                "  \"createdTimestamp\": null,\n" +
                "  \"federationLink\": null,\n" +
                "  \"serviceAccountClientLink\": null,\n" +
                "  \"groupsCount\": 0,\n" +
                "  \"attributes\": \"\"\n" +
                "}", JsonHelper.stringify(federatedUser, UserModel.class));

        var user = WMPHelper.getUserSessionModel(new BrokeredIdentityContext("test"), federatedUser, new AuthenticationSessionModel() {
                    @Override
                    public String getTabId() {
                        return null;
                    }

                    @Override
                    public RootAuthenticationSessionModel getParentSession() {
                        return null;
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
                        return null;
                    }

                    @Override
                    public void setAuthenticatedUser(UserModel userModel) {

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
                        return null;
                    }

                    @Override
                    public void clearUserSessionNotes() {

                    }

                    @Override
                    public String getAuthNote(String s) {
                        return null;
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
                        return null;
                    }

                    @Override
                    public void setClientNote(String s, String s1) {

                    }

                    @Override
                    public void removeClientNote(String s) {

                    }

                    @Override
                    public Map<String, String> getClientNotes() {
                        return null;
                    }

                    @Override
                    public void clearClientNotes() {

                    }

                    @Override
                    public Set<String> getClientScopes() {
                        return null;
                    }

                    @Override
                    public void setClientScopes(Set<String> set) {

                    }

                    @Override
                    public String getRedirectUri() {
                        return null;
                    }

                    @Override
                    public void setRedirectUri(String s) {

                    }

                    @Override
                    public RealmModel getRealm() {
                        return null;
                    }

                    @Override
                    public ClientModel getClient() {
                        return null;
                    }

                    @Override
                    public String getAction() {
                        return null;
                    }

                    @Override
                    public void setAction(String s) {

                    }

                    @Override
                    public String getProtocol() {
                        return null;
                    }

                    @Override
                    public void setProtocol(String s) {

                    }
                }
        );
        var res = JsonHelper.stringify(user, WMPUserSessionModel.class);
        Assert.assertEquals("{\n" +
                "  \"id\": \"test\",\n" +
                "  \"realm\": \"\",\n" +
                "  \"brokerSessionId\": null,\n" +
                "  \"brokerUserId\": null,\n" +
                "  \"lastSessionRefresh\": 0,\n" +
                "  \"authMethod\": \"WMP\",\n" +
                "  \"ipAddress\": \"0.0.0.0\",\n" +
                "  \"user\": \"{\\n  \\\"username\\\": \\\"test user\\\",\\n  \\\"id\\\": \\\"hello\\\",\\n  \\\"email\\\": null,\\n  \\\"enabled\\\": false,\\n  \\\"firstName\\\": null,\\n  \\\"lastName\\\": null,\\n  \\\"createdTimestamp\\\": null,\\n  \\\"federationLink\\\": null,\\n  \\\"serviceAccountClientLink\\\": null,\\n  \\\"groupsCount\\\": 0,\\n  \\\"attributes\\\": \\\"\\\"\\n}\",\n" +
                "  \"loginUserName\": null,\n" +
                "  \"started\": 0,\n" +
                "  \"notes\": \"null\",\n" +
                "  \"authenticatedClientSessions\": \"null\",\n" +
                "  \"state\": \"null\"\n" +
                "}", res);
    }
}
