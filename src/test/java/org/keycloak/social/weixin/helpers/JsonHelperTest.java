package org.keycloak.social.weixin.helpers;

import org.junit.Assert;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.social.weixin.WMPUserSessionModel;
import org.keycloak.social.weixin.helpers.JsonHelper;
import org.keycloak.social.weixin.helpers.WMPHelper;

import java.util.*;
import java.util.function.*;
import java.util.stream.*;

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
                return new Stream<GroupModel>() {
                    @Override
                    public Stream<GroupModel> filter(Predicate<? super GroupModel> predicate) {
                        return Stream.empty();
                    }

                    @Override
                    public <R> Stream<R> map(Function<? super GroupModel, ? extends R> mapper) {
                        return Stream.empty();
                    }

                    @Override
                    public IntStream mapToInt(ToIntFunction<? super GroupModel> mapper) {
                        return IntStream.empty();
                    }

                    @Override
                    public LongStream mapToLong(ToLongFunction<? super GroupModel> mapper) {
                        return LongStream.empty();
                    }

                    @Override
                    public DoubleStream mapToDouble(ToDoubleFunction<? super GroupModel> mapper) {
                        return DoubleStream.empty();
                    }

                    @Override
                    public <R> Stream<R> flatMap(Function<? super GroupModel, ? extends Stream<? extends R>> mapper) {
                        return Stream.empty();
                    }

                    @Override
                    public IntStream flatMapToInt(Function<? super GroupModel, ? extends IntStream> mapper) {
                        return IntStream.empty();
                    }

                    @Override
                    public LongStream flatMapToLong(Function<? super GroupModel, ? extends LongStream> mapper) {
                        return LongStream.empty();
                    }

                    @Override
                    public DoubleStream flatMapToDouble(Function<? super GroupModel, ? extends DoubleStream> mapper) {
                        return DoubleStream.empty();
                    }

                    @Override
                    public Stream<GroupModel> distinct() {
                        return Stream.empty();
                    }

                    @Override
                    public Stream<GroupModel> sorted() {
                        return Stream.empty();
                    }

                    @Override
                    public Stream<GroupModel> sorted(Comparator<? super GroupModel> comparator) {
                        return Stream.empty();
                    }

                    @Override
                    public Stream<GroupModel> peek(Consumer<? super GroupModel> action) {
                        return Stream.empty();
                    }

                    @Override
                    public Stream<GroupModel> limit(long maxSize) {
                        return Stream.empty();
                    }

                    @Override
                    public Stream<GroupModel> skip(long n) {
                        return Stream.empty();
                    }

                    @Override
                    public void forEach(Consumer<? super GroupModel> action) {

                    }

                    @Override
                    public void forEachOrdered(Consumer<? super GroupModel> action) {

                    }

                    @Override
                    public Object[] toArray() {
                        return new Object[0];
                    }

                    @Override
                    public <A> A[] toArray(IntFunction<A[]> generator) {
                        return null;
                    }

                    @Override
                    public GroupModel reduce(GroupModel identity, BinaryOperator<GroupModel> accumulator) {
                        return null;
                    }

                    @Override
                    public Optional<GroupModel> reduce(BinaryOperator<GroupModel> accumulator) {
                        return Optional.empty();
                    }

                    @Override
                    public <U> U reduce(U identity, BiFunction<U, ? super GroupModel, U> accumulator, BinaryOperator<U> combiner) {
                        return null;
                    }

                    @Override
                    public <R> R collect(Supplier<R> supplier, BiConsumer<R, ? super GroupModel> accumulator, BiConsumer<R, R> combiner) {
                        return null;
                    }

                    @Override
                    public <R, A> R collect(Collector<? super GroupModel, A, R> collector) {
                        return null;
                    }

                    @Override
                    public Optional<GroupModel> min(Comparator<? super GroupModel> comparator) {
                        return Optional.empty();
                    }

                    @Override
                    public Optional<GroupModel> max(Comparator<? super GroupModel> comparator) {
                        return Optional.empty();
                    }

                    @Override
                    public long count() {
                        return 0;
                    }

                    @Override
                    public boolean anyMatch(Predicate<? super GroupModel> predicate) {
                        return false;
                    }

                    @Override
                    public boolean allMatch(Predicate<? super GroupModel> predicate) {
                        return false;
                    }

                    @Override
                    public boolean noneMatch(Predicate<? super GroupModel> predicate) {
                        return false;
                    }

                    @Override
                    public Optional<GroupModel> findFirst() {
                        return Optional.empty();
                    }

                    @Override
                    public Optional<GroupModel> findAny() {
                        return Optional.empty();
                    }

                    @Override
                    public Iterator<GroupModel> iterator() {
                        return null;
                    }

                    @Override
                    public Spliterator<GroupModel> spliterator() {
                        return null;
                    }

                    @Override
                    public boolean isParallel() {
                        return false;
                    }

                    @Override
                    public Stream<GroupModel> sequential() {
                        return Stream.empty();
                    }

                    @Override
                    public Stream<GroupModel> parallel() {
                        return Stream.empty();
                    }

                    @Override
                    public Stream<GroupModel> unordered() {
                        return Stream.empty();
                    }

                    @Override
                    public Stream<GroupModel> onClose(Runnable closeHandler) {
                        return Stream.empty();
                    }

                    @Override
                    public void close() {

                    }
                };
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

        var user = WMPHelper.getUserSessionModel(new BrokeredIdentityContext("test", new IdentityProviderModel()), federatedUser, new AuthenticationSessionModel() {
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
