package org.keycloak.social.weixin.cache;

import jakarta.persistence.*;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaDelete;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.CriteriaUpdate;
import jakarta.persistence.metamodel.Metamodel;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.connections.jpa.JpaConnectionProvider;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class TicketStatusProvider implements UserStorageProvider {
    private final KeycloakSession session;
    private final ComponentModel model;
    private static Map<String, TicketEntity> localCache = new ConcurrentHashMap<>();

    private static final Logger logger = Logger.getLogger(TicketStatusProvider.class);

    protected EntityManager em;

    public TicketStatusProvider(KeycloakSession keycloakSession, ComponentModel componentModel) {
        this.session = keycloakSession;
        this.model = componentModel;
        var jpaProvider = session.getProvider(JpaConnectionProvider.class, "ticket-store");

        if (jpaProvider != null) {
            this.em = jpaProvider.getEntityManager();
            return;
        }

        this.em = new EntityManager() {
            @Override
            public void persist(Object o) {
                localCache.put(((TicketEntity) o).getTicket(), (TicketEntity) o);
            }

            @Override
            public <T> T merge(T t) {
                return null;
            }

            @Override
            public void remove(Object o) {
                localCache.remove(((TicketEntity) o).getTicket());
            }

            @Override
            public <T> T find(Class<T> aClass, Object o) {
                return (T) localCache.get((String) o);
            }

            @Override
            public <T> T find(Class<T> aClass, Object o, Map<String, Object> map) {
                return null;
            }

            @Override
            public <T> T find(Class<T> aClass, Object o, LockModeType lockModeType) {
                return null;
            }

            @Override
            public <T> T find(Class<T> aClass, Object o, LockModeType lockModeType, Map<String, Object> map) {
                return null;
            }

            @Override
            public <T> T getReference(Class<T> aClass, Object o) {
                return (T) o;
            }

            @Override
            public void flush() {
            }

            @Override
            public void setFlushMode(FlushModeType flushModeType) {

            }

            @Override
            public FlushModeType getFlushMode() {
                return null;
            }

            @Override
            public void lock(Object o, LockModeType lockModeType) {

            }

            @Override
            public void lock(Object o, LockModeType lockModeType, Map<String, Object> map) {

            }

            @Override
            public void refresh(Object o) {

            }

            @Override
            public void refresh(Object o, Map<String, Object> map) {

            }

            @Override
            public void refresh(Object o, LockModeType lockModeType) {

            }

            @Override
            public void refresh(Object o, LockModeType lockModeType, Map<String, Object> map) {

            }

            @Override
            public void clear() {
                localCache.clear();
            }

            @Override
            public void detach(Object o) {

            }

            @Override
            public boolean contains(Object o) {
                return false;
            }

            @Override
            public LockModeType getLockMode(Object o) {
                return null;
            }

            @Override
            public void setProperty(String s, Object o) {

            }

            @Override
            public Map<String, Object> getProperties() {
                return null;
            }

            @Override
            public Query createQuery(String s) {
                return null;
            }

            @Override
            public <T> TypedQuery<T> createQuery(CriteriaQuery<T> criteriaQuery) {
                return null;
            }

            @Override
            public Query createQuery(CriteriaUpdate criteriaUpdate) {
                return null;
            }

            @Override
            public Query createQuery(CriteriaDelete criteriaDelete) {
                return null;
            }

            @Override
            public <T> TypedQuery<T> createQuery(String s, Class<T> aClass) {
                return null;
            }

            @Override
            public Query createNamedQuery(String s) {
                return null;
            }

            @Override
            public <T> TypedQuery<T> createNamedQuery(String s, Class<T> aClass) {
                return null;
            }

            @Override
            public Query createNativeQuery(String s) {
                return null;
            }

            @Override
            public Query createNativeQuery(String s, Class aClass) {
                return null;
            }

            @Override
            public Query createNativeQuery(String s, String s1) {
                return null;
            }

            @Override
            public StoredProcedureQuery createNamedStoredProcedureQuery(String s) {
                return null;
            }

            @Override
            public StoredProcedureQuery createStoredProcedureQuery(String s) {
                return null;
            }

            @Override
            public StoredProcedureQuery createStoredProcedureQuery(String s, Class... classes) {
                return null;
            }

            @Override
            public StoredProcedureQuery createStoredProcedureQuery(String s, String... strings) {
                return null;
            }

            @Override
            public void joinTransaction() {

            }

            @Override
            public boolean isJoinedToTransaction() {
                return false;
            }

            @Override
            public <T> T unwrap(Class<T> aClass) {
                return null;
            }

            @Override
            public Object getDelegate() {
                return null;
            }

            @Override
            public void close() {

            }

            @Override
            public boolean isOpen() {
                return false;
            }

            @Override
            public EntityTransaction getTransaction() {
                return null;
            }

            @Override
            public EntityManagerFactory getEntityManagerFactory() {
                return null;
            }

            @Override
            public CriteriaBuilder getCriteriaBuilder() {
                return null;
            }

            @Override
            public Metamodel getMetamodel() {
                return null;
            }

            @Override
            public <T> EntityGraph<T> createEntityGraph(Class<T> aClass) {
                return null;
            }

            @Override
            public EntityGraph<?> createEntityGraph(String s) {
                return null;
            }

            @Override
            public EntityGraph<?> getEntityGraph(String s) {
                return null;
            }

            @Override
            public <T> List<EntityGraph<? super T>> getEntityGraphs(Class<T> aClass) {
                return null;
            }
        };
    }

    @Override
    public void close() {

    }

    public TicketEntity saveTicketStatus(String ticket, Number expireSeconds, String status) {
        logger.info(String.format("saveTicketStatus by %s%n%s%n", ticket, expireSeconds, status));

        var entity = new TicketEntity();
        entity.setId(UUID.randomUUID().toString());
        entity.setTicket(ticket);
        entity.setStatus(status);
        entity.setExpireSeconds(expireSeconds);
        entity.setTicketCreatedAt(System.currentTimeMillis() / 1000L);
        em.persist(entity);

        return entity;
    }

    public TicketEntity getTicketStatus(String ticket) {
        logger.info(String.format("getTicketStatus by %s%n", ticket));

        var ticketEntity = em.find(TicketEntity.class, ticket);

        logger.info(String.format("ticketEntity is %s%n", ticketEntity));

        return ticketEntity;
    }

    public TicketEntity saveTicketStatus(TicketEntity ticket) {
        logger.info(String.format("saveTicketStatus by %s%n", ticket));

        if (Objects.equals(ticket.getStatus(), "expired")) {
            em.remove(ticket);
        } else {
            em.persist(ticket);
        }

        return ticket;
    }
}
