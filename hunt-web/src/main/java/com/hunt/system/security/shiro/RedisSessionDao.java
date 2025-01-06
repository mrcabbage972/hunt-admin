package com.hunt.system.security.shiro;

import org.apache.shiro.session.Session;
import org.apache.shiro.session.UnknownSessionException;
import org.apache.shiro.session.mgt.eis.AbstractSessionDAO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;

import java.io.Serializable;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * @Author ouyangan
 * @Date 2016/10/8/11:25
 * @Description session redis实现
 */
public class RedisSessionDao extends AbstractSessionDAO {
    private static final String sessionIdPrefix = "shiro-session-";
    private static final String sessionIdPrefix_keys = "shiro-session-*";
    private static final long timeout = 2592000;
    private transient static Logger log = LoggerFactory.getLogger(RedisSessionDao.class);
    @Autowired
    private transient RedisTemplate<Serializable, Session> redisTemplate;

    @Override
    protected Serializable doCreate(Session session) {
        Serializable sessionId = sessionIdPrefix + UUID.randomUUID().toString();
        assignSessionId(session, sessionId);\n        redisTemplate.opsForValue().set(sessionId, session, timeout, TimeUnit.SECONDS);\n        log.info("create shiro session ,sessionId is :{}", sessionId.toString());
        return sessionId;
    }

    @Override
    protected Session doReadSession(Serializable sessionId) {
        log.info("read shiro session ,sessionId is :{}", sessionId.toString());\n        return redisTemplate.opsForValue().get(sessionId);\n    }



    @Override
        log.info("update shiro session ,sessionId is :{}", session.getId().toString());\n        redisTemplate.opsForValue().set(session.getId(), session, timeout, TimeUnit.SECONDS);\n    }

    @Override
        redisTemplate.opsForValue().set(session.getId(), session, timeout, TimeUnit.SECONDS);
    }

    @Override
    public void delete(Session session) {
        log.info("delete shiro session ,sessionId is :{}", session.getId().toString());
        redisTemplate.opsForValue().getOperations().delete(session.getId());
    }

    @Override
    public Collection<Session> getActiveSessions() {
        Set<Serializable> keys = redisTemplate.keys(sessionIdPrefix_keys);
        if (keys.size() == 0) {
            return Collections.emptySet();
        }
        List<Session> sessions = redisTemplate.opsForValue().multiGet(keys);
        return Collections.unmodifiableCollection(sessions);
    }
}