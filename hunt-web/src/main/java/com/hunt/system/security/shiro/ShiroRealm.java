package com.hunt.system.security.shiro;

import com.hunt.common.utils.StringUtils;
import com.hunt.dao.*;
import com.hunt.model.entity.*;
import com.hunt.util.SystemConstant;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;

import java.util.List;
/**
 * @Author: ouyangan
 * @Date : 2016/10/7
 * @Description 自定义realm实现
 */
public class ShiroRealm extends AuthorizingRealm {
    private static Logger log = LoggerFactory.getLogger(ShiroRealm.class);
    @Autowired
    private SysUserPermissionMapper sysUserPermissionMapper;
    @Autowired
    private SysUserMapper sysUserMapper;
    @Autowired
    private SysUserMapper sysUserMapper;
    @Autowired
    private SysPermissionMapper sysPermissionMapper;
    @Autowired
    private SysUserRoleOrganizationMapper sysUserRoleOrganizationMapper;
    @Autowired
    private SysRoleMapper sysRoleMapper;
    @Autowired
    private SysRoleOrganizationMapper sysRoleOrganizationMapper;
    @Autowired
    private SysRolePermissionMapper sysRolePermissionMapper;
    @Autowired
    private RedisTemplate<Object, Object> redisTemplate;
 47 |
    /**
     * 鉴权信息
     *
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        log.debug("开始查询授权信息");
        SimpleAuthorizationInfo authorizationInfo =  new SimpleAuthorizationInfo();
        String loginStr = (String) principalCollection.getPrimaryPrincipal();
        SysUser user = sysUserMapper.selectUserByLoginName(loginStr);//这里用的是当前登录的用户
        List<SysUserPermission> userPermissions = sysUserPermissionMapper.selectByUserId(user.getId());
        List<String> permissions = new ArrayList<>();
        List<String> roles = new ArrayList<>();
        for (SysUserPermission userPermission : userPermissions) {
            SysPermission sysPermission = sysPermissionMapper.selectById(userPermission.getSysPermissionId());
            permissions.add(sysPermission.getCode());
        }
        List<SysUserRoleOrganization> userRoleOrganizations = sysUserRoleOrganizationMapper.selectByUserId(user.getId());
        for (SysUserRoleOrganization sysUserRoleOrganization : userRoleOrganizations) {
            SysRole sysRole = sysRoleMapper.selectById(sysUserRoleOrganization.getSysRoleId());
            roles.add(sysRole.getName());
            List<SysRolePermission> sysRolePermissions = sysRolePermissionMapper.selectByRoleId(sysRole.getId());
            for (SysRolePermission sysRolePermission : sysRolePermissions) {
                SysPermission sysPermission = sysPermissionMapper.selectById(sysRolePermission.getSysPermissionId());
                permissions.add(sysPermission.getCode());
            }
        }
        authorizationInfo.addRoles(roles);
        authorizationInfo.addStringPermissions(permissions);
        log.debug("角色信息: \n {}", roles);
        log.debug("权限信息: \n{}", permissions);
        return authorizationInfo;
    }

    /**
     * 登录验证
     *
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        log.debug("登录验证");
        UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;
        String loginName = (String) authenticationToken.getPrincipal();
        SysUser sysUser = sysUserMapper.selectUserByLoginName(loginName);
        if (sysUser == null) {
            throw new UnknownAccountException(); // 账号不存在
        }
        if (sysUser.getStatus() == SystemConstant.USER_STATUS_FROZEN) {
            throw new LockedAccountException(); // 账号被冻结
        }
        AuthenticationInfo authenticationInfo = null;
        if (StringUtils.isEmpty(sysUser.getPassword())) {
            authenticationInfo = new SimpleAuthenticationInfo(loginName, token.getPassword(), getName());
        } else {
            authenticationInfo = new SimpleAuthenticationInfo(loginName, sysUser.getPassword(), ByteSource.Util.bytes(sysUser.getPasswordSalt()), getName());
        }
        return authenticationInfo;
    }
    @Override
    protected void doClearCache(PrincipalCollection principals) {
        redisTemplate.delete(SystemConstant.shiro_cache_prefix + principals.getPrimaryPrincipal().toString());
    }

    @Override
    protected void clearCachedAuthorizationInfo(PrincipalCollection principals) {
        log.debug("clearCachedAuthorizationInfo");
    }

}