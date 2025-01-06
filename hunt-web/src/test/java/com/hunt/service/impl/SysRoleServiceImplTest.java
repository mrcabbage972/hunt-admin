package com.hunt.service.impl;

import com.hunt.service.SysRoleService;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.transaction.annotation.Transactional;
 * @Author ouyangan
 * @Date 2016/10/27/17:56
 * @Description
 */
//@RunWith(SpringJUnit4ClassRunner.class)
//@ContextConfiguration({"classpath:spring.xml"})
@Transactional
public class SysRoleServiceImplTest {

    @Autowired
    private SysRoleService service;

    @Test
    public void testInsertRole() throws Exception {
        //SysPermission sysPermission = new SysPermission();
        //sysPermission.setName("test permission name");
        //sysPermission.setCode("code");
        //sysPermission.setDescription("test permission description");
        //sysPermissionService.insertPermission(sysPermission);

    }

    public void selectById() throws Exception {

    }

    @Test
    public void selectPage() throws Exception {

    }

    @Test
    public void deleteRole() throws Exception {

    }

    @Test
    public void updateRole() throws Exception {

    }

}