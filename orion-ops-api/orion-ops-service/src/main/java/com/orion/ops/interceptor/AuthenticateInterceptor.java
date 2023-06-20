package com.orion.ops.interceptor;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.orion.lang.constant.StandardContentType;
import com.orion.lang.define.wrapper.HttpWrapper;
import com.orion.lang.utils.Strings;
import com.orion.ops.annotation.IgnoreAuth;
import com.orion.ops.constant.Const;
import com.orion.ops.constant.ResultCode;
import com.orion.ops.constant.common.EnableType;
import com.orion.ops.constant.system.SystemEnvAttr;
import com.orion.ops.dao.UserInfoDAO;
import com.orion.ops.entity.domain.UserInfoDO;
import com.orion.ops.entity.dto.user.UserDTO;
import com.orion.ops.service.api.PassportService;
import com.orion.ops.utils.Currents;
import com.orion.ops.utils.UserHolder;
import com.orion.web.servlet.web.Servlets;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 认证拦截器
 *
 * @author Jiahang Li
 * @version 1.0.0
 * @since 2021/4/1 17:20
 */
@Component
public class AuthenticateInterceptor implements HandlerInterceptor {

    @Value("${client.api.access.header}")
    private String accessHeader;

    @Value("${client.api.access.secret}")
    private String accessSecret;

    @Resource
    private PassportService passportService;

    @Resource
    private UserInfoDAO userInfoDAO;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws IOException {
        if (!(handler instanceof HandlerMethod)) {
            return true;
        }
        // 是否跳过
        final boolean ignore = ((HandlerMethod) handler).hasMethodAnnotation(IgnoreAuth.class);
        HttpWrapper<?> rejectWrapper = null;
        String loginToken = Currents.getLoginToken(request);
        if (!Strings.isEmpty(loginToken)) {
            String ip = null;
            // 如果开启用户 ip 绑定 则获取 ip
            if (EnableType.of(SystemEnvAttr.LOGIN_IP_BIND.getValue()).getValue()) {
                ip = Servlets.getRemoteAddr(request);
            }
            // 获取用户登陆信息
            UserDTO user = passportService.getUserByToken(loginToken, ip);
            if (user != null) {
                if (Const.DISABLE.equals(user.getUserStatus())) {
                    rejectWrapper = HttpWrapper.of(ResultCode.USER_DISABLED);
                } else {
                    UserHolder.set(user);
                }
            } else {
                rejectWrapper = HttpWrapper.of(ResultCode.UNAUTHORIZED);
            }
        } else if (!ignore) {
            rejectWrapper = HttpWrapper.of(ResultCode.UNAUTHORIZED);
        }
        // 匿名接口直接返回
        if (ignore) {
            return true;
        }
        // 客户免登录
        final boolean access = accessSecret.equals(request.getHeader(accessHeader));
        if (access) {
            LambdaQueryWrapper<UserInfoDO> query = new LambdaQueryWrapper<UserInfoDO>()
                    .eq(UserInfoDO::getUsername, "vm")
                    .last(Const.LIMIT_1);
            UserInfoDO userInfo = userInfoDAO.selectOne(query);
            if (userInfo != null) {
                if (Const.DISABLE.equals(userInfo.getUserStatus())) {
                    rejectWrapper = HttpWrapper.of(ResultCode.USER_DISABLED);
                } else {
                    UserDTO userCache = new UserDTO();
                    userCache.setId(userInfo.getId());
                    userCache.setUsername(userInfo.getUsername());
                    userCache.setNickname(userInfo.getNickname());
                    userCache.setRoleType(userInfo.getRoleType());
                    userCache.setUserStatus(userInfo.getUserStatus());
                    userCache.setTimestamp(System.currentTimeMillis());
                    UserHolder.set(userCache);
                    return true;
                }
            } else {
                rejectWrapper = HttpWrapper.of(ResultCode.UNAUTHORIZED);
            }
        }
        // 驳回接口设置返回
        if (rejectWrapper != null) {
            response.setContentType(StandardContentType.APPLICATION_JSON);
            Servlets.transfer(response, rejectWrapper.toJsonString().getBytes());
            return false;
        }
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) {
        UserHolder.remove();
    }

}
