package com.orion.ops.entity.vo;

import lombok.Data;

import java.util.Date;

/**
 * 终端日志
 *
 * @author Jiahang Li
 * @version 1.0.0
 * @since 2021/4/19 20:59
 */
@Data
public class MachineTerminalLogVO {

    /**
     * id
     */
    private Long id;

    /**
     * 用户id
     */
    private Long userId;

    /**
     * 用户名
     */
    private String username;

    /**
     * 机器id
     */
    private Long machineId;

    /**
     * 机器host
     */
    private String machineHost;

    /**
     * token
     */
    private String accessToken;

    /**
     * 建立连接时间
     */
    private Date connectedTime;

    /**
     * 断开连接时间
     */
    private Date disconnectedTime;

    /**
     * close code
     */
    private Integer closeCode;

    /**
     * 创建时间
     */
    private Date createTime;

}
