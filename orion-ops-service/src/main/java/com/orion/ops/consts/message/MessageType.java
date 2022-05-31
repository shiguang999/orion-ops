package com.orion.ops.consts.message;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * 消息类型
 *
 * @author Jiahang Li
 * @version 1.0.0
 * @since 2022/3/25 11:35
 */
@AllArgsConstructor
@Getter
public enum MessageType {

    // -------------------- 系统消息 --------------------

    /**
     * 命令执行完成
     */
    EXEC_SUCCESS(1010, "命令执行完成", MessageClassify.SYSTEM, "<sb 0>${name}</sb> 命令执行完成"),

    /**
     * 命令执行失败
     */
    EXEC_FAILURE(1020, "命令执行失败", MessageClassify.SYSTEM, "<sb 0>${name}</sb> 命令执行失败"),

    /**
     * 版本仓库初始化成功
     */
    VCS_INIT_SUCCESS(1030, "版本仓库初始化成功", MessageClassify.SYSTEM, "<sb 0>${name}</sb> 仓库初始化成功"),

    /**
     * 版本仓库初始化失败
     */
    VCS_INIT_FAILURE(1040, "版本仓库初始化失败", MessageClassify.SYSTEM, "<sb 0>${name}</sb> 仓库初始化失败"),

    /**
     * 构建执行成功
     */
    BUILD_SUCCESS(1050, "构建执行成功", MessageClassify.SYSTEM, "<sb 0>${appName}</sb> <sb>#${seq}</sb> 构建成功"),

    /**
     * 构建执行失败
     */
    BUILD_FAILURE(1060, "构建执行失败", MessageClassify.SYSTEM, "<sb 0>${appName}</sb> <sb>#${seq}</sb> 构建失败"),

    /**
     * 发布审批通过
     */
    RELEASE_AUDIT_RESOLVE(1070, "发布审批通过", MessageClassify.SYSTEM, "发布单 <sb>${title}</sb> 审核已通过"),

    /**
     * 发布审批驳回
     */
    RELEASE_AUDIT_REJECT(1080, "发布审批驳回", MessageClassify.SYSTEM, "发布单 <sb>${title}</sb> 审核已被驳回"),

    /**
     * 发布执行成功
     */
    RELEASE_SUCCESS(1090, "发布执行成功", MessageClassify.SYSTEM, "发布单 <sb>${title}</sb> 发布成功"),

    /**
     * 发布执行失败
     */
    RELEASE_FAILURE(1100, "发布执行失败", MessageClassify.SYSTEM, "发布单 <sb>${title}</sb> 发布失败"),

    /**
     * 应用流水线审批通过
     */
    PIPELINE_AUDIT_RESOLVE(1110, "应用流水线审批通过", MessageClassify.SYSTEM, "应用流水线 <sb>${name}</sb> <sb>${title}</sb> 审核已通过"),

    /**
     * 应用流水线审批驳回
     */
    PIPELINE_AUDIT_REJECT(1120, "应用流水线审批驳回", MessageClassify.SYSTEM, "应用流水线 <sb>${name}</sb> <sb>${title}</sb> 审核已被驳回"),

    /**
     * 应用流水线执行成功
     */
    PIPELINE_EXEC_SUCCESS(1130, "应用流水线执行成功", MessageClassify.SYSTEM, "应用流水线 <sb>${name}</sb> <sb>${title}</sb> 执行成功"),

    /**
     * 应用流水线执行失败
     */
    PIPELINE_EXEC_FAILURE(1140, "应用流水线执行失败", MessageClassify.SYSTEM, "应用流水线 <sb>${name}</sb> <sb>${title}</sb> 执行失败"),

    // -------------------- 导入通知 --------------------

    /**
     * 导入机器成功
     */
    MACHINE_IMPORT_SUCCESS(2010, "导入机器成功", MessageClassify.IMPORT, "您在 <sb>${time}</sb> 进行的机器导入操作执行完成"),

    /**
     * 导入机器失败
     */
    MACHINE_IMPORT_FAILURE(2020, "导入机器失败", MessageClassify.IMPORT, "您在 <sb>${time}</sb> 进行的机器导入操作执行失败"),

    /**
     * 导入机器代理成功
     */
    MACHINE_PROXY_IMPORT_SUCCESS(2030, "导入机器代理成功", MessageClassify.IMPORT, "您在 <sb>${time}</sb> 进行的机器代理导入操作执行完成"),

    /**
     * 导入机器代理失败
     */
    MACHINE_PROXY_IMPORT_FAILURE(2040, "导入机器代理失败", MessageClassify.IMPORT, "您在 <sb>${time}</sb> 进行的机器代理导入操作执行失败"),

    /**
     * 导入日志文件成功
     */
    MACHINE_TAIL_FILE_IMPORT_SUCCESS(2050, "导入日志文件成功", MessageClassify.IMPORT, "您在 <sb>${time}</sb> 进行的日志文件导入操作执行完成"),

    /**
     * 导入日志文件失败
     */
    MACHINE_TAIL_FILE_IMPORT_FAILURE(2060, "导入日志文件失败", MessageClassify.IMPORT, "您在 <sb>${time}</sb> 进行的日志文件导入操作执行失败"),

    ;

    private final Integer type;

    private final String label;

    private final MessageClassify classify;

    private final String template;

    public static MessageType of(Integer type) {
        if (type == null) {
            return null;
        }
        for (MessageType value : values()) {
            if (value.type.equals(type)) {
                return value;
            }
        }
        return null;
    }

}
