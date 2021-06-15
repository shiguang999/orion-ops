package com.orion.ops.service.api;

import com.orion.lang.wrapper.HttpWrapper;
import com.orion.ops.consts.file.FileDownloadType;
import com.orion.ops.entity.request.FileTailRequest;

/**
 * 文件下载service
 *
 * @author Jiahang Li
 * @version 1.0.0
 * @since 2021/6/8 17:21
 */
public interface FileService {

    /**
     * 下载文件 检查文件是否存在
     *
     * @param id   id
     * @param type type
     * @return token
     */
    HttpWrapper<String> getDownloadToken(Long id, FileDownloadType type);

    /**
     * 通过token获取下载文件路径
     *
     * @param token token
     * @return path
     */
    String getPathByDownloadToken(String token);

    /**
     * tail文件 检查文件是否存在
     *
     * @param request request
     * @return token
     */
    HttpWrapper<String> getTailToken(FileTailRequest request);

}
