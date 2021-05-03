package com.orion.ops.controller;

import com.orion.lang.wrapper.DataGrid;
import com.orion.ops.annotation.RestWrapper;
import com.orion.ops.entity.request.MachineEnvRequest;
import com.orion.ops.entity.vo.MachineEnvVO;
import com.orion.ops.service.api.MachineEnvService;
import com.orion.ops.utils.Valid;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;

/**
 * 环境变量
 *
 * @author Jiahang Li
 * @version 1.0.0
 * @since 2021/4/15 10:06
 */
@RestController
@RestWrapper
@RequestMapping("/orion/api/env")
public class MachineEnvController {

    @Resource
    private MachineEnvService machineEnvService;

    /**
     * 添加
     */
    @RequestMapping("/add")
    public Long add(@RequestBody MachineEnvRequest request) {
        request.setId(null);
        this.check(request);
        return machineEnvService.addUpdateEnv(request);
    }

    /**
     * 更新
     */
    @RequestMapping("/update")
    public Integer update(@RequestBody MachineEnvRequest request) {
        Valid.notNull(request.getId());
        this.check(request);
        return machineEnvService.addUpdateEnv(request).intValue();
    }

    /**
     * 删除
     */
    @RequestMapping("/delete")
    public Integer delete(@RequestBody MachineEnvRequest request) {
        Valid.notNull(request.getId());
        return machineEnvService.deleteById(request);
    }

    /**
     * 列表
     */
    public DataGrid<MachineEnvVO> list(@RequestBody MachineEnvRequest request) {
        return machineEnvService.listEnv(request);
    }

    /**
     * 合法校验
     */
    private void check(MachineEnvRequest request) {
        Valid.notBlank(request.getKey());
        Valid.notNull(request.getValue());
        Valid.notNull(request.getMachineId());
    }

    // 批量删除
    // diff
    // merge

}
