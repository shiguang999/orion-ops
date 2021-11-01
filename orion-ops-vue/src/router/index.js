import Vue from 'vue'
import VueRouter from 'vue-router'
import Login from '../views/Login'
import Layout from '../components/layout/Layout'

Vue.use(VueRouter)

// 重复点击路由不抛异常
const originalPush = VueRouter.prototype.push
VueRouter.prototype.push = function push(location) {
  return originalPush.call(this, location).catch(err => err)
}

const routes = [
  {
    path: '/login',
    name: 'login',
    meta: {
      requireAuth: false,
      title: '登陆'
    },
    component: Login
  },
  {
    path: '/machine/terminal/:id',
    name: 'terminal',
    meta: {
      requireAuth: true,
      title: 'terminal'
    },
    component: () => import('../views/machine/MachineTerminal')
  },
  {
    path: '/',
    redirect: '/console'
  },
  {
    path: '',
    name: 'layout',
    component: Layout,
    children: [
      {
        path: '/console',
        name: 'console',
        meta: {
          requireAuth: true,
          title: '控制台'
        },
        component: () => import('../views/Console')
      },
      {
        path: '/machine/list',
        name: 'machineList',
        meta: {
          requireAuth: true,
          title: '机器列表'
        },
        component: () => import('../views/machine/MachineList')
      },
      {
        path: '/machine/env',
        name: 'machineEnv',
        meta: {
          requireAuth: true,
          title: '环境变量'
        },
        component: () => import('../views/machine/MachineEnv')
      },
      {
        path: '/machine/key',
        name: 'MachineKey',
        meta: {
          requireAuth: true,
          title: '机器秘钥'
        },
        component: () => import('../views/machine/MachineKey')
      },
      {
        path: '/terminal/session',
        name: 'terminalSession',
        meta: {
          requireAuth: true,
          requireAdmin: true,
          title: '终端控制'
        },
        component: () => import('../views/machine/MachineTerminalSession')
      },
      {
        path: '/machine/proxy',
        name: 'MachineProxy',
        meta: {
          requireAuth: true,
          title: '机器代理'
        },
        component: () => import('../views/machine/MachineProxy')
      },
      {
        path: '/batch/exec',
        name: 'batchExec',
        meta: {
          requireAuth: true,
          title: '批量执行'
        },
        component: () => import('../views/exec/BatchExec')
      },
      {
        path: '/log/view',
        name: 'loggerView',
        meta: {
          requireAuth: true,
          title: '日志面板'
        },
        component: () => import('../views/exec/LoggerView')
      },
      {
        path: '/app/list',
        name: 'appList',
        meta: {
          requireAuth: true,
          title: '应用列表'
        },
        component: () => import('../views/app/AppList')
      },
      {
        path: '/app/profile',
        name: 'appProfile',
        meta: {
          requireAuth: true,
          title: '环境管理'
        },
        component: () => import('../views/app/AppProfile')
      },
      {
        path: '/app/env',
        name: 'appEnv',
        meta: {
          requireAuth: true,
          title: '环境变量'
        },
        component: () => import('../views/app/AppEnv')
      },
      {
        path: '/release/config',
        name: 'releaseConfig',
        meta: {
          requireAuth: true,
          title: '发布配置'
        },
        component: () => import('../views/release/ReleaseConfig')
      },
      {
        path: '/release/bill',
        name: 'releaseBill',
        meta: {
          requireAuth: true,
          title: '发布单'
        },
        component: () => import('../views/release/ReleaseBill')
      },
      {
        path: '/user/list',
        name: 'userList',
        meta: {
          requireAuth: true,
          title: '用户列表'
        },
        component: () => import('../views/user/UserList')
      },
      {
        path: '/user/detail',
        name: 'userDetail',
        meta: {
          requireAuth: true,
          title: '用户详情'
        },
        component: () => import('../views/user/UserDetail')
      },
      {
        path: '/template/list',
        name: 'templateList',
        meta: {
          requireAuth: true,
          title: '模板配置'
        },
        component: () => import('../views/template/TemplateList')
      },
      {
        path: '*',
        name: '404',
        meta: {
          requireAuth: true,
          title: '404'
        },
        component: () => import('../views/404')
      }
    ]
  }

]

const router = new VueRouter({
  routes
})

export default router