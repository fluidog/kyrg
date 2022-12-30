# LDIM 

LDIM (linux dynamic integrity measurement)，其用于保护 linux 系统中动态执行的相关数据，包括内核、模块和进程的代码段及只读段。其实现原理是：周期性的计算相关段完整性，并与基准值进行比较，判断其是否发生变化。

其通过核外模块实现，可以应用于各种 linux 发行版，比如 Kylinos、Ubuntu 等，支持内核版本 >= 4.19。

## 快速使用

考虑到对性能的影响，需要通过策略来决定对哪些对象进行度量，默认为空。

1. 编译并插入模块
   
   ```bash
   make && insmod ldim.ko
   ```

2. 添加进程防护对象，格式：add \<path> \<enforce>

   ```bash
   # 添加保护 /usr/bin/bash 生成的进程。发现进程窜改后，杀死进程。
   echo "add /usr/bin/bash 1" > /sys/kernel/security/ldim/policy_processes
   # 查看并验证相关度量信息
   cat /sys/kernel/security/ldim/policy_processes
   ```

3. 添加模块防护对象，格式：add \<mod> \<enforce>

   ```bash
   # 添加保护模块 ldim
   echo "add ldim 0" > /sys/kernel/security/ldim/policy_modules
   # 查看并验证
   cat /sys/kernel/security/ldim/policy_modules
   ```

4. 设置防护周期

   ```bash
   echo 10 > /sys/kernel/security/ldim/interval
   ```

5. 打开防护功能

   ```bash
   echo 1 > /sys/kernel/security/ldim/status
   ```

## 功能性测试

为了快速验证动态防护相关功能正常，本模块提供相关测试工具。在源码根目录下执行 `make test`，会自动进行测试，相关测试原理及流程见： [动态防护功能测试](./test/README.md)。

## 性能测试



## 详细设计


详细设计文档见：[ 动态防护文档 ](https://fluidog.notion.site/1cfbfb77ca7d417695590386290594cd)
