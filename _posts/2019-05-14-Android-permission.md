---
layout: post
title:  "Android 权限系统（应用沙箱）"
date:   2019-05-14 10:27:23
---

前两年做系统权限相关工作时候的一些总结，整理记录一下。

Android系统为每个应用程序提供了一个安全的运行环境，不同程序间相互隔离，应用程序的数据等私有资源，外界无法访问。这个安全的运行环境由Android的权限系统，也可称为沙箱系统来提供。本文简单记录Android权限系统的基本组成模块和实现机制中的关键代码。

## 主要模块

可以将Android权限系统分为4个模块：

1. 基于用户ID的权限系统
2. Capability权限系统
3. Android Permission系统
4. SELinux权限系统

## 基于用户ID的权限系统

该权限系统基于进程的UID来控制进程对文件等资源的访问权限。简单来说，系统中每个进程有一个UID和一个或多个GID属性；每个文件具有一个UID和一个GID属性，并且有三组权限位，分别表示和自己相同的UID进程、相同的GID进程，以及其他不相关进程对文件的读、写和执行访问权限。内核以UID作为权限管理的基本粒度单位。关于进程对文件的具体访问权限规则，可以查阅UNIX/Linux手册或一些书籍。（《UNIX环境高级编程》4.5节）。

在典型的UNIX/Linux多用户系统中，系统为每个登录用户分配一个UID，所以权限控制的粒度是单个用户。Android系统没有传统意义登录用户的概念，而是将UID分配给每个应用程序，所以权限管理的粒度是单个应用程序。具体运行过程如下。

1. 应用程序安装时，系统为应用程序分配一个UID。PackageManagerService默认为每个应用程序分配一个新的UID和GID。如果应用程序申请了某些特殊的运行时权限，则为其分配（实际是将其加入）一组额外的GID Group。同一个开发者开发的两个应用（签名相同），可以共享UID和GID，只需要在AndroidManifest中声明同样的`android:sharedUserId`属性。应用程序的UID/GID和其他属性一起写入`packages.list`和`packages.xml`文件中。

   ```Java
   // PMS分配UID代码：
   // PackageManagerService.java
   if (newPkgSettingCreated) {
            if (originalPkgSetting != null) {
                mSettings.addRenamedPackageLPw(pkg.packageName, originalPkgSetting.name);
            }
            // THROWS: when we can't allocate a user id. add call to check if there's
            // enough space to ensure we won't throw; otherwise, don't modify state
            mSettings.addUserToSettingLPw(pkgSetting);
   ```

2. 启动应用程序进程时，ActivityManagerService向PackageManagerService查询应用程序的UID/GID等信息，并将这些信息作为参数传递给Zygote进程。Zygote进程为应用程序fork出子进程，并按照参数设置子进程的UID/GID，这样应用程序进程就以自己所属UID的身份运行了。

   ```Java
   // AMS 传递参数给Zygote
   // ActivityManagerService.java
   private ProcessStartResult startProcess(String hostingType, String entryPoint,
            ProcessRecord app, int uid, int[] gids, int runtimeFlags, int mountExternal,
            String seInfo, String requiredAbi, String instructionSet, String invokeWith,
            long startTime) {
        try {
            ...
            } else {
                startResult = Process.start(entryPoint,
                        app.processName, uid, uid, gids, runtimeFlags, mountExternal,
                        app.info.targetSdkVersion, seInfo, requiredAbi, instructionSet,
                        app.info.dataDir, invokeWith,
                        new String[] {PROC_START_SEQ_IDENT + app.startSeq});
            }
            ...
   }

   // Zygote 根据参数设置进程UID属性
   // com_android_internal_os_Zygote.cpp
   static pid_t ForkAndSpecializeCommon(JNIEnv* env, uid_t uid, gid_t gid, jintArray javaGids,
                                     jint runtime_flags, jobjectArray javaRlimits,
                                     jlong permittedCapabilities, jlong effectiveCapabilities,
                                     jint mount_external,
                                     jstring java_se_info, jstring java_se_name,
                                     bool is_system_server, jintArray fdsToClose,
                                     jintArray fdsToIgnore, bool is_child_zygote,
                                     jstring instructionSet, jstring dataDir) {
      ...
      pid_t pid = fork();

      if (pid == 0) {
        ...
        if (!SetGids(env, javaGids, &error_msg)) {
          fail_fn(error_msg);
        }
        ...
        int rc = setresgid(gid, gid, gid);
        ...
        rc = setresuid(uid, uid, uid);
        ...
      }
   ```

3. 设置应用程序的文件权限

   a. 设置APK文件权限为所有用户可读，这样系统或者别的应用程序才可以访问应用程序的代码。

   b. 系统为应用程序创建的数据目录，设置为其他用户可执行（搜索）。如果不设置为可执行，则用户的任何数据文件不能共享给其他应用程序。

      ```Java
      // ContextImpl.java
      public FileOutputStream openFileOutput(String name, int mode) throws FileNotFoundException {
        checkMode(mode);
        final boolean append = (mode&MODE_APPEND) != 0;
        File f = makeFilename(getFilesDir(), name);
        ...
        File parent = f.getParentFile();
        parent.mkdir();
        FileUtils.setPermissions(
            parent.getPath(),
            FileUtils.S_IRWXU|FileUtils.S_IRWXG|FileUtils.S_IXOTH,
            -1, -1);
      ```

   c. 应用通过Context.openFileOutput等Android接口创建的数据文件默认为其他用户不可读写。如果用户指定了`MODE_WORLD_READABLE`或者 `MODE_WORLD_WRITEABLE`，则设置其他用户可读或者可写。新版本这两个mode已经废除。

      ```Java
      // ContextImpl.java
      public FileOutputStream openFileOutput(String name, int mode) throws FileNotFoundException {
          checkMode(mode);
          final boolean append = (mode&MODE_APPEND) != 0;
          File f = makeFilename(getFilesDir(), name);
          ...
          setFilePermissionsFromMode(f.getPath(), mode, 0);
          return fos;
      }
      static void setFilePermissionsFromMode(String name, int mode,
          int extraPermissions) {
          int perms = FileUtils.S_IRUSR|FileUtils.S_IWUSR
              |FileUtils.S_IRGRP|FileUtils.S_IWGRP
              |extraPermissions;
          if ((mode&MODE_WORLD_READABLE) != 0) {
              perms |= FileUtils.S_IROTH;
          }
          if ((mode&MODE_WORLD_WRITEABLE) != 0) {
              perms |= FileUtils.S_IWOTH;
          }
          if (DEBUG) {
              Log.i(TAG, "File " + name + ": mode=0x" + Integer.toHexString(mode)
                    + ", perms=0x" + Integer.toHexString(perms));
          }
          FileUtils.setPermissions(name, perms, -1, -1);
      }
      ```

   d. 应用通过File.createNewFile()等Java接口创建的数据文件默认只有自己可读写。这种方式创建的文件权限与当前进程的umask设置相关。Android系统的init进程在创建系统服务（包括zygote）时，设置了umask为077，应用程序继承了zygote的umask，所以也是077，表示只保留相同UID的访问权限，仅允许相同UID的进程（也就是自己）访问。

      ```C++
      // system/core/init/service.cpp
      Result<Success> Service::Start() {
        ...
        pid = fork();
        if (pid == 0) {
          umask(077);
          ...
      }
      ```

## Capability 机制

基于UID的权限管理机制中，有一个特殊的UID 0，即所谓root用户，具有超级权限，不受权限机制的约束。而有些系统资源和能力，只有root用户才可以使用。所以系统中很多核心服务，如adbd，zygote以root身份运行，而这些系统服务又频繁与应用程序交互，这些服务中存在的安全漏洞，很容易被恶意应用程序利用，进行提权操作，突破系统权限管控。所以Android进一步使用capability机制来限制UID 0的权限。

Capability机制将只有root用户可以访问的权限进一步细分为一组能力。每个线程有四组比特位来表示自身所拥有的权限:

```Shell
$ adb shell cat /proc/<pid>/status
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 0000000000000000
```

其中CapInh表示执行execve会保留的权限；CapEff表示线程当前权限；CapPrm表示CapInh和CapEff的最大限制；CapBnd表示线程能够获得的最大权限。

Android系统中，adbd和zygote是为应用创建进程的服务。zygote服务在创建了子进程，将子进程返回给系统前，将CapBnd情况，这样即使子进程利用系统漏洞获取了root uid，仍然没有任何超级权限。adbd则在执行完必须的特权任务后，清除CapBnd，将自己权限降低。

```Java
// Zygote 设置子进程CapBnd
// com_android_internal_os_Zygote.cpp
static pid_t ForkAndSpecializeCommon(JNIEnv* env, uid_t uid, gid_t gid, jintArray javaGids,
                                     jint runtime_flags, jobjectArray javaRlimits,
                                     jlong permittedCapabilities, jlong effectiveCapabilities,
                                     jint mount_external,
                                     jstring java_se_info, jstring java_se_name,
                                     bool is_system_server, jintArray fdsToClose,
                                     jintArray fdsToIgnore, bool is_child_zygote,
                                     jstring instructionSet, jstring dataDir) {
  ...
  pid_t pid = fork();
  if (pid == 0) {
    ...
    if (!DropCapabilitiesBoundingSet(&error_msg)) {
      fail_fn(error_msg);
    }
    ...
```

## Android Permission系统

应用默认只能访问自己的文件和非常少量的系统资源。想要获取更多系统和其他应用的资源，需要使用权限机制。

资源/服务提供者通过AndroidManifest显式要求调用者的权限; 应用在manifest中申请权限，系统在安装或运行时确定授予哪些权限。

### Permission的定义

Android Permission可以分为三种类型，每种类型permission的定义方式如下：

1. Builtin permission

   系统在`/etc/permissions/*.xml`中定义。每个权限对应一个GID。

   ```xml
   // /etc/permissions/platform.xml
   <permission name="android.permission.INTERNET" >
        <group gid="inet" />
    </permission>
   <permission name="android.permission.WRITE_MEDIA_STORAGE" >
        <group gid="media_rw" />
    </permission>
   ```

   系统每授予应用一个内置权限, 就给应用添加一个对应的GID到应用的添加组ID groups中

   ```Java
   // PermissionsState.java
   private int grantPermission(BasePermission permission, int userId) {
        if (hasPermission(permission.getName(), userId)) {
            return PERMISSION_OPERATION_FAILURE;
        }

        final boolean hasGids = !ArrayUtils.isEmpty(permission.computeGids(userId));
        final int[] oldGids = hasGids ? computeGids(userId) : NO_GIDS;
        ...
   ```

2. Normal

   Normal permission是系统(android package)，系统应用以及第三方应用在自己的AndroidManifest中定义的权限。例如`READ_CONTACTS`等系统权限是在framework-res.apk的AndroidManifest中定义。

   ```xml
   // frameworks/base/core/res/AndroidManifest.xml
   <permission-group android:name="android.permission-group.CONTACTS"
        android:icon="@drawable/perm_group_contacts"
        android:label="@string/permgrouplab_contacts"
        android:description="@string/permgroupdesc_contacts"
        android:request="@string/permgrouprequest_contacts"
        android:priority="100" />

    <!-- Allows an application to read the user's contacts data.
        <p>Protection level: dangerous
    -->
    <permission android:name="android.permission.READ_CONTACTS"
        android:permissionGroup="android.permission-group.CONTACTS"
        android:label="@string/permlab_readContacts"
        android:description="@string/permdesc_readContacts"
        android:protectionLevel="dangerous" />
   ```

3. Dynamic

   可以动态添加定义的权限。参考[android developer](https://developer.android.com/guide/topics/manifest/permission-tree-element.html)

### Permission 校验

1. Buildtin permission在内核函数中显式校验，或者通过基于UID的权限机制进行校验。

   内核中对INTERNET权限的校验

   ```c
   //
   // af_inet.c
   #ifdef CONFIG_ANDROID_PARANOID_NETWORK
   #include <linux/android_aid.h>

   static inline int current_has_network(void)
   {
     return in_egroup_p(AID_INET) || capable(CAP_NET_RAW);
   }
   static int inet_create(struct net *net, struct socket *sock, int protocol,
             int kern)
   {
     ...
     if (!current_has_network())
       return -EACCES;
   ```

   基于UID的权限校验。以sdcard读写权限为例，sdcard目录权限设置为sdcard_rw组可读写（每个进程看到的权限不一样，这里以shell用户为例）。只有获得了`WRITE_MEDIA_STORAGE`权限，才能获得`sdcard_rw` GID，才能访问sdcard目录。

   ```shell
   adb shell ls -l /sdcard/
   total 112
   drwxrwx--x 2 root sdcard_rw 4096 2008-12-31 21:31 Alarms
   drwxrwx--x 3 root sdcard_rw 4096 2008-12-31 21:31 Android
   drwxrwx--x 2 root sdcard_rw 4096 2008-12-31 21:31 DCIM
   ```

2. Normal和dynamic权限的校验

   分两种情况。对于Activity，Service等程序组件的权限访问，由AMS调用权限检查函数判断是否具有合法权限。

   对于对外提供服务的系统Service或者应用service，可以在功能函数中自己调用权限检查函数检查调用者是否具有权限。

   ```Java
   PackageManager.checkPermission()
   Context.checkPermission()
   ```

## SELinux

SELinux在8.0及以后为了兼容treble，做了较大的改动，这里仅总结记录一下8.0之前官方文档中所描述的一些概念和原理。

### 基本 概念

1. 强制访问控制 MAC

   - SELinux是Linux系统上的一个强制访问控制系统，相对于已经熟悉的DAC（自主访问控制）
   - 自主访问控制中，每个资源具有属主，即资源所有者，属主可以控制资源的访问权限。这通常是粗粒度的并且易于导致错误的权限扩散
   - MAC集中管理资源的访问权限，不存在DAC的问题
   - SELinux实现为LSM的一部分

2. Enforcement levels

   - 工作模式
     - Permissive - Only logged
     - Enforcing - Enforced and logged
   - Policy type
     - Unconfined - 非常轻量级的策略，限制很少，适用于开发阶段
     - Confined - 定制策略

3. 标签（labels），规则（rules）和域（domains）

   - SELinux中，文件和进程等任何资源都有一个标签，标签和策略一起决定了那些行为是允许的。
   - 标签形如 `user:rule:type:mls_level`，其中type为主要部分。
   - 资源对象被映射为类，对每个类的访问由permission表示
   - rule形如`allow domain types:classes permissions;`，其中各部分含义：
     - domain - 进程的label
     - type - 资源对象的label
     - class - 资源对象的具体类别
     - permission - 执行的访问操作

### 背景和基本原理

- android 4.3开始，SELinux用于加强应用沙盒
- SELinux对所有进程执行强制访问控制，包括root进程
- Enforcing模式下，任何试图违反SELinux安全策略的行为被记录在logcat和dmesg中
- 以默认拒绝方式工作，即任何没有显示允许的行为都被拒绝
- 两种工作模式：permissive vs. enforcing
- 支持per-domain permissive模式
- 实施过程：
  - android 4.3 permissive
  - android 4.4 partial enforcing
  - android 5.0 full enforcing

### 关键文件

- SELinux策略文件在`system/sepolicy`目录。
- 一般不需要直接修改`system/sepolicy`，而是在/device/manufacturer/device-name/sepolicy目录下定义设备相关的策略文件
- 实现SELinux需要修改或创建的文件：
  - 新的策略源文件（*.te） - 定义域及其标签
  - 更新BoardConfig.mk - 使编译系统包含新创建的sepolicy目录
  - `file_contexts` - 定义文件的标签。必须重新编译文件系统或者执行`restorecon`命令使其生效。系统升级会自动更新系统和用户分区。在init.board.rc文件中添加`restorecon_recursive`可以自动更新其他分区。
  - `genfs_contexts` - 为proc, vfat等不支持扩展属性的文件系统设置文件标签。此配置文件作为内核策略的一部分加载。但是需要重启或者卸载并重新装载才能对已经创建的节点生效。
  - `property_contexts` - 设置Android 系统property的标签。此文件由init在系统启动以及selinux.reload_policy设置为1是加载
  - `service_contexts` - 设置Android binder服务的标签，此文件由servicemanager在系统启动以及selinux.reload_policy设置为1时加载
  - `seapp_contexts` - 设置app进程和文件的标签。由zygote进程在app启动以及由installd在系统启动时和selinux.reload_policy设置为1时读取
  - `mac_permissions.xml` - 基于签名和包名为app设置seinfo，`seapp_contexts`使用seinfo来为app设置标签。`system_server`在启动时读取此文件
- 编译系统使用`BOARD_SEPOLICY_DIRS`等变量加入新的策略文件

### 初始化设置

1. Init 初始化

   - init首次运行在kernel domain。即"u:r:kernel:s0"
   - 设置log和audit回调函数
   - 加载/sepolicy策略文件
   - 设置工作模式：如果系统配置允许Permissive模式，则设置为内核命令行参数中指定的模式，否则Enforcing模式
   - 根据`/file_contexts`，设置`/init`label。根文件系统不支持扩展属性，所以需要运行时设置
   - init重新执行自己，此时策略中的转移规则生效，init开始以init domain执行。
   - 设置log和audit回调函数
   - 加载`/file_contexts`和`property_contexts`
   - 根据加载的`/file_contexts`，设置`/dev`，`/dev/socket`等文件系统和目录的label。
   - 由initrc文件控制，在系统启动的各个阶段，对需要的文件系统和目录执行restorecon命令，设置文件label
   - selinux.reload_policy设置为1时，重新加载策略，包括`/sepolicy`,`file_contexts`,`property_contexts`

2. Binder 初始化

   - `servicemanager`服务启动时，从`/service_contexts`文件读取每个service对应的context
   - 打开selinux状态查询接口，用于监控是否reload policy。
   - 设置log和audit回调函数
   - 每次收到binder请求，检查policy是否reload过，如果reload过，则重新加载`/service_contexts`

3. zygote 初始化

   - 每次启动App时，zygote在子进程中通过native函数加载`/seapp_contexts`，计算app进程的context
   - installd每次收到一个新的请求，检查`/seapp_contexts`是否需要更新，如需要则重新加载`/seapp_contexts`文件

4. `system_server` initialization

   - PMS启动时从`/etc/mac_permissions.xml`读取每个包的seinfo信息（如果有的话）。