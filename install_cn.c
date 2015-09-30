/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"
#include "install.h"
#include "mincrypt/rsa.h"
#include "minui/minui.h"
#include "minzip/SysUtil.h"
#include "minzip/Zip.h"
#include "mounts.h"
#include "mtdutils/mtdutils.h"
#include "roots.h"
#include "verifier.h"
#include "recovery_ui.h"

#include "firmware.h"

#include "extendedcommands.h"
#include "propsrvc/legacy_property_service.h"

#define ASSUMED_UPDATE_BINARY_NAME  "META-INF/com/google/android/update-binary"
#define ASSUMED_UPDATE_SCRIPT_NAME  "META-INF/com/google/android/update-script"
#define PUBLIC_KEYS_FILE "/res/keys"

// The update binary ask us to install a firmware file on reboot.  Set
// that up.  Takes ownership of type and filename.
static int
handle_firmware_update(char* type, char* filename, ZipArchive* zip) {
    unsigned int data_size;
    const ZipEntry* entry = NULL;

    if (strncmp(filename, "PACKAGE:", 8) == 0) {
        entry = mzFindZipEntry(zip, filename+8);
        if (entry == NULL) {
            LOGE("无法在刷机包中找到 \"%s\"", filename+8);
            return INSTALL_ERROR;
        }
        data_size = entry->uncompLen;
    } else {
        struct stat st_data;
        if (stat(filename, &st_data) < 0) {
            LOGE("统计时出错 %s: %s\n", filename, strerror(errno));
            return INSTALL_ERROR;
        }
        data_size = st_data.st_size;
    }

    LOGI("类型为 %s; 大小为 %d; 文件为 %s\n",
         type, data_size, filename);

    char* data = malloc(data_size);
    if (data == NULL) {
        LOGI("无法为固件数据分配 %d 字节的空间\n", data_size);
        return INSTALL_ERROR;
    }

    if (entry) {
        if (mzReadZipEntry(zip, entry, data, data_size) == false) {
            LOGE("无法读取刷机包中的 \"%s\"", filename+8);
            return INSTALL_ERROR;
        }
    } else {
        FILE* f = fopen(filename, "rb");
        if (f == NULL) {
            LOGE("无法打开 %s: %s\n", filename, strerror(errno));
            return INSTALL_ERROR;
        }
        if (fread(data, 1, data_size, f) != data_size) {
            LOGE("无法读取固件数据: %s\n", strerror(errno));
            return INSTALL_ERROR;
        }
        fclose(f);
    }

    if (remember_firmware_update(type, data, data_size)) {
        LOGE("无法保存 %s 镜像\n", type);
        free(data);
        return INSTALL_ERROR;
    }

    free(filename);

    return INSTALL_SUCCESS;
}

static const char *LAST_INSTALL_FILE = "/cache/recovery/last_install";
static const char *DEV_PROP_PATH = "/dev/__properties__";
static const char *DEV_PROP_BACKUP_PATH = "/dev/__properties_backup__";
static bool legacy_props_env_initd = false;
static bool legacy_props_path_modified = false;

static int set_legacy_props() {
    if (!legacy_props_env_initd) {
        if (legacy_properties_init() != 0)
            return -1;

        char tmp[32];
        int propfd, propsz;
        legacy_get_property_workspace(&propfd, &propsz);
        sprintf(tmp, "%d,%d", dup(propfd), propsz);
        setenv("ANDROID_PROPERTY_WORKSPACE", tmp, 1);
        legacy_props_env_initd = true;
    }

    if (rename(DEV_PROP_PATH, DEV_PROP_BACKUP_PATH) != 0) {
        LOGE("无法重命名属性设置文件路径：%s\n", DEV_PROP_PATH);
        return -1;
    } else {
        legacy_props_path_modified = true;
    }

    return 0;
}

static int unset_legacy_props() {
    if (rename(DEV_PROP_BACKUP_PATH, DEV_PROP_PATH) != 0) {
        LOGE("无法重命名属性设置文件路径：%s\n", DEV_PROP_BACKUP_PATH);
        return -1;
    } else {
        legacy_props_path_modified = false;
    }

    return 0;
}

// If the package contains an update binary, extract it and run it.
static int
try_update_binary(const char *path, ZipArchive *zip) {
#ifdef BOARD_NATIVE_DUALBOOT_SINGLEDATA
	int rc;
	if((rc=device_truedualboot_before_update(path, zip))!=0)
		return rc;
#endif

    const ZipEntry* binary_entry =
            mzFindZipEntry(zip, ASSUMED_UPDATE_BINARY_NAME);
    if (binary_entry == NULL) {
        const ZipEntry* update_script_entry =
                mzFindZipEntry(zip, ASSUMED_UPDATE_SCRIPT_NAME);
        if (update_script_entry != NULL) {
            ui_print("Amend 格式的脚本(update-script)现在已不被支持。\n");
            ui_print("Amend 格式的脚本自 Android 1.5 起已被谷歌取消支持。\n");
            ui_print("当使用高于 3.0 版本的 ClockworkMod 时，需要移除 Amend 格式的脚本。\n");
            ui_print("请将脚本转换为 Edify 格式的脚本(updater-script 加 update-binary)以便做出可以使用的刷机包。\n");

            return INSTALL_UPDATE_BINARY_MISSING;
        }

        mzCloseZipArchive(zip);
        return INSTALL_UPDATE_BINARY_MISSING;
    }

    char* binary = "/tmp/update_binary";
    unlink(binary);
    int fd = creat(binary, 0755);
    if (fd < 0) {
        mzCloseZipArchive(zip);
        LOGE("无法创建 %s\n", binary);
        return 1;
    }
    bool ok = mzExtractZipEntryToFile(zip, binary_entry, fd);
    close(fd);

    if (!ok) {
        LOGE("无法复制 %s\n", ASSUMED_UPDATE_BINARY_NAME);
        mzCloseZipArchive(zip);
        return 1;
    }

    /* Make sure the update binary is compatible with this recovery
     *
     * We're building this against 4.4's (or above) bionic, which
     * has a different property namespace structure. If "set_perm_"
     * is found, it's probably a regular updater instead of a custom
     * one. If "set_metadata_" isn't there, it's pre-4.4, which
     * makes it incompatible.
     *
     * Also, I hate matching strings in binary blobs */

    FILE *updaterfile = fopen(binary, "rb");
    char tmpbuf;
    char setpermmatch[9] = { 's','e','t','_','p','e','r','m','_' };
    char setmetamatch[13] = { 's','e','t','_','m','e','t','a','d','a','t','a','_' };
    size_t pos = 0;
    bool foundsetperm = false;
    bool foundsetmeta = false;

    if (updaterfile == NULL) {
        LOGE("找不到%s文件检测\n", ASSUMED_UPDATE_BINARY_NAME);
        return 1;
    }
    fseek(updaterfile, 0, SEEK_SET);
    while (!feof(updaterfile)) {
        fread(&tmpbuf, 1, 1, updaterfile);
        if (!foundsetperm && pos < sizeof(setpermmatch) && tmpbuf == setpermmatch[pos]) {
            pos++;
            if (pos == sizeof(setpermmatch)) {
                foundsetperm = true;
                pos = 0;
            }
            continue;
        }
        if (!foundsetmeta && tmpbuf == setmetamatch[pos]) {
            pos++;
            if (pos == sizeof(setmetamatch)) {
                foundsetmeta = true;
                pos = 0;
            }
            continue;
        }
        /* None of the match loops got a continuation, reset the counter */
        pos = 0;
    }
    fclose(updaterfile);

    /* Set legacy properties */
    if (foundsetperm && !foundsetmeta) {
        LOGI("为 update-binary 使用旧版属性环境...\n");
        if (set_legacy_props() != 0) {
            LOGE("旧版属性环境初始化失败。可能未检测到属性设置文件。\n");
        } else {
            LOGI("已初始化旧版属性环境。\n");

        }
    }

    int pipefd[2];
    pipe(pipefd);

    // When executing the update binary contained in the package, the
    // arguments passed are:
    //
    //   - the version number for this interface
    //
    //   - an fd to which the program can write in order to update the
    //     progress bar.  The program can write single-line commands:
    //
    //        progress <frac> <secs>
    //            fill up the next <frac> part of of the progress bar
    //            over <secs> seconds.  If <secs> is zero, use
    //            set_progress commands to manually control the
    //            progress of this segment of the bar
    //
    //        set_progress <frac>
    //            <frac> should be between 0.0 and 1.0; sets the
    //            progress bar within the segment defined by the most
    //            recent progress command.
    //
    //        firmware <"hboot"|"radio"> <filename>
    //            arrange to install the contents of <filename> in the
    //            given partition on reboot.
    //
    //            (API v2: <filename> may start with "PACKAGE:" to
    //            indicate taking a file from the OTA package.)
    //
    //            (API v3: this command no longer exists.)
    //
    //        ui_print <string>
    //            display <string> on the screen.
    //
    //   - the name of the package zip file.
    //

    char** args = malloc(sizeof(char*) * 5);
    args[0] = binary;
    args[1] = EXPAND(RECOVERY_API_VERSION);   // defined in Android.mk
    args[2] = malloc(10);
    sprintf(args[2], "%d", pipefd[1]);
    args[3] = (char*)path;
    args[4] = NULL;

    pid_t pid = fork();
    if (pid == 0) {
        setenv("UPDATE_PACKAGE", path, 1);
        close(pipefd[0]);
        execve(binary, args, environ);
        fprintf(stdout, "E:Can't run %s (%s)\n", binary, strerror(errno));
        _exit(-1);
    }
    close(pipefd[1]);

    char* firmware_type = NULL;
    char* firmware_filename = NULL;

    char buffer[1024];
    FILE* from_child = fdopen(pipefd[0], "r");
    while (fgets(buffer, sizeof(buffer), from_child) != NULL) {
        char* command = strtok(buffer, " \n");
        if (command == NULL) {
            continue;
        } else if (strcmp(command, "progress") == 0) {
            char* fraction_s = strtok(NULL, " \n");
            char* seconds_s = strtok(NULL, " \n");

            float fraction = strtof(fraction_s, NULL);
            int seconds = strtol(seconds_s, NULL, 10);

            ui_show_progress(fraction * (1-VERIFICATION_PROGRESS_FRACTION),
                             seconds);
        } else if (strcmp(command, "set_progress") == 0) {
            char* fraction_s = strtok(NULL, " \n");
            float fraction = strtof(fraction_s, NULL);
            ui_set_progress(fraction);
        } else if (strcmp(command, "firmware") == 0) {
            char* type = strtok(NULL, " \n");
            char* filename = strtok(NULL, " \n");

            if (type != NULL && filename != NULL) {
                if (firmware_type != NULL) {
                    LOGE("忽略多个固件更新的操作");
                } else {
                    firmware_type = strdup(type);
                    firmware_filename = strdup(filename);
                }
            }
        } else if (strcmp(command, "ui_print") == 0) {
            char* str = strtok(NULL, "\n");
            if (str) {
                ui_print("%s", str);
            } else {
                ui_print("\n");
            }
        } else {
            LOGE("未知命令 [%s]\n", command);
        }
    }
    fclose(from_child);

    int status;
    waitpid(pid, &status, 0);

    /* Unset legacy properties */
    if (legacy_props_path_modified) {
        if (unset_legacy_props() != 0) {
            LOGE("未成功禁用旧版属性环境。旧版属性环境可能仍然在使用中。\n");
        } else {
            LOGI("已禁用旧版属性环境。n");

        }
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        LOGE("%s 中出错\n(状态 %d)\n", path, WEXITSTATUS(status));
        mzCloseZipArchive(zip);
        return INSTALL_ERROR;
    }

    if (firmware_type != NULL) {
        int ret = handle_firmware_update(firmware_type, firmware_filename, zip);
        mzCloseZipArchive(zip);
        return ret;
    }
    mzCloseZipArchive(zip);
    return INSTALL_SUCCESS;
}

static int
really_install_package(const char *path)
{
    ui_set_background(BACKGROUND_ICON_INSTALLING);
    ui_print("找到刷机包...\n");
    ui_show_indeterminate_progress();
    ensure_path_unmounted("/system");

    // Resolve symlink in case legacy /sdcard path is used
    // Requires: symlink uses absolute path
    char new_path[PATH_MAX];
    if (strlen(path) > 1) {
        char *rest = strchr(path + 1, '/');
        if (rest != NULL) {
            int readlink_length;
            int root_length = rest - path;
            char *root = malloc(root_length + 1);
            strncpy(root, path, root_length);
            root[root_length] = 0;
            readlink_length = readlink(root, new_path, PATH_MAX);
            if (readlink_length > 0) {
                strncpy(new_path + readlink_length, rest, PATH_MAX - readlink_length);
                path = new_path;
            }
            free(root);
        }
    }

    LOGI("刷机包位置: %s\n", path);

    if (ensure_path_mounted(path) != 0) {
        LOGE("无法挂载 %s\n", path);
        return INSTALL_CORRUPT;
    }

    ui_print("打开刷机包...\n");

    int err;

    if (signature_check_enabled) {
        int numKeys;
        Certificate* loadedKeys = load_keys(PUBLIC_KEYS_FILE, &numKeys);
        if (loadedKeys == NULL) {
            LOGE("无法载入密钥\n");
            return INSTALL_CORRUPT;
        }
        LOGI("%d 个密钥已从 %s 中载入\n", numKeys, PUBLIC_KEYS_FILE);

        // Give verification half the progress bar...
        ui_print("正在校验刷机包...\n");
        ui_show_progress(
                VERIFICATION_PROGRESS_FRACTION,
                VERIFICATION_PROGRESS_TIME);

        err = verify_file(path, loadedKeys, numKeys);
        free(loadedKeys);
        LOGI("verify_file 返回 %d\n", err);
        if (err != VERIFY_SUCCESS) {
            LOGE("签名校验失败\n");
            ui_show_text(1);
            if (!confirm_selection("安装不受信任的刷机包？", "是 - 安装"))
                return INSTALL_CORRUPT;
        }
    }

    /* Try to open the package.
     */
    ZipArchive zip;
    err = mzOpenZipArchive(path, &zip);
    if (err != 0) {
        LOGE("无法打开 %s\n(%s)\n", path, err != -1 ? strerror(err) : "已损坏");
        return INSTALL_CORRUPT;
    }

    /* Verify and install the contents of the package.
     */
    ui_print("正在安装刷机包...\n");
    return try_update_binary(path, &zip);
}

int
install_package(const char* path)
{
    FILE* install_log = fopen_path(LAST_INSTALL_FILE, "w");
    if (install_log) {
        fputs(path, install_log);
        fputc('\n', install_log);
    } else {
        LOGE("无法打开 last_install: %s\n", strerror(errno));
    }
    int result = really_install_package(path);
    if (install_log) {
        fputc(result == INSTALL_SUCCESS ? '1' : '0', install_log);
        fputc('\n', install_log);
        fclose(install_log);
        chmod(LAST_INSTALL_FILE, 0644);
    }
    return result;
}
