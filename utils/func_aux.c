#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/uaccess.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <linux/spinlock.h>  // for spin_lock, spin_unlock
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/cred.h>
#include <linux/dirent.h>
#include <linux/stat.h>
#include "func_aux.h"

MODULE_AUTHOR("Luca Di Marco");
MODULE_DESCRIPTION("Aux function for the reference monitor");
MODULE_LICENSE("GPL");



char *find_directory(char *path) {
    int i = strlen(path) - 1;
    char *new_string = kmalloc(strlen(path) + 1, GFP_KERNEL);
    if (new_string == NULL) {
        printk(KERN_ERR "Failed to allocate memory for new_string\n");
        return NULL;
    }

    strcpy(new_string, path);

    while (i >= 0) {
        if (path[i] != '/') {
            new_string[i] = '\0';
        } else {
            new_string[i] = '\0';
            break;
        }
        i--;
    }

    if (i < 0) {
        kfree(new_string);
        return NULL;
    }

    return new_string;
}

//Path user in path kernel
char *full_path(int dfd, const __user char *user_path) {
    struct path path_struct;
    char *tpath;
    char *path;
    int error = -EINVAL, flag = 0;
    unsigned int lookup_flags = 0;

    tpath = kmalloc(1024, GFP_KERNEL);
    if (tpath == NULL) {
        printk(KERN_ERR "Failed to allocate memory for tpath\n");
        return NULL;
    }

    //resolving user path to kernel path with user_path_at
    if (!(flag & AT_SYMLINK_NOFOLLOW)) lookup_flags |= LOOKUP_FOLLOW;
    error = user_path_at(dfd, user_path, lookup_flags, &path_struct);
    if (error) {
        //printk(KERN_ERR "user_path_at failed with error: %d\n", error);
        kfree(tpath);
        return NULL;
    }

    //conversion of the kernel path to string
    path = d_path(&path_struct, tpath, 1024);
    if (IS_ERR(path)) {
        kfree(tpath);
        return NULL;
    }

    path = kstrdup(path, GFP_KERNEL);
    if (!path) {
        printk(KERN_ERR "kstrdup failed to allocate memory\n");
        kfree(tpath);
        return NULL;
    }

    kfree(tpath);
    return path;
}

//search for the absolute path of the current working dir for the current process
char *get_pwd(void) {
    struct path abs_path;
    char *buf, *full_path;

    buf = kmalloc(1024, GFP_KERNEL);
    if (buf == NULL) {
        printk(KERN_ERR "Failed to allocate memory for buf\n");
        return NULL;
    }

    //retrieve the current working directory of the process
    get_fs_pwd(current->fs, &abs_path);

    //dentry conversion
    full_path = dentry_path_raw(abs_path.dentry, buf, PATH_MAX);
    if (IS_ERR(full_path)) {
        printk(KERN_ERR "dentry_path_raw failed with error: %ld\n", PTR_ERR(full_path));
        kfree(buf);
        return NULL;
    }

    full_path = kstrdup(full_path, GFP_KERNEL); 
    if (!full_path) {
        printk(KERN_ERR "kstrdup failed to allocate memory\n");
        kfree(buf);
        return NULL;
    }

    kfree(buf);
    return full_path;
}

char *resolve_path(const char *path) {
    char *resolved_path, *token, *tmp;
    char **stack;
    int i, depth = 0;
    size_t len;

    //Stack allocation to keep track of path components
    stack = kmalloc_array(strlen(path) / 2 + 1, sizeof(char *), GFP_KERNEL);
    if (!stack) {
        printk(KERN_ERR "Failed to allocate memory for stack\n");
        return NULL;
    }

    //Copy the path for tokenization
    tmp = kstrdup(path, GFP_KERNEL);
    if (!tmp) {
        printk(KERN_ERR "Failed to allocate memory for path copy\n");
        kfree(stack);
        return NULL;
    }

    //Path tokenization
    token = strsep(&tmp, "/");
    while (token) {
        if (strcmp(token, ".") == 0) {
            //Ignore '.' (stay in the same directory)
        } else if (strcmp(token, "..") == 0) {
            if (depth > 0) {
                //Go back to the previous directory
                depth--;
            }
        } else if (strlen(token) > 0) {
            //Add the token to the stack
            stack[depth++] = token;
        }
        token = strsep(&tmp, "/");
    }

    //Calculation of path length solved
    len = 1; //for the initial slash
    for (i = 0; i < depth; i++) {
        len += strlen(stack[i]) + 1;
    }

    //Memory allocation for the resolved path
    resolved_path = kmalloc(len, GFP_KERNEL);
    if (!resolved_path) {
        printk(KERN_ERR "Failed to allocate memory for resolved_path\n");
        kfree(stack);
        kfree(tmp);
        return NULL;
    }

    //Construction of the resolved path
    resolved_path[0] = '/';
    resolved_path[1] = '\0';
    for (i = 0; i < depth; i++) {
        strcat(resolved_path, stack[i]);
        if (i < depth - 1) {
            strcat(resolved_path, "/");
        }
    }

    kfree(stack);
    kfree(tmp);

    return resolved_path;
}

char *get_absolute_path(const char *user_path) {
    char *abs_path;
    char *current_dir;
    char *resolved_path;
    size_t len;

    //Is alredy absolute path
    if (user_path[0] == '/') {
        return resolve_path(user_path);
    }

    //Get the path to the current working directory
    current_dir = get_pwd();
    if (!current_dir) {
        printk(KERN_ERR "Failed to retrieve current working directory\n");
        return NULL;
    }

    //Calculate the length of the final absolute path
    len = strlen(current_dir) + strlen(user_path) + 2; // 1 for slash, 1 for null terminator
    abs_path = kmalloc(len, GFP_KERNEL);
    if (!abs_path) {
        printk(KERN_ERR "Failed to allocate memory for abs_path\n");
        kfree(current_dir);
        return NULL;
    }

    //Construct the absolute path
    snprintf(abs_path, len, "%s/%s", current_dir, user_path);

    //Resolves ".." and "." components of the route
    resolved_path = resolve_path(abs_path);
    if (!resolved_path) {
        printk(KERN_ERR "Failed to resolve full path\n");
        kfree(abs_path);
        kfree(current_dir);
        return NULL;
    }

    kfree(current_dir);
    kfree(abs_path);
    return resolved_path;
}



