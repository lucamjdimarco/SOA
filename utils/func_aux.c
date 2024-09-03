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

MODULE_AUTHOR("Luca Di Marco");
MODULE_DESCRIPTION("Aux function for the reference monitor");
MODULE_LICENSE("GPL");


int strncmp_custom(const char *s1, const char *s2, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        
        if (s1[i] != s2[i]) {
            return s1[i] - s2[i];
        }
        if (s1[i] == '\0' || s2[i] == '\0') {
            break;
        }
    }

    return 0;
}


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

//Convesiona path utente in path kernel
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

    //risoluzione del path user in path kernel con user_path_at
    if (!(flag & AT_SYMLINK_NOFOLLOW)) lookup_flags |= LOOKUP_FOLLOW;
    error = user_path_at(dfd, user_path, lookup_flags, &path_struct);
    if (error) {
        //printk(KERN_ERR "user_path_at failed with error: %d\n", error);
        kfree(tpath);
        return NULL;
    }

    //conversione in stringa del path kernel
    path = d_path(&path_struct, tpath, 1024);
    if (IS_ERR(path)) {
        //printk(KERN_ERR "d_path failed with error: %ld\n", PTR_ERR(path));
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

//ricerca del percorso assoluto della dir di lavoro corrente per processo corrente
char *get_pwd(void) {
    struct path abs_path;
    char *buf, *full_path;

    buf = kmalloc(1024, GFP_KERNEL);
    if (buf == NULL) {
        printk(KERN_ERR "Failed to allocate memory for buf\n");
        return NULL;
    }

    //recuperata la directory di lavoro corrente del processo 
    get_fs_pwd(current->fs, &abs_path);

    //conversione della dentry
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

char *get_absolute_path(const char *user_path) {
    char *abs_path;

    // Se il percorso utente è già assoluto, restituiscilo così com'è
    if (user_path[0] == '/') {
        abs_path = kstrdup(user_path, GFP_KERNEL);
        if (!abs_path) {
            printk(KERN_ERR "Failed to allocate memory for abs_path\n");
            return NULL;
        }
        return abs_path;
    }

    // Recupera il percorso della directory di lavoro corrente
    char *current_dir = get_pwd();
    if (!current_dir) {
        printk(KERN_ERR "Failed to retrieve current working directory\n");
        return NULL;
    }

    // Combina la directory di lavoro corrente con il percorso relativo fornito dall'utente
    abs_path = full_path(AT_FDCWD, user_path);
    if (!abs_path) {
        printk(KERN_ERR "Failed to resolve full path\n");
        kfree(current_dir);
        return NULL;
    }

    kfree(current_dir);
    return abs_path;
}


