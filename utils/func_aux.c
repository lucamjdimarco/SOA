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

char *resolve_path(const char *path) {
    char *resolved_path, *token, *tmp;
    char **stack;
    int i, depth = 0;
    size_t len;

    // Allocazione dello stack per tenere traccia dei componenti del percorso
    stack = kmalloc_array(strlen(path) / 2 + 1, sizeof(char *), GFP_KERNEL);
    if (!stack) {
        printk(KERN_ERR "Failed to allocate memory for stack\n");
        return NULL;
    }

    // Copia del percorso per la tokenizzazione
    tmp = kstrdup(path, GFP_KERNEL);
    if (!tmp) {
        printk(KERN_ERR "Failed to allocate memory for path copy\n");
        kfree(stack);
        return NULL;
    }

    // Tokenizzazione del percorso
    token = strsep(&tmp, "/");
    while (token) {
        if (strcmp(token, ".") == 0) {
            // Ignora '.' (rimani nella stessa directory)
        } else if (strcmp(token, "..") == 0) {
            if (depth > 0) {
                // Torna alla directory precedente
                depth--;
            }
        } else if (strlen(token) > 0) {
            // Aggiunge il token allo stack
            stack[depth++] = token;
        }
        token = strsep(&tmp, "/");
    }

    // Calcolo della lunghezza del percorso risolto
    len = 1; // Per lo slash iniziale
    for (i = 0; i < depth; i++) {
        len += strlen(stack[i]) + 1;
    }

    // Allocazione della memoria per il percorso risolto
    resolved_path = kmalloc(len, GFP_KERNEL);
    if (!resolved_path) {
        printk(KERN_ERR "Failed to allocate memory for resolved_path\n");
        kfree(stack);
        kfree(tmp);
        return NULL;
    }

    // Costruzione del percorso risolto
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

    // Se il percorso utente è già assoluto, risolvilo direttamente
    if (user_path[0] == '/') {
        return resolve_path(user_path);
    }

    // Recupera il percorso della directory di lavoro corrente
    current_dir = get_pwd();
    if (!current_dir) {
        printk(KERN_ERR "Failed to retrieve current working directory\n");
        return NULL;
    }

    // Calcola la lunghezza del percorso assoluto finale
    len = strlen(current_dir) + strlen(user_path) + 2; // 1 per lo slash, 1 per il terminatore nullo
    abs_path = kmalloc(len, GFP_KERNEL);
    if (!abs_path) {
        printk(KERN_ERR "Failed to allocate memory for abs_path\n");
        kfree(current_dir);
        return NULL;
    }

    // Costruisce il percorso assoluto
    snprintf(abs_path, len, "%s/%s", current_dir, user_path);

    // Risolve i componenti ".." e "." del percorso
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

/*##################################################*/
// int scan_directory(const char *dir_path, struct monitored_entry **entries) {
//     struct file *dir;
//     struct dir_context ctx;
//     struct linux_dirent64 *dirent;
//     char *buf;
//     int err = 0;

//     dir = filp_open(dir_path, O_RDONLY | O_DIRECTORY, 0);
//     if (IS_ERR(dir)) {
//         printk(KERN_ERR "Failed to open directory: %s\n", dir_path);
//         return PTR_ERR(dir);
//     }

//     buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
//     if (!buf) {
//         printk(KERN_ERR "Failed to allocate memory for buffer\n");
//         filp_close(dir, NULL);
//         return -ENOMEM;
//     }

//     ctx.pos = 0;
//     while ((err = kernel_read(dir, buf, PAGE_SIZE, &ctx.pos)) > 0) {
//         dirent = (struct linux_dirent64 *)buf;
//         while (dirent->d_reclen > 0 && err > 0) {
//             // Ignora "." e ".."
//             if (strcmp(dirent->d_name, ".") != 0 && strcmp(dirent->d_name, "..") != 0) {
//                 // Crea una nuova entry e aggiungila alla lista
//                 struct monitored_entry *entry = kmalloc(sizeof(struct monitored_entry), GFP_KERNEL);
//                 if (!entry) {
//                     printk(KERN_ERR "Failed to allocate memory for monitored entry\n");
//                     kfree(buf);
//                     filp_close(dir, NULL);
//                     return -ENOMEM;
//                 }

//                 entry->path = kasprintf(GFP_KERNEL, "%s/%s", dir_path, dirent->d_name);
//                 if (!entry->path) {
//                     kfree(entry);
//                     kfree(buf);
//                     filp_close(dir, NULL);
//                     return -ENOMEM;
//                 }

//                 entry->next = *entries;
//                 *entries = entry;
//             }
//             dirent = (struct linux_dirent64 *)((char *)dirent + dirent->d_reclen);
//         }
//     }

//     kfree(buf);
//     filp_close(dir, NULL);

//     return err < 0 ? err : 0;
// }

static int filldir(struct dir_context *ctx, const char *name, int namlen, loff_t offset,
                   u64 ino, unsigned int d_type) {
    struct dir_context_data *data = container_of(ctx, struct dir_context_data, ctx);
    struct monitored_entry *entry;

    // Ignora "." e ".."
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
        return 0;
    }

    //Skip root directory 
    // if (data->skip_root && offset == 0) {
    //     return 0;
    // } 
    if(strcmp(name, data->dir_path) == 0) {
        return 0;
    }

    // Crea una nuova entry
    entry = kmalloc(sizeof(struct monitored_entry), GFP_KERNEL);
    if (!entry) {
        printk(KERN_ERR "Failed to allocate memory for monitored entry\n");
        return -ENOMEM;
    }

    // Assegna il percorso completo
    entry->path = kasprintf(GFP_KERNEL, "%s/%s", data->dir_path, name);
    if (!entry->path) {
        kfree(entry);
        return -ENOMEM;
    }

    // Inserisci l'entry nella lista
    entry->next = *data->entries;
    *data->entries = entry;

    return 0;
}

int scan_directory(const char *dir_path, struct monitored_entry **entries) {
    struct file *dir;
    struct dir_context_data ctx_data = {
        .ctx.actor = filldir,  // Imposta il callback corretto nel contesto
        .ctx.pos = 0,          // Posizione iniziale
        .entries = entries,    // Lista collegata per le entries
        .dir_path = dir_path,  // Path della directory da scansionare
        //.skip_root = 1,        // Imposta il flag per saltare la directory principale
    };
    int err;

    dir = filp_open(dir_path, O_RDONLY | O_DIRECTORY, 0);
    if (IS_ERR(dir)) {
        printk(KERN_ERR "Failed to open directory: %s\n", dir_path);
        return PTR_ERR(dir);
    }

    err = iterate_dir(dir, &ctx_data.ctx);
    if (err < 0) {
        printk(KERN_ERR "Failed to iterate directory: %s\n", dir_path);
    }

    filp_close(dir, NULL);
    return err;
}


//Funzione per verificare se un percorso è una directory
int is_directory(const char *path) {
    struct path path_struct;
    struct kstat stat;
    int err;

    // Ottieni la struttura di path
    err = kern_path(path, LOOKUP_FOLLOW, &path_struct);
    if (err) {
        printk(KERN_ERR "Failed to get path: %d\n", err);
        return err;
    }

    // Usa vfs_stat per ottenere le informazioni sul file/directory
    err = vfs_getattr(&path_struct, &stat, STATX_TYPE, AT_STATX_SYNC_AS_STAT);
    if (err) {
        printk(KERN_ERR "vfs_getattr failed: %d\n", err);
        path_put(&path_struct);
        return err;
    }

    // Rilascia la struttura di path
    path_put(&path_struct);

    // Verifica se il tipo è una directory
    if (S_ISDIR(stat.mode)) {
        return 1;  // È una directory
    } else {
        return 0;  // Non è una directory
    }
}
/*##################################################*/



