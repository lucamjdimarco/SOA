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
#include <linux/spinlock.h> // for spin_lock, spin_unlock
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/device.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/workqueue.h>
#include <crypto/hash.h> // Required for cryptographic hash functions
#include <linux/signal.h>
#include "utils/hash.h"
#include "utils/func_aux.h"

#define PATH 512
#define MAX_LEN 50
#define PASS_LEN 32
#define SHA256_LENGTH 32
#define TABLE_ENTRIES 7
#define SALT_LENGTH 16

#define DEVICE_NAME "ref_monitor"

static char *the_file = NULL;
module_param(the_file, charp, 0660);
MODULE_PARM_DESC(the_file, "Path to the file in the singleFS");

static int Major;
static struct class* device_class = NULL;
static struct device* device = NULL;

struct path_node {
    char *path;
    struct path_node *next;
};

struct r_monitor {
    struct path_node *head; // Puntatore alla testa della lista dei path da proteggere 
    int last_index; //indice dell'ultimo path inserito
    int mode; //0 = OFF; 1 = ON; 2 = REC_OFF; 3 = REC_ON;
    char password[PASS_LEN];
    spinlock_t lock;
};

struct r_monitor monitor = {
    .head = NULL,
    .password = "default",
    //.last_index = -1,
    .mode = 0,
};


static struct kprobe kp_filp_open;
static struct kprobe kp_rmdir;
static struct kprobe kp_mkdir_at;
static struct kprobe kp_unlinkat;

struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
};

static ssize_t ref_write(struct file *, const char *, size_t, loff_t *);
static int ref_open(struct inode *, struct file *);
// Dichiarazione delle funzioni di gestione
void setMonitorON(void);
void setMonitorOFF(void);
void setMonitorREC_ON(void);
void setMonitorREC_OFF(void);
int comparePassw(char *password);
int changePassword(char *new_password);
int insertPath(const char *path);
int removePath(const char *path);

// Workqueue for deferred logging
static struct workqueue_struct *log_wq;
typedef struct {
    struct work_struct work;
    char log_entry[512];
} log_work_t;

static inline bool is_root_uid(void) {
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
        #include "linux/uidgid.h"
            return uid_eq(current_uid(), GLOBAL_ROOT_UID);
        #else
            return 0 == current_uid();
    #endif
}



// Funzione per verificare se un percorso è protetto
bool is_protected_path(const char *path) {
    struct path_node *cur_node; 
    bool protected = false;

    spin_lock(&monitor.lock);

    // Scorre la lista per cercare una corrispondenza
    cur_node = monitor.head;
    while (cur_node) {
        if (strncmp(cur_node->path, path, strlen(cur_node->path)) == 0) {
            protected = true;
            break;
        }
        cur_node = cur_node->next;
    }

    spin_unlock(&monitor.lock);

    return protected;
}


/* ---------------------------------------------- */
// Function for deffered work

// Function to get the TGID, thread ID, UID, EUID
void get_process_info(char *info, size_t len) {
    struct task_struct *task = current;
    snprintf(info, len, "TGID: %d, TID: %d, UID: %d, EUID: %d", task->tgid, task->pid, __kuid_val(task_uid(task)), __kuid_val(task_euid(task)));
}

// Function to compute the SHA-256 hash of a file
int compute_file_hash(const char *filename, unsigned char *hash) {
    struct file *filp;
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    char *buf;
    int bytes_read;
    int ret = 0;

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) {
        return PTR_ERR(tfm);
    }

    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }

    buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buf) {
        kfree(desc);
        crypto_free_shash(tfm);
        return -ENOMEM;
    }

    desc->tfm = tfm;

    if (crypto_shash_init(desc)) {
        ret = -EINVAL;
        goto out_free;
    }

    filp = filp_open(filename, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        ret = PTR_ERR(filp);
        goto out_free;
    }

    //Leggo blocchi di grandezza PAGE_SIZE e aggiorno l'hash
    while ((bytes_read = kernel_read(filp, buf, PAGE_SIZE, &filp->f_pos)) > 0) {
        if (crypto_shash_update(desc, buf, bytes_read)) {
            ret = -EINVAL;
            goto close_filp;
        }
    }

    //Se la lettura non da errore viene calcolato hash finale
    if (bytes_read < 0) {
        ret = bytes_read;
    } else if (crypto_shash_final(desc, hash)) {
        ret = -EINVAL;
    }

close_filp:
    filp_close(filp, NULL);
out_free:
    kfree(buf);
    kfree(desc);
    crypto_free_shash(tfm);
    return ret;
}

// Function to compute the SHA-256 hash of a directory
int compute_directory_hash(const char *path, unsigned char *hash) {
    struct path p;
    //Struttura per mantenere le informazioni di stato della directory
    struct kstat stat;
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    char *buf;
    int ret = 0;

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) {
        return PTR_ERR(tfm);
    }

    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }

    buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buf) {
        kfree(desc);
        crypto_free_shash(tfm);
        return -ENOMEM;
    }

    desc->tfm = tfm;

    if (crypto_shash_init(desc)) {
        ret = -EINVAL;
        goto out_free;
    }

    // Get path (kern_path) and stats (vfs_getattr)
    ret = kern_path(path, LOOKUP_FOLLOW, &p);
    if (ret) {
        goto out_free;
    }
    
    //qui ottengo le informazioni della directory
    ret = vfs_getattr(&p, &stat, STATX_BASIC_STATS, AT_STATX_SYNC_AS_STAT);
    if (ret) {
        goto out_free;
    }

    // Check if the path is a directory
    if (!S_ISDIR(stat.mode)) {
        printk(KERN_INFO "Path is not a directory: %s\n", path);
        ret = -EINVAL;
        goto out_free;
    }

    // Create a buffer with directory properties
    snprintf(buf, PAGE_SIZE, "%s%llu%llu%llu%o", 
             path,
             (unsigned long long)stat.ino,
             (unsigned long long)stat.size,
             (unsigned long long)stat.ctime.tv_sec,
             stat.mode);

    ret = crypto_shash_update(desc, buf, strlen(buf));
    if (ret) {
        ret = -EINVAL;
        goto out_free;
    }

    //Calcolato hash finale della descrizione della directory
    ret = crypto_shash_final(desc, hash);

out_free:
    kfree(buf);
    kfree(desc);
    crypto_free_shash(tfm);
    return ret;
}


void log_to_file(struct work_struct *work) {
    struct file *filp;
    loff_t pos = 0;
    //Puntatore alla struttura log_work_t: contiene i dati del log (ottenuta con container_of).
    log_work_t *log_work = container_of(work, log_work_t, work);
    ssize_t ret;

    filp = filp_open(the_file, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (IS_ERR(filp)) {
        printk(KERN_ERR "Failed to open log file\n");
    } else {
        ret = kernel_write(filp, log_work->log_entry, strlen(log_work->log_entry), &pos);
        if (ret < 0) {
            printk(KERN_ERR "Failed to write to log file\n");
        }
        filp_close(filp, NULL);
    }

    kfree(log_work);
}

// Function to schedule the logging work
void schedule_logging(const char *program_path) {
    unsigned char hash[SHA256_LENGTH];
    char hash_str[SHA256_LENGTH * 2 + 1];
    char info[128];
    log_work_t *log_work;
    int i;
    int hash_result;
    struct path p;
    struct kstat stat;

    printk(KERN_INFO "Starting schedule_logging for path: %s\n", program_path);

    // Get path and stats
    if (kern_path(program_path, LOOKUP_FOLLOW, &p) == 0) {
        //Ottenimento delle statistiche del file/directory
        if (vfs_getattr(&p, &stat, STATX_BASIC_STATS, AT_STATX_SYNC_AS_STAT) == 0) {
            //Se il path è una directory, calcola l'hash della directory
            if (S_ISDIR(stat.mode)) {
                printk(KERN_INFO "Computing hash for directory: %s\n", program_path);
                hash_result = compute_directory_hash(program_path, hash);
            } else {
                //Se il path è un file, calcola l'hash del file
                printk(KERN_INFO "Computing hash for file: %s\n", program_path);
                hash_result = compute_file_hash(program_path, hash);
            }

            if (hash_result != 0) {
                printk(KERN_ERR "Failed to compute hash for path: %s, error code: %d\n", program_path, hash_result);
                return;
            }

            // Convert the hash to a string
            for (i = 0; i < SHA256_LENGTH; i++) {
                sprintf(&hash_str[i * 2], "%02x", hash[i]);
            }
            hash_str[SHA256_LENGTH * 2] = '\0';

            //Ottenimento del processo corrente
            get_process_info(info, sizeof(info));

            log_work = kmalloc(sizeof(*log_work), GFP_KERNEL);
            if (!log_work) {
                printk(KERN_ERR "Failed to allocate memory for log work\n");
                return;
            }

            snprintf(log_work->log_entry, sizeof(log_work->log_entry), "%s, Program Path: %s, Hash: %s\n", info, program_path, hash_str);
            printk(KERN_INFO "Log entry created: %s\n", log_work->log_entry);

            //inizializzo lavoro deferred
            INIT_WORK(&log_work->work, log_to_file);
            //inserisco il lavoro deferred nella workqueue
            queue_work(log_wq, &log_work->work);
        } else {
            printk(KERN_ERR "Failed to get stats for path: %s\n", program_path);
        }
    } else {
        printk(KERN_ERR "Failed to get path: %s\n", program_path);
    }
}

/* ---------------------------------------------- */

static void send_permission_denied_signal(void) {
    struct kernel_siginfo info;
    memset(&info, 0, sizeof(struct kernel_siginfo));
    info.si_signo = SIGTERM;
    info.si_code = SI_KERNEL;
    info.si_errno = -EACCES;

    send_sig_info(SIGTERM, &info, current);
}

static int handler_filp_open(struct kprobe *p, struct pt_regs *regs) {

    int fd = (int)regs->di;
    struct open_flags *op = (struct open_flags *)(regs->dx);
    const __user char *path_user = ((struct filename *)(regs->si))->uptr;
    const char *path_kernel = ((struct filename *)(regs->si))->name;


    int exist = 0;
    char *path = NULL;
    char *dir = NULL;

    if (!regs) {
        printk(KERN_ERR "Invalid registers\n");
        return 0;
    }

    if(strncmp_custom(path_kernel, "/run", 4) == 0) {
        return 0;
    }

    if (!(op->open_flag & O_RDWR) && !(op->open_flag & O_WRONLY) && !(op->open_flag & (O_CREAT | __O_TMPFILE | O_EXCL))) {
        return 0;
    }

    if (!path_user) {
        path = kstrdup(path_kernel, GFP_KERNEL);
        if (!path) {
            printk(KERN_ERR "Failed to allocate memory for path\n");
            regs->ax = -ENOMEM;
            return 0;
        }
    } else {
        path = full_path(fd, path_user);
        if (!path) {
            path = kstrdup(path_kernel, GFP_KERNEL);
            if (!path) {
                printk(KERN_ERR "Failed to allocate memory for path\n");
                regs->ax = -ENOMEM;
                return 0;
            }
            exist = 1;
        }
    }
    
    dir = find_directory(path);
    if (!dir) {
        dir = get_pwd();
    }


    if (!dir) {
        printk(KERN_ERR "Failed to determine directory\n");
        kfree(path);
        regs->ax = -EACCES;
        return 0;
    }

    if ((!(op->open_flag & O_CREAT) || op->mode) && exist) {
        if (is_protected_path(dir)) {
            printk(KERN_INFO "Access to protected path blocked: %s\n", dir);
            schedule_logging(dir);
            kfree(dir);
            kfree(path);
            regs->ax = -EACCES;
            regs->di = (unsigned long)NULL;
            send_permission_denied_signal();
            return 0;
        }
    } else if (is_protected_path(path)) {
        printk(KERN_INFO "Access to protected path blocked: %s\n", path);
        schedule_logging(path);
        kfree(dir);
        kfree(path);
        regs->ax = -EACCES;
        regs->di = (unsigned long)NULL;
        send_permission_denied_signal();
        return 0;
    }

    kfree(dir);
    kfree(path);

    return 0;
}


static int handler_rmdir(struct kprobe *p, struct pt_regs *regs) {

    int fd = (int)regs->di;
    const __user char *path_user = ((struct filename *)(regs->si))->uptr;
	const char *path_kernel = ((struct filename *)(regs->si))->name;

    char *ret_ptr = NULL;
    char *dir = NULL;

    if (!regs) {
        printk(KERN_ERR "Invalid registers\n");
        return 0;
    }

    if (!path_user) {
        ret_ptr = kstrdup(path_kernel, GFP_KERNEL);
        if (!ret_ptr) {
            printk(KERN_ERR "Failed to allocate memory for path\n");
            regs->ax = -ENOMEM;
            return 0;
        }
    } else {
        ret_ptr = full_path(fd, path_user);
        if (!ret_ptr) {
            ret_ptr = kstrdup(path_kernel, GFP_KERNEL);
            if (!ret_ptr) {
                printk(KERN_ERR "Failed to allocate memory for path\n");
                regs->ax = -ENOMEM;
                return 0;
            }
        }
    }

    
    dir = find_directory(ret_ptr);
    if (!dir) {
        dir = get_pwd();
    }

    if (!dir) {
        printk(KERN_ERR "Failed to determine directory\n");
        kfree(ret_ptr);
        regs->ax = -EACCES;
        return 0;
    }

    if (is_protected_path(dir)) {
        printk(KERN_INFO "Access to protected path blocked: %s\n", dir);
        schedule_logging(dir);
        kfree(dir);
        kfree(ret_ptr);
        regs->di = (unsigned long)NULL;
        regs->ax = -EACCES;
        send_permission_denied_signal();
        return 0;
    }

    kfree(dir);
    kfree(ret_ptr);
    return 0;
}

static int handler_mkdirat(struct kprobe *p, struct pt_regs *regs) {

    int fd = (int)regs->di;
    const __user char *path_user = ((struct filename *)(regs->si))->uptr;
    const char *path_kernel = ((struct filename *)(regs->si))->name;

    char *ret_ptr = NULL;
    char *dir = NULL;

    if (!regs) {
        printk(KERN_ERR "Invalid registers\n");
        return 0;
    }

    if (!path_user) {
        ret_ptr = kstrdup(path_kernel, GFP_KERNEL);
        if (!ret_ptr) {
            printk(KERN_ERR "Failed to allocate memory for path\n");
            regs->ax = -ENOMEM;
            return 0;
        }
    } else {
        ret_ptr = full_path(fd, path_user);
        if (!ret_ptr) {
            ret_ptr = kstrdup(path_kernel, GFP_KERNEL);
            if (!ret_ptr) {
                printk(KERN_ERR "Failed to allocate memory for path\n");
                regs->ax = -ENOMEM;
                return 0;
            }
        }
    }

    dir = find_directory(ret_ptr);
    if (!dir) {
        dir = get_pwd();
    }

    if (!dir) {
        printk(KERN_ERR "Failed to determine directory\n");
        kfree(ret_ptr);
        regs->ax = -EACCES;
        return 0;
    }

    if (is_protected_path(dir)) {
        printk(KERN_INFO "Access to protected path blocked: %s\n", dir);
        schedule_logging(dir);
        kfree(dir);
        kfree(ret_ptr);
        regs->di = (unsigned long)NULL;
        regs->ax = -EACCES;
        send_permission_denied_signal();
        return 0;
    }
    
    kfree(dir);
    kfree(ret_ptr);
    return 0;
}



static int handler_unlinkat(struct kprobe *p, struct pt_regs *regs) {
    
    int fd = (int)regs->di;
    const __user char *path_user = ((struct filename *)(regs->si))->uptr;
	const char *path_kernel = ((struct filename *)(regs->si))->name;

    char *ret_ptr = NULL;
    char *dir = NULL;

    if (!regs) {
        printk(KERN_ERR "Invalid registers\n");
        return 0;
    }

    if (!path_user) {
        ret_ptr = kstrdup(path_kernel, GFP_KERNEL);
        if (!ret_ptr) {
            printk(KERN_ERR "Failed to allocate memory for path\n");
            regs->ax = -ENOMEM;
            return 0;
        }
    } else {
        ret_ptr = full_path(fd, path_user);
        if (!ret_ptr) {
            ret_ptr = kstrdup(path_kernel, GFP_KERNEL);
            if (!ret_ptr) {
                printk(KERN_ERR "Failed to allocate memory for path\n");
                regs->ax = -ENOMEM;
                return 0;
            }
        }
    }

    dir = find_directory(ret_ptr);
    if (!dir) {
        dir = get_pwd();
    }

    if (!dir) {
        printk(KERN_ERR "Failed to determine directory\n");
        kfree(ret_ptr);
        regs->ax = -EACCES;
        return 0;
    }

    if (is_protected_path(dir)) {
        printk(KERN_INFO "Access to protected path blocked: %s\n", dir);
        schedule_logging(dir);
        kfree(dir);
        kfree(ret_ptr);
        regs->di = (unsigned long)NULL;
        regs->ax = -EACCES;
        send_permission_denied_signal();
        return 0;
    }

    kfree(dir);
    kfree(ret_ptr);
    return 0;
}

void print_hash(const unsigned char *hash, size_t length) {
    int i;
    char hash_str[SHA256_LENGTH * 2 + 1];

    for (i = 0; i < length; i++) {
        sprintf(&hash_str[i * 2], "%02x", hash[i]);
    }

    hash_str[length * 2] = '\0';
    printk(KERN_INFO "Hash: %s\n", hash_str);
}

void setMonitorON() {
    
    switch (monitor.mode) {
        case 0:
            spin_lock(&monitor.lock);
            monitor.mode = 1;
            spin_unlock(&monitor.lock);

            
            enable_kprobe(&kp_filp_open);
            enable_kprobe(&kp_rmdir);
            enable_kprobe(&kp_mkdir_at);
            enable_kprobe(&kp_unlinkat);

            printk(KERN_INFO "Monitor is now ON\n");
            break;
        case 1:
            printk(KERN_INFO "Monitor is already ON\n");
            break;
        case 2:
            spin_lock(&monitor.lock);
            monitor.mode = 1;
            spin_unlock(&monitor.lock);

            enable_kprobe(&kp_filp_open);
            enable_kprobe(&kp_rmdir);
            enable_kprobe(&kp_mkdir_at);
            enable_kprobe(&kp_unlinkat);

            printk(KERN_INFO "Monitor is now ON\n");
            break;
        case 3:
            spin_lock(&monitor.lock);
            monitor.mode = 1;
            spin_unlock(&monitor.lock);

            printk(KERN_INFO "Monitor is now ON\n");
            break;
        default:
            printk(KERN_ERR "Error: invalid mode\n");
    }
    

}

void setMonitorOFF() {

    switch(monitor.mode){
        case 0:
            printk(KERN_INFO "Monitor is already OFF\n");
            break;
        case 1:
            spin_lock(&monitor.lock);
            monitor.mode = 0;
            spin_unlock(&monitor.lock);

            
            disable_kprobe(&kp_filp_open);
            disable_kprobe(&kp_rmdir);
            disable_kprobe(&kp_mkdir_at);
            disable_kprobe(&kp_unlinkat);

            printk(KERN_INFO "Monitor is now OFF\n");
            break;
        case 2:
            spin_lock(&monitor.lock);
            monitor.mode = 0;
            spin_unlock(&monitor.lock);

            printk(KERN_INFO "Monitor is now OFF\n");
            break;
        case 3:
            spin_lock(&monitor.lock);
            monitor.mode = 0;
            spin_unlock(&monitor.lock);

            disable_kprobe(&kp_filp_open);
            disable_kprobe(&kp_rmdir);
            disable_kprobe(&kp_mkdir_at);
            disable_kprobe(&kp_unlinkat);

            printk(KERN_INFO "Monitor is now OFF\n");
            break;
        default:
            printk(KERN_ERR "Error: invalid mode\n");
    }
   
}

void setMonitorREC_ON() {
    
    switch(monitor.mode){
        //off
        case 0:
            spin_lock(&monitor.lock);
            monitor.mode = 3;
            spin_unlock(&monitor.lock);
            
            enable_kprobe(&kp_filp_open);
            enable_kprobe(&kp_rmdir);
            enable_kprobe(&kp_mkdir_at);
            enable_kprobe(&kp_unlinkat);

            printk(KERN_INFO "Monitor is now REC_ON\n");
            break;
        //on
        case 1:
            spin_lock(&monitor.lock);
            monitor.mode = 3;
            spin_unlock(&monitor.lock);
            printk(KERN_INFO "Monitor is now REC_ON\n");
            break;
        //rec_off
        case 2:
            spin_lock(&monitor.lock);
            monitor.mode = 3;
            spin_unlock(&monitor.lock);

            enable_kprobe(&kp_filp_open);
            enable_kprobe(&kp_rmdir);
            enable_kprobe(&kp_mkdir_at);
            enable_kprobe(&kp_unlinkat);

            printk(KERN_INFO "Monitor is now REC_ON\n");
            break;
        //rec_on
        case 3:
            printk(KERN_INFO "Monitor is already REC_ON\n");
            break;
        default:
            printk(KERN_ERR "Error: invalid mode\n");
    }
}

void setMonitorREC_OFF() {

    switch(monitor.mode){
        case 0:
            spin_lock(&monitor.lock);
            monitor.mode = 2;
            spin_unlock(&monitor.lock);

            printk(KERN_INFO "Monitor is now REC_OFF\n");
            break;
        case 1:
            spin_lock(&monitor.lock);
            monitor.mode = 2;
            spin_unlock(&monitor.lock);

           
            disable_kprobe(&kp_filp_open);
            disable_kprobe(&kp_rmdir);
            disable_kprobe(&kp_mkdir_at);
            disable_kprobe(&kp_unlinkat);

            printk(KERN_INFO "Monitor is now REC_OFF\n");
            break;
        case 2:
            printk(KERN_INFO "Monitor is already REC_OFF\n");
            break;
        case 3:
            spin_lock(&monitor.lock);
            monitor.mode = 2;
            spin_unlock(&monitor.lock);

            
            disable_kprobe(&kp_filp_open);
            disable_kprobe(&kp_rmdir);
            disable_kprobe(&kp_mkdir_at);
            disable_kprobe(&kp_unlinkat);

            printk(KERN_INFO "Monitor is now REC_OFF\n");
            break;
        default:
            printk(KERN_ERR "Error: invalid mode\n");
    }
}



int insertPath(const char *path) {
    struct path_node *new_node, *cur_node;  
    char *absolute_path;


    if (monitor.mode != 2 && monitor.mode != 3) {
        printk(KERN_ERR "Error: REC_ON or REC_OFF required\n");
        return -1;
    }

    // Converti il percorso fornito in un percorso assoluto
    absolute_path = get_absolute_path(path);
    if (!absolute_path) {
        printk(KERN_ERR "Error: Could not resolve absolute path\n");
        return -EINVAL;
    }

    // Controlla se il percorso assoluto è lo stesso del file di log
    if (the_file && strncmp(absolute_path, the_file, strlen(the_file)) == 0) {
        printk(KERN_ERR "Error: Cannot protect the log file path\n");
        kfree(absolute_path);  // Libera la memoria allocata per absolute_path
        return -EINVAL;
    }

    spin_lock(&monitor.lock);

    // Controlla se il percorso è già presente nella lista
    cur_node = monitor.head;
    while (cur_node) {
        if (strcmp(cur_node->path, absolute_path) == 0) {
            printk(KERN_INFO "Path already exists: %s\n", absolute_path);
            spin_unlock(&monitor.lock);
            kfree(absolute_path);  // Libera la memoria allocata per absolute_path
            return -EEXIST;
        }
        cur_node = cur_node->next;
    }

    // Creazione del nuovo nodo
    new_node = kmalloc(sizeof(struct path_node), GFP_KERNEL);
    if (!new_node) {
        printk(KERN_ERR "Failed to allocate memory for new node\n");
        spin_unlock(&monitor.lock);
        kfree(absolute_path);  // Libera la memoria allocata per absolute_path
        return -ENOMEM;
    }
    new_node->path = absolute_path;  // Usa il percorso assoluto
    new_node->next = monitor.head;
    monitor.head = new_node;

    spin_unlock(&monitor.lock);

    printk(KERN_INFO "Path inserted: %s\n", absolute_path);

    return 0;
}

int removePath(const char *path) {
    struct path_node *cur_node, *prev_node = NULL;  // Rinominato da 'current'
    int ret = -1;
    char *absolute_path;

    if (monitor.mode != 2 && monitor.mode != 3) {
        printk(KERN_ERR "Error: REC_ON or REC_OFF required\n");
        return -1;
    }

    // Converti il percorso fornito in un percorso assoluto
    absolute_path = get_absolute_path(path);
    if (!absolute_path) {
        printk(KERN_ERR "Error: Could not resolve absolute path\n");
        return -EINVAL;
    }

    spin_lock(&monitor.lock);

    cur_node = monitor.head;
    while (cur_node) {
        if (strcmp(cur_node->path, absolute_path) == 0) {
            if (prev_node) {
                prev_node->next = cur_node->next;
            } else {
                monitor.head = cur_node->next;
            }
            kfree(cur_node->path);
            kfree(cur_node);
            ret = 0;
            break;
        }
        prev_node = cur_node;
        cur_node = cur_node->next;
    }

    spin_unlock(&monitor.lock);

    if (ret == 0) {
        printk(KERN_INFO "Path removed: %s\n", absolute_path);
    } else {
        printk(KERN_ERR "Failed to remove path: %s\n", absolute_path);
    }

    return ret;
}



int comparePassw(char *password) {
    int ret;
    unsigned char hash[SHA256_LENGTH];
    unsigned char salt[SALT_LENGTH];

    // Hash della password fornita con il salt memorizzato
    ret = hash_password(password, salt, hash);
    if (ret != 0) {
        printk(KERN_ERR "Error hashing password\n");
        return -1;
    }

    // Confronta l'hash calcolato con quello memorizzato usando un confronto costante
    if (constant_time_compare(hash, monitor.password, SHA256_LENGTH) == 0) {
        printk(KERN_INFO "Password correct\n");
        return 0;
    } else {
        printk(KERN_INFO "Password incorrect\n");
        return -1;
    }
}

int changePassword(char *new_password) {
    int ret;
    char hash[PASS_LEN + 1];
    unsigned char salt[SALT_LENGTH];

    if(monitor.mode != 2 && monitor.mode != 3) {
        printk(KERN_ERR "Error: REC_ON or REC_OFF required\n");
        return -1;
    }

    // Hash della password fornita
    ret = hash_password(new_password, salt, hash);
    if (ret != 0) {
        printk(KERN_ERR "Error hashing password\n");
        return -1;
    }

    printk(KERN_INFO "Password changed\n");

    spin_lock(&monitor.lock);
    strncpy(monitor.password, hash, PASS_LEN);
    spin_unlock(&monitor.lock);


    return 0;
}

int verifyPassword(const char *password, const char *stored_hash, const unsigned char *salt) {
    unsigned char hash[SHA256_LENGTH];
    int ret;

    // Hash della password fornita con il salt memorizzato
    ret = hash_password(password, salt, hash);
    if (ret != 0) {
        printk(KERN_ERR "Error hashing password\n");
        return -1;
    }

    // Confronta l'hash calcolato con quello memorizzato usando un confronto costante
    if (constant_time_compare(hash, stored_hash, SHA256_LENGTH) == 0) {
        printk(KERN_INFO "Password correct\n");
        return 0;
    } else {
        printk(KERN_INFO "Password incorrect\n");
        return -1;
    }
}

static int ref_open(struct inode *inode, struct file *file) {
    printk(KERN_INFO "Open\n");
    return 0;
}

static ssize_t ref_write(struct file *f, const char __user *buff, size_t len, loff_t *off) {
    char *buffer;
    char *command;
    char *parameter;
    char *additional_param = NULL;
    int ret = -1;
    unsigned char salt[SALT_LENGTH];

    if (is_root_uid() != 1) {
        printk(KERN_ERR "Error: ROOT user required\n");
        return -EPERM;
    }

    buffer = kmalloc(len + 1, GFP_KERNEL);
    if (!buffer) {
        printk(KERN_ERR "Failed to allocate memory\n");
        return -ENOMEM;
    }

    if (copy_from_user(buffer, buff, len)) {
        kfree(buffer);
        return -EFAULT;
    }
    buffer[len] = '\0';

    command = strsep(&buffer, ":");
    parameter = strsep(&buffer, ":");
    if (buffer) {
        additional_param = strsep(&buffer, ":");
    }

    if (command && parameter) {
        //printk(KERN_INFO "Received command: %s with parameter: %s\n", command, parameter);

        if (strncmp(command, "ON", 2) == 0) {
            ret = verifyPassword(parameter, monitor.password, salt);
            if(ret != 0) {
                printk(KERN_ERR "Error verifying password\n");
                kfree(buffer);
                return ret;
            }
            printk(KERN_INFO "Setting monitor ON\n");
            setMonitorON();
        } else if(strncmp(command, "OFF", 3) == 0) {
            ret = verifyPassword(parameter, monitor.password, salt);
            if(ret != 0) {
                printk(KERN_ERR "Error verifying password\n");
                kfree(buffer);
                return ret;
            }
            printk(KERN_INFO "Setting monitor OFF\n");
            setMonitorOFF();
        } else if (strncmp(command, "REC_ON", 6) == 0) {
            ret = verifyPassword(parameter, monitor.password, salt);
            printk(KERN_INFO "Setting monitor REC_ON\n");
            setMonitorREC_ON();
        } else if (strncmp(command, "REC_OFF", 7) == 0) {
            ret = verifyPassword(parameter, monitor.password, salt);
            if(ret != 0) {
                printk(KERN_ERR "Error verifying password\n");
                kfree(buffer);
                return ret;
            }
            printk(KERN_INFO "Setting monitor REC_OFF\n");
            setMonitorREC_OFF();
        } else if (strncmp(command, "CHGPASS", 7) == 0) {
            ret = verifyPassword(parameter, monitor.password, salt);
            if(ret != 0) {
                printk(KERN_ERR "Error verifying password\n");
                kfree(buffer);
                return ret;
            }
            if(additional_param) {
                ret = changePassword(additional_param);
                if (ret != 0) {
                    printk(KERN_ERR "Error changing password\n");
                    kfree(buffer);
                    return ret;
                }
            } else {
                printk(KERN_ERR "Missing new password\n");
                ret = -EINVAL;
            }
        } else if(strncmp(command, "INSERT", 6) == 0) {
            ret = verifyPassword(parameter, monitor.password, salt);
            if(ret != 0) {
                printk(KERN_ERR "Error verifying password\n");
                kfree(buffer);
                return ret;
            }
            ret = insertPath(additional_param);
            if (ret != 0) {
                printk(KERN_ERR "Error inserting path\n");
                kfree(buffer);
                return ret;
            }
        } else if (strncmp(command, "REMOVE", 6) == 0) {
            ret = verifyPassword(parameter, monitor.password, salt);
            if(ret != 0) {
                printk(KERN_ERR "Error verifying password\n");
                kfree(buffer);
                return ret;
            }
            ret = removePath(additional_param);
            if (ret != 0) {
                printk(KERN_ERR "Error removing path\n");
                kfree(buffer);
                return ret;
            }
        } else {
            printk(KERN_ERR "Unknown command\n");
            ret = -EINVAL;
        }
    } else {
        printk(KERN_ERR "Invalid input format\n");
        ret = -EINVAL;
    }

    kfree(buffer);
    return ret;
}


static struct file_operations fops = {
  .owner = THIS_MODULE,	
  .write = ref_write,
  .open = ref_open,
};

static int __init monitor_init(void) {

    int ret;
    char hash[PASS_LEN + 1];
    unsigned char salt[SALT_LENGTH];

    printk(KERN_INFO "Monitor module loaded\n");

    

    Major = register_chrdev(0, DEVICE_NAME, &fops);
    if (Major < 0) {
        printk(KERN_ALERT "Registering char device failed with %d\n", Major);
        return Major;
    }

    // Creazione della classe del dispositivo
    device_class = class_create(THIS_MODULE, DEVICE_NAME);
    if (IS_ERR(device_class)) {
        unregister_chrdev(Major, DEVICE_NAME);
        printk(KERN_INFO "Class creation failed\n");
        return PTR_ERR(device_class);
    }

    // Creazione del dispositivo
    device = device_create(device_class, NULL, MKDEV(Major, 0), NULL, DEVICE_NAME);
    if (IS_ERR(device)) {
        class_destroy(device_class);
        unregister_chrdev(Major, DEVICE_NAME);
        printk(KERN_INFO "Device creation failed\n");
        return PTR_ERR(device);
    }


    printk(KERN_INFO "I was assigned major number %d. To talk to\n", Major);

    // Inizializzazione del monitor
    ret = hash_password("default", salt, hash);
    if (ret != 0) {
        printk(KERN_ERR "Error hashing password\n");
        return -1;
    }

    spin_lock(&monitor.lock);
    monitor.last_index = -1;
    monitor.mode = 0;
    strncpy(monitor.password, hash, PASS_LEN);
    spin_unlock(&monitor.lock);

    kp_filp_open.pre_handler = handler_filp_open;
    kp_filp_open.symbol_name = "do_filp_open";

    kp_rmdir.pre_handler = handler_rmdir;
    kp_rmdir.symbol_name = "do_rmdir";

    kp_mkdir_at.pre_handler = handler_mkdirat;
    kp_mkdir_at.symbol_name = "do_mkdirat";

    kp_unlinkat.pre_handler = handler_unlinkat;
    kp_unlinkat.symbol_name = "do_unlinkat";

    if (register_kprobe(&kp_filp_open) < 0) {
        printk(KERN_INFO "Failed to register kprobe filp_open\n");
        return -1;
    }
    if (register_kprobe(&kp_rmdir) < 0) {
        printk(KERN_INFO "Failed to register kprobe rmdir\n");
        return -1;
    }
    if (register_kprobe(&kp_mkdir_at) < 0) {
        printk(KERN_INFO "Failed to register kprobe mkdirat\n");
        return -1;
    }
    if(register_kprobe(&kp_unlinkat) < 0) {
        printk(KERN_INFO "Failed to register kprobe unlinkat\n");
        return -1;
    }

    //disable_kprobe(&kp_openat2);   
    disable_kprobe(&kp_filp_open);
    disable_kprobe(&kp_rmdir);
    disable_kprobe(&kp_mkdir_at);
    disable_kprobe(&kp_unlinkat);

    printk(KERN_INFO "Kprobe filp_open registered and disabled successfully\n");
    printk(KERN_INFO "Kprobe rmdir registered and disabled successfully\n");
    printk(KERN_INFO "Kprobe mkdirat registered and disabled successfully\n");
    printk(KERN_INFO "Kprobe unlinkat registered and disabled successfully\n");

    // Initialize workqueue
    log_wq = create_workqueue("log_wq");
    if (!log_wq) {
        printk(KERN_ERR "Failed to create workqueue\n");
        return -ENOMEM;
    }

    return 0;
}

static void __exit monitor_exit(void) {

    flush_workqueue(log_wq);
    destroy_workqueue(log_wq);

    printk(KERN_INFO "Monitor module unloaded\n");

    // Rimozione del dispositivo
    device_destroy(device_class, MKDEV(Major, 0));
    class_unregister(device_class);
    class_destroy(device_class);
    unregister_chrdev(Major, DEVICE_NAME);

    unregister_kprobe(&kp_filp_open);
    unregister_kprobe(&kp_rmdir);
    unregister_kprobe(&kp_mkdir_at);
    unregister_kprobe(&kp_unlinkat);

    printk(KERN_INFO "Kprobe filp_open unregistered\n");
    printk(KERN_INFO "Kprobe rmdir unregistered\n");
    printk(KERN_INFO "Kprobe mkdirat unregistered\n");
    printk(KERN_INFO "Kprobe unlinkat unregistered\n");
}

module_init(monitor_init);
module_exit(monitor_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luca Di Marco");
MODULE_DESCRIPTION("Reference Monitor");