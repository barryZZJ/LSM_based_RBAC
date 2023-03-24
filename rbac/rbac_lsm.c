#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/lsm_hooks.h>

// configuration
#define CONF_USER_ROLE	"/etc/rbac/user_role_mapping"
#define CONF_ROLE_PERM	"/etc/rbac/role_perm_mapping"
#define CONF_SWITCH		"/etc/rbac/switch"

#define USERS_NMAX	        10
#define ROLES_NMAX	        5
#define ROLE_NAME_LEN_MAX   20

#define PERM_NMAX           2
#define PERM_NAME_LEN_MAX   20
#define PERM_RMDIR_NAME     "RMDIR"
#define PERM_MKDIR_NAME     "MKDIR"
#define PERM_RMDIR_VAL      0x01
#define PERM_MKDIR_VAL      0x02

typedef unsigned int uint;

typedef struct {
    uint uid;
    int role_ind;
} USER;

typedef struct {
    char name[50];
    uint perms;
} ROLE;

static USER users[USERS_NMAX];
static ROLE roles[ROLES_NMAX];

static int num_users;
static int num_roles;
static bool module_enabled;

unsigned int atoui(char* str) {
	unsigned int res = 0;
	int i;
	for(i = 0; i < strlen(str); i++) {
		res = res * 10 + str[i] - '0';
	}
	// printk(KERN_INFO "atoui:: %s -> %u\n", str, res);
	return res;
}

static void load_switch(void) {
    printk(KERN_INFO "Loading switch...\n");
    
    struct file *fp;
    mm_segment_t oldfs;

    fp = filp_open(CONF_SWITCH, O_RDONLY, 0);
    if (IS_ERR(fp) || (fp == NULL)) {
        printk(KERN_ERR "Failed to open %s\n", CONF_SWITCH);
        return;
    }

    oldfs = get_fs();
    set_fs(get_ds());

    char buf;
    module_enabled = true;
    
    if (kernel_read(fp, &buf, 1, &fp->f_pos) > 0) {
        module_enabled = buf == '1';
    }
    if (module_enabled){
        printk(KERN_INFO "Module is enabled\n");
    } else {
        printk(KERN_INFO "Module is disabled\n");
    }

    set_fs(oldfs);
    filp_close(fp, NULL);

}

static void load_users_config(void) {
    printk(KERN_INFO "Loading users configuration...\n");
    
    struct file *fp;
    mm_segment_t oldfs;

    fp = filp_open(CONF_USER_ROLE, O_RDONLY, 0);
    if (IS_ERR(fp) || (fp == NULL)) {
        printk(KERN_ERR "Failed to open %s\n", CONF_USER_ROLE);
        return;
    }

    oldfs = get_fs();
    set_fs(get_ds());

    uint uid;
    char* role_name;
    char* uid_str;

    char buf[1024] = {0};
    char* ptr = buf;
    char* line;
    int linei = 0;
    num_users = 0;
    while (kernel_read(fp, buf, sizeof(buf)-1, &fp->f_pos) > 0) {
        // printk(KERN_INFO "buf: %s\n", buf);

        if (num_users >= USERS_NMAX) {
            printk(KERN_ERR "Too many users in %s, maximum is %d\n", CONF_USER_ROLE, USERS_NMAX);
            break;
        }

        line = strsep(&ptr, "\n");
        while (line != NULL){
            // strip '\r'
            line[strcspn(line, "\r")] = '\0';

            if (line[0] != '\0'){
                // printk(KERN_INFO "line %d: %s\n", linei + 1, line);

                uid_str = strsep(&line, "=");
                if (uid_str != NULL && line != NULL){
                    uid = atoui(uid_str);
                    role_name = line;

                    // Look up the index of the role in the roles array
                    int role_ind = -1;
                    int j;
                    for (j = 0; j < num_roles; j++) {
                        if (strncmp(roles[j].name, role_name, sizeof(roles[j].name)) == 0) {
                            role_ind = j;
                            break;
                        }
                    }
                    if (role_ind == -1) {
                        printk(KERN_WARNING "Unknown role in line %d: \"%s\"\n", linei + 1, role_name);
                    } else {
                        users[num_users].uid = uid;
                        users[num_users].role_ind = role_ind;
                        printk(KERN_INFO "User %u is %s\n", users[num_users].uid, roles[role_ind].name);

                        num_users++;
                    }
                } else {
                    printk(KERN_WARNING "Invalid format in line %d!", linei + 1);
                }
            }
            line = strsep(&ptr, "\n");
            linei++;
        }
    }

    set_fs(oldfs);
    filp_close(fp, NULL);

}

static void load_roles_config(void) {
    printk(KERN_INFO "Loading roles configuration...\n");

    struct file *fp;
    mm_segment_t oldfs;

    fp = filp_open(CONF_ROLE_PERM, O_RDONLY, 0);
    if (IS_ERR(fp) || (fp == NULL)) {
        printk(KERN_ERR "Failed to open %s\n", CONF_ROLE_PERM);
        return;
    }
    
    oldfs = get_fs();
    set_fs(get_ds());

    char* role_name;
    char* ptr_perm_names;
    char *perm_name;

    char buf[1024] = {0};
    char* ptr = buf;
    char* line;
    int linei = 0;
    num_roles = 0;
    while (kernel_read(fp, buf, sizeof(buf)-1, &fp->f_pos) > 0) {
        // printk(KERN_INFO "buf: %s\n", buf);

        if (num_roles >= ROLES_NMAX) {
            printk(KERN_ERR "Too many roles in %s, maximum is %d\n", CONF_ROLE_PERM, ROLES_NMAX);
            break;
        }

        line = strsep(&ptr, "\n");
        while (line != NULL) {
            // strip '\r'
            line[strcspn(line, "\r")] = '\0';

            if (line[0] != '\0'){
                // printk(KERN_INFO "line %d: %s\n", linei + 1, line);

                role_name = strsep(&line, "=");
                if (role_name != NULL && line != NULL){
                    ptr_perm_names = line;

                    uint perms = 0;
                    perm_name = strsep(&ptr_perm_names, ",");
                    // printk(KERN_INFO "perm_name: %s\n", perm_name);
                    while (perm_name != NULL) {
                        if (strncmp(perm_name, PERM_RMDIR_NAME, PERM_NAME_LEN_MAX) == 0) {
                            perms |= PERM_RMDIR_VAL;
                        } else if (strncmp(perm_name, PERM_MKDIR_NAME, PERM_NAME_LEN_MAX) == 0) {
                            perms |= PERM_MKDIR_VAL;
                        } else {
                            printk(KERN_WARNING "Unknown permission in line %d: %s\n", linei + 1, perm_name);
                        }
                        perm_name = strsep(&ptr_perm_names, ",");
                    }
                    
                    strncpy(roles[num_roles].name, role_name, ROLE_NAME_LEN_MAX);
                    roles[num_roles].perms = perms;
                    printk(KERN_INFO "Role loaded: %s, %d\n", roles[num_roles].name, roles[num_roles].perms);

                    num_roles++;
                } else {
                    printk(KERN_WARNING "Invalid format in line %d!", linei + 1);
                }
            }
            line = strsep(&ptr, "\n");
            linei++;
        }
    }

    set_fs(oldfs);
    filp_close(fp, NULL);
}

static USER get_curr_user(void) {
    struct cred *cur = prepare_creds();
    uint uid = (uint) cur->uid.val;
    int i;
    USER user = {uid, -1};
    for(i = 0; i < num_users; i++){
        if (users[i].uid == uid){
            user.role_ind = users[i].role_ind;
            return user;
        }
    }
    return user;
}


static bool has_permission(USER user, uint action) {
    printk(KERN_INFO "checking user %u 's permission for action %u\n", user.uid, action);
    ROLE role = roles[user.role_ind];
    return (role.perms & action) != 0;
}

static int check_permission(uint action){

    load_switch();
    // permit if module is disabled
    if (!module_enabled) {
        printk(KERN_INFO "module disabled, permission granted.\n");
        return 0;
    }

    // load roles first to update num_roles, 
    // which will be used to load user config
    load_roles_config();
    load_users_config();
    USER user = get_curr_user();
    
    // permit if user not found
    if (user.role_ind == -1) {
        printk(KERN_INFO "current user %u does not match configuration, permission granted.\n", user.uid);
        return 0;
    }

    if (has_permission(user, action)){
        // permitted
        return 0;
    } else {
        // permission denied
        return EACCES;
    }
}

static int hook_inode_rmdir(struct inode *dir, struct dentry *dentry){
    printk(KERN_INFO "hooked rmdir\n");
    int res = check_permission(PERM_RMDIR_VAL);
    if (res == 0){
        printk(KERN_INFO "permission granted\n");
    } else {
        printk(KERN_INFO "permission denied\n");
    }
    return res;

}

static int hook_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mask){
    printk(KERN_INFO "hooked mkdir\n");
    int res = check_permission(PERM_MKDIR_VAL);
    if (res == 0){
        printk(KERN_INFO "permission granted\n");
    } else {
        printk(KERN_INFO "permission denied\n");
    }
    return res;

}

static struct security_hook_list hooks[] = {
	LSM_HOOK_INIT(inode_rmdir, hook_inode_rmdir),
    LSM_HOOK_INIT(inode_mkdir, hook_inode_mkdir)
};


static int __init rbac_init(void) {
	printk(KERN_INFO "RBAC: Initializing.\n");	
	security_add_hooks(hooks, ARRAY_SIZE(hooks), "lsm-rbac");
	printk(KERN_INFO "RBAC: Hooks added.\n");
    return 0;
}

// static void rbac_exit(void) {
// 	printk(KERN_INFO "RBAC: Exiting.\n");	
//     // int i, count = ARRAY_SIZE(hooks);
//     // for (i = 0; i< count; i++){
//     //     list_del_rcu(&hooks[i].list);
//     // }
// }
security_initcall(rbac_init);

// module_init(rbac_init);
// module_exit(rbac_exit);

// MODULE_DESCRIPTION("A LSM based RBAC for OS security class");
// MODULE_AUTHOR("zzj");
// MODULE_LICENSE("GPL");
