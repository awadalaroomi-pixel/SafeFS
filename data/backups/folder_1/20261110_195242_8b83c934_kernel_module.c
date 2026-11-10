#include <linux/module.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("SafeFS");

static int __init safefs_init(void) {
    pr_info("SafeFS Kernel Hook Loaded\n");
    return 0;
}
module_init(safefs_init);