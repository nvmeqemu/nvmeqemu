#define APPNAME         "qnvme"
#define LEVEL           APPNAME
#define DEBUG

#define LOG_NORM(fmt, ...)    \
    printf("%s: " fmt "\n", LEVEL, ## __VA_ARGS__)
#define LOG_ERR(fmt, ...)    \
    printf("%s-ERR:%s:%d: " fmt "\n", LEVEL, __FILE__, \
        __LINE__, ## __VA_ARGS__)
#ifdef DEBUG
#define LOG_DBG(fmt, ...)    \
    printf("%s-DBG:%s:%d: " fmt "\n", LEVEL, __FILE__, \
        __LINE__, ## __VA_ARGS__)
#else
#define LOG_DBG(fmt, ...)
#endif
