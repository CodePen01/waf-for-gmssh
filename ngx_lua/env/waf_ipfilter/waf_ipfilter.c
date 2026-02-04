#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <regex.h>
#include <ctype.h>

#define PID_FILE "/www/server/safewaf/log/ipfilter.pid"
#define LOG_FILE "/www/server/safewaf/log/ipfilter.log"
#define LOG_INFO "INFO"
#define LOG_ERROR "ERROR"
#define LOG_DEBUG "DEBUG"
#define LOG_WARNING "WARNING"
#define RULE_NAME "waf_ip_filter"
#define RULE_NAME6 "waf_ip_filter_v6"
#define UPDATE_FILE "/dev/shm/.waf_ip_filter"

/**
 * 读取文件内容
 * @param filename <char*> 文件名
 * @param mode <char*> 文件打开模式
 * @return char*
 */
void *read_file(char *filename, char *mode, char *fbody)
{
    int buff_size = 128;
    char buff[buff_size];
    FILE *fp = NULL;
    fp = fopen(filename, mode);

    // //重置游标
    rewind(fp);
    fbody[0] = '\0';
    //读取文件内容
    while (fgets(buff, buff_size, fp) != NULL)
    {
        strcat(fbody, buff);
    }

    fclose(fp);
}

/**
 * 正则匹配
 * @param str <char *> 要被匹配的字符串
 * @param pattern <char *> 正则表达式
 * @return int
 */
int match(char *str, char *pattern)
{
    regex_t reg;
    size_t nmatch = 1;
    regmatch_t pmatch[1];
    int cflags = REG_EXTENDED;
    regcomp(&reg, pattern, cflags);
    int ret = regexec(&reg, str, nmatch, pmatch, 0);
    regfree(&reg);
    if (ret == 0)
    {
        return 1;
    }
    return 0;
}

/**
 * 是否为IPv4地址
 * @param ip <char *> 要被匹配的字符串
 * @return int
 */
int is_ipv4(char *ip)
{
    char *pattern = "^(([0-9]{1,3}[.]){3}[0-9]{1,3}|([0-9]{1,3}[.]){3}[0-9]{1,3}/[0-9]{1,2}|([0-9]{1,3}[.]){3}[0-9]{1,3}-([0-9]{1,3}[.]){3}[0-9]{1,3})$";
    int ret = match(ip, pattern);
    return ret;
}

/**
 * 是否为IPv6地址
 * @param ip <char *> 要被匹配的字符串
 * @return int
 */
int is_ipv6(char *ip)
{
    char *pattern = "^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}/[0-9]{1,3}|([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}-([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})$";
    int ret = match(ip, pattern);
    return ret;
}

/**
 * 写入文件
 * @param filename <char*> 文件名
 * @param content <char*> 内容
 * @param mode <char*> 文件打开模式
 * @return int
 */
int write_file(char *filename, char *fbody, char *mode)
{
    FILE *fp = NULL;
    int result;
    fp = fopen(filename, mode);
    result = fputs(fbody, fp);
    fclose(fp);
    return result;
}

/**
 * 执行SHELL命令
 * @param cmd <char *> SHELL命令
 * @param result <char *> 用于存储命令执行结果的指针
 * @param 注意：此处执行命令只存储管道1的结果，如果需要其它管道的内容，请重定向到管道1
 * @return void
 */
void exec_shell(char *cmd, char *result)
{
    FILE *fp = NULL;
    fp = popen(cmd, "r");
    int buff_size = 128;
    char buff[buff_size];
    result[0] = '\0';
    while (fgets(buff, buff_size, fp) != NULL)
    {
        int buff_len = strlen(buff);
        strncat(result, buff, buff_len);
    }
    pclose(fp);
}

/**
 * 判断文件是否存在
 * @param filename <char*> 文件名
 * @return int
 */
int file_exists(char *filename)
{
    if (access(filename, F_OK) != -1)
    {
        return 1;
    }
    return 0;
}

/**
 *  获取格式化时间
 * @param date_time <char *> 用于存储格式化时间的指针
 * @return void
 */
void get_date(char *date_time)
{
    time_t now;
    struct tm *tm_now;

    time(&now);
    tm_now = localtime(&now);

    strftime(date_time, 24, "%Y-%m-%d %H:%M:%S", tm_now);
}

/**
 * 写日志到文件
 * @param msg <char *> 日志内容
 * @param level <char *> 日志级别  INFO/DEBUG/ERROR/WARNING
 * @return void
 */
void write_log(char *msg, char *level)
{
    char log_body[256];
    char date_time[24];
    get_date(date_time);
    snprintf(log_body, 256, "[%s] - [%s] - %s\n", date_time, level, msg);
    write_file(LOG_FILE, log_body, "a+");
    printf("%s", log_body);
    if (strcmp(level, LOG_ERROR) == 0)
    {
        write_log("因致命错误而中断进程", "WARNING");
        exit(0);
    }
}

/**
 * 写日志到文件 JOIN STRING
 * @param msg <char *> 日志内容
 * @param val <char *> 要拼接的字符串
 * @param level <char *> 日志级别  INFO/DEBUG/ERROR/WARNING
 * @return void
 */
void write_log_join(char *msg, char *val, char *level)
{
    char log_body[256];
    snprintf(log_body, 256, "%s `%s`", msg, val);
    write_log(log_body, level);
}

/**
 * 判断是否安装ipset
 * @return int
 */
int is_install_ipset()
{
    if (file_exists("/usr/sbin/ipset") || file_exists("/sbin/ipset") || file_exists("/usr/local/sbin/ipset") || file_exists("/usr/local/bin/ipset"))
    {
        return 1;
    }
    return 0;
}

/**
 * 判断是否安装iptables
 * @return int
 */
int is_install_iptables()
{
    if (file_exists("/usr/sbin/iptables") || file_exists("/sbin/iptables") || file_exists("/usr/local/sbin/iptables") || file_exists("/usr/local/bin/iptables"))
    {
        return 1;
    }
    return 0;
}

/**
 * 创建ipset
 * @return int
 */
int create_ipset()
{
    //检查是否已经创建过了
    char cmd1[128];
    snprintf(cmd1, 128, "ipset list |grep %s 2>&1", RULE_NAME);
    char cmd1_result[256];
    exec_shell(cmd1, cmd1_result);
    if (strlen(cmd1_result) < 10){

        //创建ipset
        char cmd2[256];
        snprintf(cmd2, 256, "ipset create %s hash:ip hashsize 4096 maxelem 262144 timeout 86400 2>&1", RULE_NAME);
        char cmd2_result[256];
        exec_shell(cmd2, cmd2_result);

        //检查是否创建成功
        char cmd1_result2[256];
        exec_shell(cmd1, cmd1_result2);
        if (strlen(cmd1_result2) < 10)
        {
            write_log(cmd2_result, LOG_WARNING);
            write_log("错误：未能成功创建ipset", LOG_ERROR);
            return 0;
        }

    }

    char cmd6[128];
    snprintf(cmd6, 128, "ipset list |grep %s 2>&1", RULE_NAME6);
    char cmd6_result[256];
    exec_shell(cmd6, cmd6_result);
    if (strlen(cmd6_result) < 10){
        char cmd3[384];
        snprintf(cmd3, 384, "ipset create %s hash:ip hashsize 4096 maxelem 262144 timeout 86400 family inet6 2>&1", RULE_NAME6);
        char cmd3_result[256];
        exec_shell(cmd3, cmd3_result);
        char cmd6_result2[256];
        exec_shell(cmd6, cmd6_result2);
        if (strlen(cmd6_result2) < 10)
        {
            write_log(cmd6_result2, LOG_WARNING);
            write_log("警告：未能成功创建ipset - IPv6", LOG_WARNING);
        }
    }

    return 1;
}

/**
 * 设置ipset到iptables
 * @return int
 */
int set_ipset_iptables()
{
    // 获取nginx/httpd监听的端口
    char cmd0[256];
    memset(cmd0, 0, sizeof(cmd0));
    sprintf(cmd0, "netstat -tunlp|grep -E '(nginx|httpd)'|awk '{print $4}'|awk -F ':' '{print $2}'|grep -v '^80$'|grep -v '^443$'");

    char cmd0_result[256];
    exec_shell(cmd0, cmd0_result);
    int res_len = strlen(cmd0_result);
    if(res_len > 0){
        if (cmd0_result[res_len - 1] != '\n'){
            cmd0_result[res_len] = '\n';
            cmd0_result[res_len + 1] = '\0';
        }
    }
    strcat(cmd0_result, "80\n");
    strcat(cmd0_result, "443\n");
    char delim[] = "\n";
    char *port = strtok(cmd0_result, delim);
    while(port != NULL){
        if(strlen(port) == 0) continue;
        //检查是否已经设置过了
        char cmd1[128];
        char cmd1_result[512];
        snprintf(cmd1, 128, "iptables -nL|grep  %s|grep %s", RULE_NAME, port);
        exec_shell(cmd1, cmd1_result);
        if (!strlen(cmd1_result)){
            //设置80端口封禁
            char cmd2[256];
            char cmd2_result[256];
            snprintf(cmd2, 256, "iptables -I INPUT -m set --match-set %s src -p tcp --destination-port %s -j DROP 2>&1", RULE_NAME,port);
            exec_shell(cmd2, cmd2_result);
            if (strlen(cmd2_result))
            {
                write_log(cmd2_result, LOG_WARNING);
                write_log("错误：未能将ipset配置到iptables", LOG_ERROR);
                return 0;
            }
        }

        //检查是否设置IPv6
        char cmd6[128];
        char cmd6_result[512];
        snprintf(cmd6, 128, "ip6tables -nL|grep  %s|grep %s", RULE_NAME6,port);
        exec_shell(cmd6, cmd6_result);
        if (!strlen(cmd6_result)){
            char cmd3[384];
            char cmd3_result[256];
            snprintf(cmd3, 384, "ip6tables -I INPUT -m set --match-set %s src -p tcp --destination-port %s -j DROP 2>&1", RULE_NAME6,port);
            exec_shell(cmd3, cmd3_result);
            if (strlen(cmd3_result))
            {
                write_log(cmd3_result, LOG_WARNING);
                write_log("警告：未能将ipset配置到ip6tables", LOG_WARNING);
            }
        }

        port = strtok(NULL, delim);
    }

    return 1;
}

/**
 * 添加IP地址到封锁列表
 * @param ip <char *> IP地址或IP地址范围，如：192.168.1.1或192.168.1.2-192.168.1.5
 * @param timeout <int> 自动释放时间
 * @return int
 */
int add_ipset(char *ip, int timeout)
{
    char cmd[128];
    char *is_ipv6 = strstr(ip, ":");
    if (is_ipv6)
    {
        snprintf(cmd, 128, "ipset add %s %s timeout %d -exist 2>&1", RULE_NAME6, ip, timeout);
    }else{
        snprintf(cmd, 128, "ipset add %s %s timeout %d -exist 2>&1", RULE_NAME, ip, timeout);
    }
    char cmd_result[128];
    exec_shell(cmd, cmd_result);
    char _log[128];
    if (is_ipv6){
        // 新增判断：timeout=0时显示"永久封禁"，否则显示秒数
        if (timeout == 0) {
            snprintf(_log, 128, "添加IP：%s,永久封禁，到封锁列表[%s]", ip, RULE_NAME6);
        } else {
            snprintf(_log, 128, "添加IP：%s,过期时间: %d秒，到封锁列表[%s]", ip, timeout, RULE_NAME6);
        }
    }else{
        // 新增判断：timeout=0时显示"永久封禁"，否则显示秒数
        if (timeout == 0) {
            snprintf(_log, 128, "添加IP：%s,永久封禁，到封锁列表[%s]", ip, RULE_NAME);
        } else {
            snprintf(_log, 128, "添加IP：%s,过期时间: %d秒，到封锁列表[%s]", ip, timeout, RULE_NAME);
        }
    }

    write_log(_log, LOG_INFO);
    return 1;
}

/**
 * 从封锁列表删除指定IP
 * @param ip <char *> IP地址或IP地址范围，如：192.168.1.1或192.168.1.2-192.168.1.5
 * @return int
 */
int del_ipset(char *ip)
{

    char cmd[128];
    char cmd2[128];
    char cmd_result[128];
    char *s = strstr(ip, "0.0.0.0");
    char *is_ipv6 = strstr(ip, ":");

    if (s)
    {
        snprintf(cmd, 128, "ipset flush %s 2>&1", RULE_NAME);
        snprintf(cmd2, 128, "ipset flush %s 2>&1", RULE_NAME6);
        char cmd2_result[128];
        exec_shell(cmd2, cmd2_result);
    }
    else
    {
        if(is_ipv6){
            snprintf(cmd, 128, "ipset del %s %s 2>&1", RULE_NAME6, ip);
        }else{
            snprintf(cmd, 128, "ipset del %s %s 2>&1", RULE_NAME, ip);
        }
    }

    exec_shell(cmd, cmd_result);

    char _log[128];
    if (s)
    {
        snprintf(_log, 128, "从封锁列表[%s]删除所有IP", RULE_NAME);
    }
    else
    {
        if(is_ipv6){
            snprintf(_log, 128, "从封锁列表[%s]删除IP:%s", RULE_NAME6, ip);
        }else{
            snprintf(_log, 128, "从封锁列表[%s]删除IP:%s", RULE_NAME, ip);
        }
    }
    write_log(_log, LOG_INFO);
    return 1;
}

/**
 * 初始化运行环境
 * @return void
 */
void init()
{
    write_log("正在初始化运行环境", LOG_INFO);
    if (is_install_iptables() == 0)
    {
        write_log("错误：iptables未安装!", LOG_ERROR);
    }
    if (is_install_ipset() == 0)
    {
        write_log("错误：ipset未安装!", LOG_ERROR);
    }
    if (create_ipset() == 0)
    {
        write_log("错误：ipset创建失败!", LOG_ERROR);
    }
    if (set_ipset_iptables() == 0)
    {
        write_log("错误：设置iptables失败!", LOG_ERROR);
    }
}

/**
 * 删除字符串中的指定字符
 * @param str <char *> 要被处理的字符串
 * @param del_str <char> 要被删除的字符
 * @return void
 */
void strip(char *str, char del_str)
{
    int i, j = 0;
    int len = strlen(str);
    char temp[len + 1];
    memset(temp, 0, sizeof(temp));
    for (i = 0; str[i] != '\0'; i++)
    {
        if (str[i] != del_str)
        {
            temp[j++] = str[i];
        }
    }
    temp[j] = '\0';
    strcpy(str, temp);
}

/**
 * 处理规则文件
 * @return int
 */
int check_filter_file()
{
    //规则文件是否存在
    if (!file_exists(UPDATE_FILE))
        return 0;

    //读取规则文件
    FILE *fp = NULL;
    fp = fopen(UPDATE_FILE, "r");
    int buff_size = 64;
    char buff[buff_size];
    char expstr[128];
    char delim[2] = ",";
    while (fgets(buff, buff_size, fp) != NULL)
    {

        //分割规则行
        char *act, *ips, *timeout, *cur;
        cur = strdup(buff);
        act = strsep(&cur, delim);
        ips = strsep(&cur, delim);
        timeout = strsep(&cur, delim);

        //跳过错误的格式
        if (act == 0 || ips == 0)
        {
            free(cur);
            continue;
        }

        strip(ips, '\n');
        if (is_ipv4(ips) == 0)
        {
            if(is_ipv6(ips) == 0){
                write_log_join("错误的IP地址格式:", ips, LOG_WARNING);
                free(cur);
                continue;
            }
        }

        //添加规则
        if (*act == '+')
        {
            int timeout_val = 0;
            int j; // 提前声明循环变量，兼容C90
            if (timeout != NULL && strlen(timeout) > 0)
            {
                strip(timeout, '\n');
                // 检查timeout是否为数字
                int is_digit = 1;
                for (j=0; timeout[j]!='\0'; j++) { // 此处不再声明int j
                    if (!isdigit(timeout[j])) {
                        is_digit = 0;
                        break;
                    }
                }
                if (!is_digit) {
                    write_log("错误的超时时间（非数字）", LOG_WARNING);
                    free(cur);
                    continue;
                }
                timeout_val = atoi(timeout);
                if (timeout_val < 0) {
                    write_log("错误的超时时间（负数）", LOG_WARNING);
                    free(cur);
                    continue;
                }
            }

            if (strstr(ips, "0.0.0.0"))
            {
                write_log("不能将0.0.0.0添加到封禁列表", LOG_WARNING);
                free(cur);
                continue;
            }
            if (strstr(ips, "127.0.0.1"))
            {
                write_log("不能将127.0.0.1添加到封禁列表", LOG_WARNING);
                free(cur);
                continue;
            }

            add_ipset(ips, timeout_val);

            //删除规则
        }
        else if (*act == '-')
        {
            del_ipset(ips);
        }
        free(cur);
    }
    fclose(fp);

    //删除规则文件
    if (file_exists(UPDATE_FILE))
    {
        remove(UPDATE_FILE);
    }
    return 1;
}

/**
 * 开始监听规则变化
 * @return int
 */
int update_filter()
{
    char pid[8];
    snprintf(pid, 8, "%d", getpid());
    write_file(PID_FILE, pid, "w+");
    write_log("服务已启动", LOG_INFO);
    char pid_msg[16];
    snprintf(pid_msg, 16, "PID: %s", pid);
    write_log(pid_msg, LOG_INFO);

    while (1)
    {
        check_filter_file();
        sleep(1);
    }

    return 0;
}

int main()
{
    init();
    update_filter();
    return 0;
}
