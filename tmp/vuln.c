#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* 故意留下两个典型 AWDP 漏洞：
 * 1) main 中 read 长度过大 -> 栈溢出
 * 2) vuln_uaf 中 free 后未置空 + double free
 */
static char *g_ptr;

void vuln_uaf(void) {
    g_ptr = (char *)malloc(0x30);
    strcpy(g_ptr, "hello");
    free(g_ptr);
    /* UAF: free 后未置空 */
    if (g_ptr) {
        puts(g_ptr);
    }
    free(g_ptr); /* double free */
}

int read_input(void) {
    char buf[64];
    puts("input:");
    int n = read(0, buf, 0x200); /* 溢出：buf 只有 64 */
    buf[63] = 0;
    printf("got %d bytes\n", n);
    return n;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln_uaf();
    read_input();
    puts("done");
    return 0;
}

/* 供 code cave 注入测试用的空隙（可执行段内的连续 0x00） */
__attribute__((used, section(".text"), aligned(16)))
const char mistyfix_cave[512] = {0};
