# 正常业务流回归：发一行输入，期待程序打印 done 并正常退出
sendline("hello")
recvuntil("done", timeout=5)
