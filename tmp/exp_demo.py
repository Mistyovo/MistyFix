# 模拟 exp：溢出尝试，修复后不应拿到 flag（防御成功 = PASS）
sendline(b"A" * 300)
