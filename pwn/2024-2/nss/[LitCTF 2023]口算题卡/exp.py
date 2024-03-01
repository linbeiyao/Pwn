from pwn import *
context.log_level = 'debug'
p = remote('node4.anna.nssctf.cn',28034)

import re


# 定义一个函数来解析问题并计算结果
def solve_problem(problem):
    # 使用正则表达式提取数字
    nums = re.findall(r'\d+', problem)
    # 将提取到的数字转换为整数
    num1 = int(nums[0])
    num2 = int(nums[1])
    # 提取运算符
    operator = re.search(r'(\+|\-)', problem).group()
    # 根据运算符计算结果
    if operator == '+':
        return num1 + num2
    elif operator == '-':
        return num1 - num2
    else:
        return None

# 接收并解析问题并计算答案
for _ in range(100):
    p.recvuntil(b'What is ')
    problem = p.recvuntil(b'?').strip().decode()  # 接收并解析问题
    result = solve_problem(problem)  # 解析问题并计算结果
    p.sendline(str(result))  # 将答案发送给服务器
p.interactive()

# 接收并打印最终的标志
#print(p.recvall().decode())

