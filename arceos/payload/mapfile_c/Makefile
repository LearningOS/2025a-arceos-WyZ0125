# 使用已安装的 riscv64-linux-gnu-gcc 编译器
CC = riscv64-linux-gnu-gcc

# 编译选项：静态链接、优化级别、添加调试信息
CFLAGS = -static -O2 -Wall -Wextra

# 目标文件
TARGET = mapfile

# 默认目标
all: $(TARGET)

# 编译规则
$(TARGET): mapfile.c
	$(CC) $(CFLAGS) $< -o $@

# 清理规则
clean:
	rm -f $(TARGET) *.o

# 安装规则（可选）
install: $(TARGET)
	cp $(TARGET) ../