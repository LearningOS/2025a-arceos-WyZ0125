# 使用已安装的 riscv64-linux-gnu-gcc 编译器
CC = riscv64-linux-gnu-gcc

# 编译选项：静态链接、优化级别、添加调试信息
CFLAGS = -static -O2 -Wall -Wextra
TARGET := hello

CC := riscv64-linux-musl-gcc
STRIP := riscv64-linux-musl-strip

all: $(TARGET)

%: %.c
	$(CC) -static $< -o $@
	$(STRIP) $@

clean:
	@rm -rf ./$(TARGET)
