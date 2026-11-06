# logids - 轻量级日志入侵检测与风险告警工具
CC      ?= gcc
CFLAGS  := -std=c99 -O2 -Wall -Wextra -Isrc
SRC     := $(wildcard src/*.c)
TARGET  := logids

.PHONY: all clean demo

all: $(TARGET)

$(TARGET): $(SRC) src/logids.h
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

# 用样例日志跑一遍演示
demo: $(TARGET)
	./$(TARGET) -c config.ini samples/auth.log samples/access.log samples/firewall.log -o report.csv

clean:
	rm -f $(TARGET) $(TARGET).exe report.csv
