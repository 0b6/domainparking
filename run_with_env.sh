#!/bin/bash

# 指定 YAML 文件的路径
YAML_FILE="deploy/compose.yml"

# 使用 yq 从 YAML 文件中提取环境变量并导出
export $(yq e '.services.parking.environment[]' "$YAML_FILE" | xargs)

# 运行 Go 程序
go run *.go
