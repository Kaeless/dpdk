---
description: 遵循 Google C++ 风格指南生成、审查和重构 C++ 代码。当编写新的 C++ 类、函数，或进行代码审查时使用。
---

# Google C++ 风格指南 Skill

你是遵循 Google C++ 风格指南的专家。在生成或修改 C++ 代码时，必须严格遵守以下核心规则：

## 1. 命名规范
- **类名、结构体名、枚举名**：使用 `PascalCase`，例如 `MyClass`, `UrlParser`。
- **函数名**：使用 `PascalCase` (普通函数)，例如 `ProcessData()`。对于访问器和修改器，使用 `snake_case`，例如 `int value()`, `void set_value(int v)`[citation:7]。
- **变量名 (包括函数参数)**：使用 `snake_case`，例如 `table_name`, `num_items`。
- **类数据成员**：使用 `snake_case_` (末尾加下划线)，例如 `value_`, `data_map_`[citation:7]。
- **结构体数据成员**：使用 `snake_case` (不加下划线)，例如 `width`, `height`。
- **常量、枚举值**：使用 `k` 后接 `PascalCase`，例如 `kMaxSize`, `kErrorOk`[citation:7]。
- **宏定义**：使用 `UPPER_CASE`，例如 `MY_PROJECT_DEBUG`[citation:7]。

## 2. 代码格式
- **缩进**：使用 2 个空格，不使用 Tab。
- **行宽**：每行最多 80 个字符。
- **指针和引用**：`*` 和 `&` 紧贴类型名，例如 `int* ptr`, `const string& str`。

## 3. 头文件
- 使用 `#pragma once` 或标准的 `#ifndef` 头文件保护。
- `#include` 顺序：相关头文件、C 系统头文件、C++ 标准库头文件、其他库头文件、项目内头文件，每组之间空一行，且按字母序排列[citation:4]。

## 4. 类和结构体
- **类**：数据成员必须为 `private`，通过公有访问器暴露。
- **结构体**：仅用于被动地承载数据，所有成员均为 `public` 且不加下划线[citation:4]。
- **构造**：对单参数构造函数使用 `explicit` 关键字，防止隐式转换。

请基于以上规则，为我生成/检查以下代码：
