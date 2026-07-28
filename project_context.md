# Project Context

## 项目概览

当前项目位于 `E:\Code\dpdk`。

## 当前产物

- `outputs/曹景龙-自我介绍.pptx`：基于个人简历生成的 16:9 自我介绍演示文稿，项目图片缺失处使用可编辑矩形占位框。
- `outputs/极简蓝白学术汇报模板.pptx`：12 页、16:9 的可编辑学术汇报模板，覆盖研究背景、相关工作、方法、实验、图表、讨论、结论与问答等常用版式。
- `outputs/曹景龙-自我介绍-极简蓝白项目版.pptx`：基于 2026-01 极简单栏版简历和极简蓝白学术汇报模板生成的 10 页自我介绍演示文稿，按个人简介、工作项目、其他项目、技术栈及研究成果组织；7 个项目各占一页，并保留可编辑图片矩形占位框。
- `hot100_cpp/`：参考 `E:\Code\leetcode-hot100` 的题目集合新增的 C++17 Hot 100 题解模块。100 道题集中在 `include/hot100.hpp`，按题号命名空间隔离；包含公共 LeetCode 节点类型、复杂度索引、CMake 配置和逐题样例测试。

## Hot 100 C++ 运行方式

```powershell
g++ -std=c++17 -Wall -Wextra -Wpedantic -I hot100_cpp/include hot100_cpp/tests/hot100_tests.cpp -o hot100_cpp/hot100_tests.exe
hot100_cpp/hot100_tests.exe
```

预期输出：`Hot 100 C++ smoke tests passed`。

## 维护约定

- 本文件用于记录项目背景、当前状态、关键路径和开发上下文。
- `AGENTS.md` 用于记录 Codex/自动化代理协作规则。
- 后续新增重要模块、构建方式、运行方式或排查经验时，应同步补充到本文件。
