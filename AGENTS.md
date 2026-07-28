# Agent Instructions

本项目默认使用以下约定：

- 保持 `AGENTS.md` 和 `project_context.md` 两个项目说明文件存在并及时更新。
- `AGENTS.md` 记录给 Codex/自动化代理的协作规则、常用命令、注意事项。
- `project_context.md` 记录项目背景、目录结构、运行方式、关键决策和当前上下文。
- 修改项目结构、构建流程或关键依赖后，应同步更新相关说明。

## Hot 100 C++

- 题解模块位于 `hot100_cpp/`，参考题目清单来自 `E:\Code\leetcode-hot100`。
- 题解统一维护在 `hot100_cpp/include/hot100.hpp`，每题使用 `hot100::pNNN` 命名空间隔离同名 `Solution` 类。
- 直接验证命令：`g++ -std=c++17 -Wall -Wextra -Wpedantic -I hot100_cpp/include hot100_cpp/tests/hot100_tests.cpp -o hot100_cpp/hot100_tests.exe`，随后运行 `hot100_cpp/hot100_tests.exe`。
- 也可使用 `cmake -S hot100_cpp -B hot100_cpp/build`、`cmake --build hot100_cpp/build`、`ctest --test-dir hot100_cpp/build --output-on-failure`。
