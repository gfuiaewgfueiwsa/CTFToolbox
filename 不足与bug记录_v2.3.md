# CTFToolbox v2.3 全功能测试 — 不足与 Bug 记录

测试时间：2026-10-09
测试对象：`CTFToolbox 万能 CTF 集合工具箱 v2.3`（Python 3.13.14 + customtkinter，PyInstaller onedir）
测试方式：后端模块单测 51 项 + GUI 自动化 40 项 + GUI 补充（一键分析流水线/媒体中心/网页导航/SSH/工具中心/报告导出）21 项 + 冻结 exe CLI 全样本实测 + 冻结 exe GUI 启动截图 + 冻结态脚本库路径模拟验证 + 便携 Python/ffmpeg 实测。

---

## 一、测试结果总览

| 测试套件 | 结果 | 说明 |
|---|---|---|
| 后端模块（test_backend.py，51 项） | 51 PASS / 0 FAIL | 编码、古典密码、对称/非对称、哈希爆破、NTLM、隐写、图片、压缩包、雕刻、取证、Web、Pwn 模板、分发器、脚本库 88 脚本 |
| GUI 主功能（test_gui.py，40 项） | 40 PASS / 0 FAIL | 编码/密码页、密文加解密页、实用小工具页、专项工具页、Web/Pwn 页、工具中心、脚本库 |
| GUI 补充（test_gui2.py，16 项） | 16 PASS / 0 FAIL | 一键分析 15 样本完整流水线、图片打开/反色/旋转/直方图/EXIF、网页导航、SSH 标签、工具中心卡片 |
| 报告导出（test_gui3.py，5 项） | 5 PASS / 0 FAIL | txt + html 双报告，内容含 flag、结构完整 |
| 冻结 exe CLI（15 个真实样本） | 全部分析成功 | 明文/base64/hex/三重 b64/正常 zip/7z 加密 zip（口令 123456 自动破解）/CRC zip/PNG/伪装 ELF/内嵌 zip 载体/MD5/零宽/空文件/坏 zip/wav |
| 冻结 exe GUI 启动 | 正常，无崩溃 | 标题 v2.3，11 个标签齐全（含「📚 脚本库」），crash.log 无异常 |
| 冻结态脚本库 | 88 条目全部加载 | 模拟 sys.frozen + exe 同级 scripts\library 布局，7 方向计数正确（crypto22/misc18/web15/pwn9/reverse8/forensics8/utils8） |
| 便携运行时 | 正常 | tools\runtime\python（Python 3.11.16）可跑脚本 --selftest；便携 ffmpeg/ffplay 存在且 ffmpeg 可正常探测 wav |

**结论：核心功能全部可用。共发现 7 个应修复问题 + 5 个体验问题，任务⑤已全部修复/复核（状态见下文，最终回归 112 项测试全绿）。**

> 任务⑤修复后状态更新（2026-10-09 晚）：BUG-1~BUG-7、ISSUE-1~ISSUE-3、ISSUE-5 全部修复并回归通过；ISSUE-4 经复核为测试脚本自身产生的警告，生产代码不使用 pyjwt.encode，无需改动。最终 exe 于 2026-10-09 晚重新构建。

---

## 二、Bug 清单（含精确位置）

### BUG-1【已修复】Python 3.13 / OpenSSL 3 下 MD4/NTLM 完全不可用
- 位置：`ctfbox/modules_text.py`
  - 原问题点：哈希计算与 NTLM 弱口令爆破直接调用 `hashlib.new("md4")`
  - 修复：第 485 行新增纯 Python MD4 实现 `_md4_pure()`（RFC 1320）；第 535 行新增 `md4_hex()`（先用 `usedforsecurity=False` 调 OpenSSL，失败再走纯 Python 兜底）；第 548、578 行两处调用点已替换。
- 现象：Python 3.13 的 OpenSSL 3 默认拒绝 MD4，`hashlib.new("md4")` 直接抛 `ValueError: unsupported hash type md4`，导致"计算哈希"的 NTLM 行报错、NTLM 弱口令爆破整体不可用（冻结 exe CLI 跑哈希样本时复现）。
- 验证：RFC 1320 向量（空串→31d6cfe0…、"a"→bde52cb3…）、NTLM("password")=8846f7eaee8fb117ad06bdd830b7586c、NTLM 字典爆破均通过。

### BUG-2【已修复】Web 端口扫描传 list 时崩溃
- 位置：`ctfbox/webtools.py` 第 121 行 `_parse_ports()`
- 现象：该函数只接受字符串，GUI/其他调用方传入 list/tuple 时抛 `AttributeError: 'list' object has no attribute 'split'`。
- 修复：改为支持 str/list/tuple，list/tuple 递归解析并合并端口集合。

### BUG-3【任务⑤已修复】媒体中心工作线程在窗口关闭/主循环未就绪时崩溃
- 位置：`ctfbox/ui_media.py`，工作线程内的 `self.after(0, ...)` 调用：第 776、780、786、823、900、983 行（983 行为图片分析结果回填，已实测复现）。
- 现象：分析任务在后台线程运行时关闭窗口（或主循环暂时不响应），线程回调 `self.after()` 抛 `RuntimeError: main thread is not in main loop`，stderr 打印线程级 Traceback。不杀主进程，但属于未捕获异常，且可能导致结果丢失。
- 复现：test_gui2.py 跑完销毁窗口时，图片分析线程仍在运行。
- 修复：已在 MediaFrame 新增 `_ui(fn)` 助手（after 注册与回调执行双层 try/except，窗口销毁/主循环未就绪时静默丢弃），上述 6 处工作线程回调全部改走 `_ui`；主线程内的 after 不动。回归：test_gui2 关闭窗口时不再出现任何线程 Traceback。

### BUG-4【任务⑤已修复】尾部残缺 ZIP 雕刻后误报"完整性正常"
- 位置：`ctfbox/modules_carve.py` 第 338-342 行
- 现象：从载体尾部雕刻出的 ZIP 只有中央目录+部分数据时，`ZipFile.testzip()` 返回 None（它不实际解压全部数据），软件提示"雕刻 ZIP 完整性正常"，但用户实际解压会报 `negative seek during extraction` 之类错误（10_zip_appended 样本实测：雕刻出的 177 字节尾部 ZIP 即如此），提示语误导。
- 修复：完整性校验改为 testzip() + 逐条 `z.open()` 实际流式读完全部数据，任一失败即报"雕刻 ZIP 数据不完整/可能被截断"并列出失败条目；全部成功才报"完整性正常（可正常解压）"。同时对 dispatcher 多次调用雕刻导致的重复结论/重复"雕刻出"条目做了去重。实测 10_carrier.bin：完整 zip 报"可正常解压"，190 字节尾部残缺 zip 正确报"可能被截断"。

### BUG-5【任务⑤已修复】同一 flag 在一键分析结果中重复上报
- 位置：`ctfbox/dispatcher.py` 第 99 行（原始内容强匹配先报一次）与 `_text_flow` 自动解码链（约 278/295/305/316/324/334/354 行，解码后又报一次）
- 现象：文本本身就含 `flag{...}` 时，报告里同一 flag 出现 2 条记录（CLI 与 GUI 报告树均如此）。
- 修复：已在 `ctfbox/common.py` 的 `Report.add()` 中对 `level=="flag"` 按 detail 去重（同一 Report 实例相同 flag 只留第一条），一处覆盖全部调用点。实测明文样本 flag 由 2 条降为 1 条。注：不同文件（如修复 zip 与雕刻 zip 是不同 Report）各自上报同一 flag 属正常的来源标注，不去重。

### BUG-6【任务⑤收尾阶段发现并修复】"重新镜像离线网页"按钮引用的脚本在工程中缺失
- 位置：`ctfbox/ui_main.py` `_remirror_web()`（约 1540 行）调用工程根 `_mirror_webtools.py`，但该文件在工程中根本不存在；且冻结态下按 `__file__` 上推两级会定位到 `_internal\` 目录，路径同样错误。
- 现象：网页导航页"重新镜像离线网页"按钮在开发态与冻结态都必然失败（脚本不存在/路径错误），用户无法自行刷新离线工具镜像。
- 修复：①新建工程根 `_mirror_webtools.py`（纯标准库：同站静态递归镜像 zero-width/qrazybox/兽音/熊曰/佛论禅，CyberChef 走 GitHub Releases 官方 zip；暂存目录成功才替换、失败保留旧版；自动重写 manifest）；②`ui_main.py` 冻结态改用 `common.APP_DIR` 拼路径，并增加脚本缺失/无 Python 解释器的明确提示；③`build.bat` 增加把该脚本复制到 exe 同级目录的步骤。实测 zero-width（3 文件）、qrazybox（95 文件）、CyberChef v11.5.0（79MB 官方包）镜像成功；pcmoe 三个站点在本机 DNS 解析失败时按设计保留旧目录并回退在线打开。

### BUG-7【任务⑤收尾阶段发现并修复】修复/雕刻两条路径对同一 ZIP 重复分析，flag 与结论重复刷屏
- 位置：`ctfbox/dispatcher.py` `_analyze()` 递归（visited 仅按 路径+大小+时间 去重）、`ctfbox/modules_carve.py` 完整性结论段。
- 现象：10_carrier.bin（13 字节垃圾头 + 完整 ZIP + 190 字节残缺 ZIP）经"文件头修复"得到 repaired zip、又经"ZIP 雕刻"得到 carved zip，两者是同一容器的两份副本（尾部差 13 字节，文件哈希不同），导致 readme/note 子树、flag、ZIP 列表、完整性结论全部重复两遍。
- 修复：①dispatcher 递归层新增内容级去重（递归层文件 SHA256 相同只分析一次）与压缩包成员指纹去重（成员名+CRC+大小一致的容器只分析一次，根级用户文件不去重）；②modules_carve 完整性结论按成员指纹去重（"完整性正常"只报一次），但截断/损坏告警始终逐条保留（残缺包指纹与完整包相同也必须报警）。实测 10 号样本：flag 仅 1 条、完整性正常仅 1 条、残缺 ZIP 截断告警保留。

---

## 三、不合理 / 体验问题（低优先级，任务⑤一并处理）

### ISSUE-1【任务⑤已修复】已含明文 flag 的文本仍刷大量无意义解码链
- 位置：`ctfbox/dispatcher.py` `_text_flow()`
- 现象：明文 flag 样本会继续尝试 Base91/ROT/进制等几十种弱解码，输出大量"看起来像结果但无意义"的解码行，报告噪音大。
- 修复（dispatcher `_text_flow` 自动链式解码展示层）：①恒等解码（输出=输入，如 ROT47→ROT47）一律丢弃；②本文件已拿到强 flag 时，只展示能解出【新】flag 的链；③无 flag 的链必须通过自然语言可读性校验（无控制字符、可打印率≥95%、长度≥8、中文占比≥30% 或 ≥60% 字母落在常见词上），扣除 `xxx{...}` 形状的 50 分加分，挡住 ROT13(flag{...}) 与 Base85/91 乱码假阳性。实测：明文样本解码链 15 行→0 行，普通英文样本乱码链→0，base64/三重 base64 隐写样本仍精确给出唯一解码链与 flag。

### ISSUE-2【任务⑤已修复】"重新镜像离线网页"硬编码 `py -3.13`
- 位置：`ctfbox/ui_main.py` 第 1542 行 `subprocess.run(["py", "-3.13", script], ...)`
- 现象：冻结发布给用户后，用户机器不一定装了 Python 启动器 `py`，该按钮会直接失败；且软件自带便携 Python（tools\runtime\python）却没用上。
- 修复：已改用 `common.external_python()`（冻结态优先 tools/runtime/python 便携解释器，其次系统 Python/py 启动器），找不到解释器时在工具中心日志给出明确提示而不是直接抛异常。

### ISSUE-3【任务⑤已修复】CLI 模式在 PowerShell 重定向时控制台中文乱码
- 现象：`CTFToolbox.exe --cli 文件` 在 PowerShell 管道/重定向场景下中文显示为乱码（控制台代码页 936/UTF-8 不匹配）；**报告文件本身为 UTF-8 完全正常，GUI 完全正常**，仅控制台显示层问题。
- 修复：CLI 入口在 Windows 先 `chcp 65001`，再对 stdout/stderr `reconfigure(encoding="utf-8", errors="replace")`（不支持时 try/except 跳过）；报告文件本就为 UTF-8。

### ISSUE-4【复核：非问题，无需修复】JWT 弱密钥检查时 PyJWT 向 stderr 打印 InsecureKeyLengthWarning
- 复核结论：软件自身的 JWT 检查（`modules_codes.jwt_inspect`、`modules_text.jwt_decode`）使用 hmac/base64 手工实现，**不调用 pyjwt.encode**，生产运行不会产生该警告；测试时看到的警告来自测试脚本自己 `jwt.encode` 造 token，与软件无关，不改。

### ISSUE-5【任务⑤收尾阶段修复】离线网页 manifest 使用绝对路径，程序文件夹改名/搬迁后离线入口失效
- 位置：`tools/portable/webtools/manifest.json`、`ctfbox/webnav.py` `load_offline_manifest()`
- 现象：manifest 中记录的是构建机绝对路径（如 `D:/工具合集软件/CTFToolbox/tools/...`），最终程序文件夹改名为 `CTFToolbox_v2.3` 后路径全部失效，只能靠目录名猜测兜底（CyberChef 入口名不在猜测列表内，必然离线打不开）。
- 修复：`_mirror_webtools.py` 改写 manifest 时统一存相对 webtools 目录的相对路径；`webnav.load_offline_manifest()` 读取时相对路径基于 WEB_DIR 还原为绝对路径，同时兼容旧版绝对路径 manifest。实测改名后 CyberChef/zero-width/qrazybox 三个离线入口均能正确解析。

---

## 四、任务①（上次构建失败）结论（已闭环）

- 根因：`ctfbox/crashguard.py` 的 `install()` 以 append 模式全程持有 `workspace/crash.log` 文件句柄；旧 CTFToolbox.exe 仍在运行时执行 PyInstaller `--clean` 删除 dist 目录，触发 `PermissionError [WinError 5/32]`。
- 修复：`build.bat` 开头增加 `taskkill /F /IM CTFToolbox.exe`（容错），构建前确保句柄释放。本次任务⑤重新构建前会再次确认无 exe 占用。

## 五、任务③遗留说明（非错误）

- exe 的 PE 版本资源已补齐：新增 `version_info.txt`（FileVersion/ProductVersion 2.3.0.0，中英双 StringTable），spec 的 EXE() 已加 `version="version_info.txt"`，右键属性可见「CTFToolbox 万能 CTF 集合工具箱」与 2.3.0.0。
- `ctfbox/__init__.py` 的 `__version__` 已由旧的 1.0.0 更新为 2.3.0。
- robocopy 退出码 1 在其语义中为"成功复制了文件"（0-7 均成功，≥8 才失败），shell 包装层显示 failed exit code 1 属误报，源/目标文件数与字节数核对一致。

## 六、未做自动化覆盖的范围（如实声明，建议人工抽查）

以下功能依赖真实网络/外设/交互式窗口，自动化环境不具备，未做端到端实测，代码路径已走读且按钮实例化无异常：
1. SSH 终端真实连接（需可用的 SSH 目标与凭据）；
2. 媒体中心视频播放、音频播放（ffplay 弹窗）、GIF 逐帧播放的实际画面（ffmpeg/ffplay 二进制已验证存在且 ffmpeg 探测正常）；
3. 工具中心的 winget 在线安装（Nmap/Wireshark）、"补全便携运行时"在线下载、"一键补齐 Kali 套件"；
4. sqlmap 对真实靶场的注入跑批；
5. "重新镜像离线网页"联网流程（且该按钮存在 ISSUE-2，任务⑤修复）；
6. 资源管理器拖文件入窗的拖放动作；
7. 外部工具按钮实际拉起 Ghidra/x64dbg/dnSpy/DIE/radare2/ExifTool（路径检测均显示"已就绪"）。

## 七、任务⑤修复与回归结果（已完成）

1. BUG-3（ui_media 线程安全回填 `_ui`）、BUG-4（雕刻 ZIP 真实试解压校验 + 重复结论去重）、BUG-5（Report 级 flag 去重）全部修复；
2. ISSUE-1（解码链降噪，含恒等链/形状加分/可读性门槛三重过滤）、ISSUE-2（镜像按钮改用 external_python 便携解释器）、ISSUE-3（CLI chcp 65001 + UTF-8 reconfigure）修复；ISSUE-4 复核为非问题；
3. 收尾阶段又发现并修复 BUG-6（重新镜像按钮引用的 `_mirror_webtools.py` 工程中缺失 + 冻结态路径错误，已补脚本并修正路径与 build.bat）、BUG-7（修复/雕刻双路径重复分析同一 ZIP，已加 SHA256 内容去重 + 压缩包成员指纹去重）、ISSUE-5（manifest 改相对路径，程序文件夹可整体搬迁）；
4. 最终回归（全部修复后代码）：后端 51/51、GUI 40/40、GUI 补充 16/16、报告导出 5/5、冻结态脚本库 89 文件，全部 PASS，无线程异常；
5. 最终 PyInstaller 重新构建（2026-10-09 18:20 后，PE 版本 2.3.0.0），部署后 scripts 89 文件、_mirror_webtools.py 位于 exe 同级、tools 离线镜像刷新（CyberChef v11.5.0 / zero-width / qrazybox，manifest 相对路径）；
6. 冻结 exe 复验：CLI 明文样本仅 1 条 flag 且零解码噪音、base64 样本唯一解码链命中、MD5 样本爆破 password、加密 zip 口令 123456、10 号载体 flag 仅 1 条且残缺 zip 正确提示截断；GUI 启动正常无崩溃；
7. 随后清理 build/、__pycache__、workspace 测试产物、测试脚本与样本，最终工作目录只保留：最新源码文件夹、最新源码 zip、程序文件夹（exe+_internal+tools）、题解（Polar 靶场题解.md，未改动）。
