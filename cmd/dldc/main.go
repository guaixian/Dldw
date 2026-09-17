// dldc 是 dldw 的中转模式入口（与 cmd/dldw 同一程序主体）：
//
//	dldc <tool> [args...]     # 所有流量强制经服务端隧道中转（不做缓存）
//	例：dldc git clone <url>、dldc curl <url>
//
// 需要服务端 tunnel.mode: relay_all（否则非白名单域名会被拒绝）。
// 等价写法：dldw relay <tool> [args...]；也可直接把 dldw.exe 复制为
// dldc.exe（程序按自身文件名识别模式）。
package main

import (
	"os"

	"dldw/internal/client/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
