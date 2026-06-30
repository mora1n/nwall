package conf

import "os"

// writeFile 是测试辅助：写入字符串到文件。
func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
