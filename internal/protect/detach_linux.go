package protect

import "syscall"

// detachedSysProcAttr 让回滚倒计时子进程脱离父会话独立存活。
func detachedSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
