#gomasscan
gomasscan是一个纯go编写的masscan扫描库

##前提

 - 只支持darwin/linux
 - 需要高权限
 - 需要安装libpcap
 
##使用
    
```go
package main

import (
    "fmt"
    "github.com/lcvvvv/gomasscan"
    "time"
)

func main() {
	//创建扫描器对象
	client, err := gomasscan.NewScanner()
	if err != nil {
		panic(err)
	}
	defer client.Done()
	//开放端口处理函数
	client.HandlerOpen = func(ip string, port int) {
		//输出开放端口
		fmt.Println(ip, port)
	}
	//将IP地址加入筛选范围内
	var ip = "192.168.0.1"
	var startTime = time.Now()
	_ = client.Add(ip)
    //开始扫描
	go func() {
		for i:=0;i<65536;i++{
			client.SendSYN(ip, i, gomasscan.SYN)
		}
	}()
	for {
		time.Sleep(time.Second)
		elapsed := time.Since(startTime)
		seconds := elapsed.Seconds()
		fmt.Println("发包量", client.Count()/uint64(seconds), "/s")
	}

}
```

##感谢

 - [naabu](https://github.com/projectdiscovery/naabu)
 - [masscan](https://github.com/zan8in/masscan)