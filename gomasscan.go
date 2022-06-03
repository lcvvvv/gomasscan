package main

import (
	"fmt"
	"gomasscan/scanner"
	"sync"
	"time"
)

func main() {
	//创建扫描器对象
	client, err := scanner.NewScanner()
	if err != nil {
		panic(err)
	}
	defer client.Done()
	//初始化
	err = client.Init()
	if err != nil {
		panic(err)
	}
	//开放端口处理函数
	client.HandlerOpen = func(ip string, port int) {
		fmt.Println(ip, port)
	}
	var ip = "192.168.20.1"
	//将IP地址加入筛选范围内
	err = client.Add(ip)
	if err != nil {
		panic(err)
	}
	time.Sleep(time.Second * 3)
	fmt.Println("开始发送数据")
	for i := 1; i < 65535; i++ {
		client.SendSYN(ip, i, scanner.SYN)
		time.Sleep(time.Microsecond * 200)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	wg.Wait()
}
