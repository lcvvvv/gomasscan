package gomasscan

import (
	"fmt"
	"testing"
	"time"
)

func TestScanner(t *testing.T) {
	//创建扫描器对象
	client, err := NewScanner()
	if err != nil {
		panic(err)
	}
	defer client.Done()
	//开放端口处理函数
	client.HandlerOpen = func(ip string, port int) {
		fmt.Println(ip, port)
	}

	var ip = "192.168.0.1"
	//将IP地址加入筛选范围内
	err = client.Add(ip)
	if err != nil {
		panic(err)
	}
	startTime := time.Now()
	fmt.Println("开始发送数据")
	go func() {
		for {
			client.SendSYN(ip, 81, SYN)
		}
	}()
	client.SetRate(655350)
	time.Sleep(time.Second)
	for {
		elapsed := time.Since(startTime)
		seconds := elapsed.Seconds()
		fmt.Println("发包量", client.Count()/uint64(seconds), "/s")
		time.Sleep(time.Second * 5)
	}

}
