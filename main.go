package main

import (
	"context"
	"embed"
	"github.com/cyber-xxm/cyber-gin/v1/internal/bootstrap"
	"sync"
)

// 资源目录，内置到执行程序中
//
//go:embed resources
var resources embed.FS

// Usage: go build -ldflags "-X main.VERSION=x.x.x"
var (
	VERSION = "v10.1.0"
	wg      = sync.WaitGroup{}
)

// @title gin-admin
// @version v10.1.0
// @description A lightweight, flexible, elegant and full-featured RBAC scaffolding based on GIN + GORM 2.0 + Casbin 2.0 + Wire DI.
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
// @schemes http https
// @basePath /
func main() {

	ctx := context.Background()

	//全局初始化 每个应用都必须调用的
	//cef.GlobalInit(nil, &resources)
	////创建应用
	//cefApp := cef.NewApplication()
	//if common.IsDarwin() {
	//	cefApp.SetUseMockKeyChain(true)
	//}
	////chromium 配置
	//config := cef.BrowserWindow.Config.ChromiumConfig()
	//config.SetEnableMenu(true)     //启用右键菜单
	//config.SetEnableDevTools(true) //启用开发者工具
	//cef.BrowserWindow.Config.Title = "Energy - Local load"
	//// 本地加载资源方式, 直接读取本地或内置执行文件资源
	//// 该模块不使用 http server
	//// 默认访问地址fs://energy/index.html, 仅能在应用内访问
	////   fs: 默认的自定义协议名, 你可以任意设置
	////   energy: 默认的自定义域, 你可以任意设置
	////   index.html: 默认打开的页面名，你可以任意设置
	//// 页面ajax xhr数据获取
	//// xhr数据获取通过Proxy配置, 支持http, https证书配置
	//cef.BrowserWindow.Config.Url = "fs://energy" // 设置默认
	//cef.BrowserWindow.Config.LocalResource(cef.LocalLoadConfig{
	//	Scheme:     "fs",             // 自定义协议名
	//	Domain:     "energy",         // 自定义域名
	//	ResRootDir: "resources/dist", // 资源存放目录, FS不为空时是内置资源目录名, 空时当前文件执行目录, @/to/path @开头表示当前目录下开始
	//	FS:         resources,        //静态资源所在的 embed.FS
	//	Proxy: &cef.XHRProxy{ // 页面Ajax XHR请求接口代理转发配置
	//		Scheme: consts.LpsTcp, // http's 支持ssl配置
	//		IP:     "127.0.0.1",   //http服务ip或domain
	//		Port:   8040,
	//		//SSL: cef.XHRProxySSL{ // ssl 证书配置,如果使用https但未配置该选项，默认跳过ssl检查
	//		//	FS:      resources,          //如果证书内置到exe中,需要在此配置 embed.FS
	//		//	RootDir: "resources/ssl",    //证书存放目录
	//		//	Cert:    "demo.pem",         //ssl cert
	//		//	Key:     "demo.key",         //ssl key
	//		//	CARoots: []string{"ca.cer"}, // ssl ca root
	//		//},
	//	},
	//}.Build())
	//cef.SetBrowserProcessStartAfterCallback(func(success bool) {
	//	go func() {
	//
	//	}()
	//	// 等待直到 Gin 服务启动成功
	//	for {
	//		time.Sleep(500 * time.Millisecond) // 每隔 500ms 检查一次
	//		resp, err := http.Get("http://localhost:8040/api/v1/captcha/id")
	//		if err == nil && resp.StatusCode == http.StatusOK {
	//			fmt.Println("Gin server is up and running!")
	//			break
	//		}
	//	}
	//})
	////运行应用
	//cef.Run(cefApp)

	err := bootstrap.Run(ctx, bootstrap.RunConfig{
		WorkDir: "/Users/xxm/Documents/Workspace/GolandProjects/cyber-gin/configs",
		Configs: "dev",
		//StaticDir: "resources/dist",
	})
	if err != nil {
		panic(err)
	}
}
