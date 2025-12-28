package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	// DEFAULT_PORT 默认端口
	DEFAULT_PORT = "8000"
	// DEFAULT_TIMEOUT 默认请求超时时间（5分钟）
	DEFAULT_TIMEOUT = 5 * time.Minute
	// DEFAULT_MAX_BODY_SIZE 默认最大请求体大小（100MB）
	DEFAULT_MAX_BODY_SIZE = 100 * 1024 * 1024
	// DEFAULT_API_PROXY_CONFIG 默认代理配置
	DEFAULT_API_PROXY_CONFIG = `{"openai": "https://api.openai.com"}`
)

var (
	// httpClient HTTP 客户端实例
	httpClient *http.Client
	// proxyURL 代理地址
	proxyURL *url.URL
	// apiProxyConfig 路径前缀到目标 URL 的映射
	apiProxyConfig map[string]string
	// timeout 请求超时时间（可通过环境变量配置）
	timeout time.Duration
	// maxBodySize 最大请求体大小（可通过环境变量配置）
	maxBodySize int64
)

/**
 * 加载 .env 文件
 */
func loadEnv() {
	file, err := os.Open(".env")
	if err != nil {
		return // .env 文件不存在，跳过
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			// 只设置未设置的环境变量
			if os.Getenv(key) == "" {
				os.Setenv(key, value)
			}
		}
	}
}

/**
 * 加载配置参数
 */
func loadConfig() {
	// 加载 API_PROXY_CONFIG
	configJSON := os.Getenv("API_PROXY_CONFIG")
	if configJSON == "" {
		configJSON = DEFAULT_API_PROXY_CONFIG
	}

	apiProxyConfig = make(map[string]string)
	if err := json.Unmarshal([]byte(configJSON), &apiProxyConfig); err != nil {
		log.Fatalf("Failed to parse API_PROXY_CONFIG: %v", err)
	}

	if len(apiProxyConfig) == 0 {
		log.Fatal("API_PROXY_CONFIG is empty, at least one proxy configuration is required")
	}

	// 加载 TIMEOUT（单位：秒）
	timeoutStr := os.Getenv("TIMEOUT")
	if timeoutStr != "" {
		if timeoutSec, err := strconv.Atoi(timeoutStr); err == nil && timeoutSec > 0 {
			timeout = time.Duration(timeoutSec) * time.Second
		} else {
			log.Printf("Invalid TIMEOUT value: %s, using default", timeoutStr)
			timeout = DEFAULT_TIMEOUT
		}
	} else {
		timeout = DEFAULT_TIMEOUT
	}

	// 加载 MAX_BODY_SIZE（单位：MB）
	maxBodySizeStr := os.Getenv("MAX_BODY_SIZE")
	if maxBodySizeStr != "" {
		if sizeMB, err := strconv.Atoi(maxBodySizeStr); err == nil && sizeMB > 0 {
			maxBodySize = int64(sizeMB) * 1024 * 1024
		} else {
			log.Printf("Invalid MAX_BODY_SIZE value: %s, using default", maxBodySizeStr)
			maxBodySize = DEFAULT_MAX_BODY_SIZE
		}
	} else {
		maxBodySize = DEFAULT_MAX_BODY_SIZE
	}
}

/**
 * 初始化 HTTP 客户端
 */
func initHTTPClient() {
	// Keep-Alive 配置（默认启用）
	enableKeepAlive := os.Getenv("ENABLE_KEEPALIVE") != "false"

	transport := &http.Transport{
		MaxIdleConns:        1000,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   !enableKeepAlive,
		DisableCompression:  false,
	}

	// 配置代理
	httpProxy := os.Getenv("HTTP_PROXY")
	if httpProxy != "" {
		var err error
		proxyURL, err = url.Parse(httpProxy)
		if err != nil {
			log.Printf("Invalid proxy URL: %v", err)
		} else {
			transport.Proxy = http.ProxyURL(proxyURL)
			log.Printf("Using proxy: %s", httpProxy)
		}
	}

	httpClient = &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			return nil
		},
	}
}

/**
 * CORS 中间件
 */
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Access-Control-Allow-Origin")
		if origin == "" {
			origin = "*"
		}

		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

/**
 * 检查请求是否为流式传输
 */
func isStreamRequest(body []byte) bool {
	if len(body) == 0 {
		return false
	}

	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return false
	}

	stream, ok := data["stream"].(bool)
	return ok && stream
}

/**
 * 复制 HTTP 头部（排除特定头部）
 */
func copyHeaders(dst http.Header, src http.Header) {
	for key, values := range src {
		// 跳过 Host、连接相关头部和 IP 相关头部
		lowerKey := strings.ToLower(key)
		if lowerKey == "host" || lowerKey == "connection" ||
		   lowerKey == "content-length" || lowerKey == "transfer-encoding" ||
		   lowerKey == "x-forwarded-for" || lowerKey == "x-real-ip" {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

/**
 * 主代理处理函数
 */
func proxyHandler(w http.ResponseWriter, r *http.Request) {
	// 根路径重定向
	if r.URL.Path == "/" {
		http.Redirect(w, r, "https://www.bilibili.com/video/BV1AM4y1M71p/?spm_id_from=..search-card.all.click&vd_source=202e4935d40ec347ce7874800ad3fb26", http.StatusFound)
		return
	}

	// 解析路径前缀，找到对应的目标 URL
	path := strings.TrimPrefix(r.URL.Path, "/")
	pathParts := strings.SplitN(path, "/", 2)

	if len(pathParts) == 0 {
		http.Error(w, "Invalid request path", http.StatusBadRequest)
		return
	}

	prefix := pathParts[0]
	targetBaseURL, exists := apiProxyConfig[prefix]
	if !exists {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "Path prefix not found",
			"message": fmt.Sprintf("No proxy configuration for prefix: %s", prefix),
		})
		return
	}

	// 构建目标 URL
	var targetPath string
	if len(pathParts) == 2 {
		targetPath = "/" + pathParts[1]
	} else {
		targetPath = "/"
	}

	if r.URL.RawQuery != "" {
		targetPath += "?" + r.URL.RawQuery
	}

	targetURL := targetBaseURL + targetPath

	// 读取请求体
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize))
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// 检查是否为流式请求
	isStream := r.Method == "POST" && isStreamRequest(body)

	// 创建代理请求
	proxyReq, err := http.NewRequest(r.Method, targetURL, bytes.NewReader(body))
	if err != nil {
		log.Printf("Error creating proxy request: %v", err)
		http.Error(w, "Failed to create proxy request", http.StatusInternalServerError)
		return
	}

	// 复制请求头
	copyHeaders(proxyReq.Header, r.Header)

	// 发送请求
	resp, err := httpClient.Do(proxyReq)
	if err != nil {
		log.Printf("Proxy error: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "Proxy request failed",
			"message": err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	// 复制响应头
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	// 处理响应体
	if isStream {
		// 流式传输
		io.Copy(w, resp.Body)
	} else {
		// 非流式传输
		io.Copy(w, resp.Body)
	}
}

/**
 * 获取配置的所有前缀键
 */
func getConfigKeys() []string {
	keys := make([]string, 0, len(apiProxyConfig))
	for k := range apiProxyConfig {
		keys = append(keys, k)
	}
	return keys
}

/**
 * 主函数
 */
func main() {
	// 加载 .env 文件
	loadEnv()

	// 加载配置参数
	loadConfig()

	// 初始化 HTTP 客户端
	initHTTPClient()

	// 获取端口
	port := os.Getenv("PORT")
	if port == "" {
		port = DEFAULT_PORT
	}

	// 设置路由
	http.HandleFunc("/", corsMiddleware(proxyHandler))

	// 创建 HTTP 服务器
	addr := ":" + port
	server := &http.Server{
		Addr:         addr,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: timeout + 10*time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// 打印启动信息
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Proxy server running on port %s\n", port)
	fmt.Printf("Timeout: %.0fs\n", timeout.Seconds())
	fmt.Printf("Max Idle Connections: 1000\n")

	// 显示 Keep-Alive 状态
	enableKeepAlive := os.Getenv("ENABLE_KEEPALIVE") != "false"

	if enableKeepAlive {
		fmt.Println("Keep-Alive: ENABLED (连接复用，高性能)")
	} else {
		fmt.Println("Keep-Alive: DISABLED (每次请求新建连接，支持 IP 轮换)")
	}

	fmt.Printf("Optimized for: High Concurrency\n")
	if proxyURL != nil {
		fmt.Printf("Using proxy: %s\n", proxyURL.String())
	} else {
		fmt.Println("No proxy configured")
	}

	// 显示代理配置
	fmt.Println("\nProxy Path Mappings:")
	for prefix, target := range apiProxyConfig {
		fmt.Printf("  /%s/* => %s/*\n", prefix, target)
	}
	fmt.Println(strings.Repeat("=", 60))

	// 启动服务器（在 goroutine 中）
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// 等待中断信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// 优雅关闭
	log.Println("\nShutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}
