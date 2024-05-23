package main

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"math/big"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"net/http"
)

var (
	logger *zap.Logger
	cfg    *viper.Viper
)

type RequestBody struct {
	Network string `json:"network"`
	Address string `json:"address"`
}

type ApiResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"` // 使用 interface{} 类型允许这个字段保存任何类型的数据
}

type RateLimiter struct {
	lastRequestTime map[string]time.Time // 存储每个用户的最后一次请求时间
	mu              sync.Mutex           // 互斥锁，用于保护并发访问
	requestInterval time.Duration        // 请求时间间隔
}

// 创建一个新的 RateLimiter 实例
func NewRateLimiter(interval time.Duration) *RateLimiter {
	return &RateLimiter{
		lastRequestTime: make(map[string]time.Time),
		requestInterval: interval,
	}
}

// 中间件函数，用于限制每个用户每24小时只能请求一次
func (rl *RateLimiter) Limit() gin.HandlerFunc {
	return func(c *gin.Context) {
		address := c.Query("address") // 假设从查询参数中获取用户ID

		rl.mu.Lock()
		defer rl.mu.Unlock()

		lastTime, ok := rl.lastRequestTime[address]
		if ok && time.Since(lastTime) < rl.requestInterval {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "Only one request allowed per specified interval"})
			c.Abort()
			return
		}

		// 更新用户的最后一次请求时间
		rl.lastRequestTime[address] = time.Now()

		c.Next()
	}
}

func main() {
	var err error
	// 初始化日志记录器
	initLogger()
	defer func(logger *zap.Logger) {
		err := logger.Sync()
		if err != nil {
			fmt.Println("Failed to sync logger:", err)
		}
	}(logger)
	logger, err = zap.NewProduction()

	// 初始化配置管理器

	cfg, err = initConfig()
	if err != nil {
		logger.Error("Failed to initialize config", zap.Error(err))
		os.Exit(1)
	}
	// 创建 Gin 引擎
	r := gin.Default()
	rateLimiterStr := cfg.GetString("rate_limiter")
	rateLimiter, err := strconv.Atoi(rateLimiterStr)
	if err != nil {
		panic(err)
	}

	limiter := NewRateLimiter(time.Duration(rateLimiter) * time.Hour)

	r.Use(limiter.Limit())
	// 设置路由
	r.POST("/sepolia/request", sepolia)
	r.POST("/goerli/request", goerli)

	// 启动 HTTP 服务器
	port := cfg.GetInt("port")
	err = r.Run(":" + strconv.Itoa(port))
	if err != nil {
		logger.Fatal("Failed to start server", zap.Error(err))
	}
}

func sepolia(c *gin.Context) {
	handleWithdraw(c)
}

func goerli(c *gin.Context) {
	handleWithdraw(c)
}

// handleWithdraw 处理领水请求
func handleWithdraw(c *gin.Context) {
	var requestBody RequestBody
	fmt.Println(requestBody)
	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: err.Error(),
		})
		return
	}

	Address := requestBody.Address
	if !common.IsHexAddress(Address) {
		c.JSON(http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "The Ethereum wallet address you entered does not meet the standard format. Please check and enter a valid wallet address.",
		})
		return
	}
	amount := big.NewInt(cfg.GetInt64("amount"))
	amount.Mul(amount, big.NewInt(1e18))

	network := requestBody.Network
	nodeURL := cfg.GetString(network + ".node_url")
	senderAddress := cfg.GetString(network + ".sender_address")
	client, err := ethclient.Dial(nodeURL)
	if err != nil {
		logger.Error("Failed to connect to Ethereum client", zap.Error(err))
		c.JSON(http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to connect to Ethereum client",
		})
		return
	}
	defer client.Close()

	privateKeyString := cfg.GetString(network + ".private_key")
	// 将私钥字符串转换为ECDSA私钥
	privateKey, err := crypto.HexToECDSA(privateKeyString)
	if err != nil {
		logger.Error("Failed to decode private key", zap.Error(err))
		c.JSON(http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to decode private key",
		})
		return
	}

	toAddress := common.HexToAddress(Address)

	// 初始化发送地址
	fromAddress := common.HexToAddress(senderAddress)

	// 获取nonce值，即从该发送地址出的交易数量
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		logger.Error("Failed to get nonce", zap.Error(err))
		c.JSON(http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Internal error",
		})
		return
	}

	// 获取当前的燃气价格
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		logger.Error("Failed to suggest gas price", zap.Error(err))
		c.JSON(http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Internal error",
		})
		return
	}
	gasLimit := uint64(21000)
	gasTinCap, err := client.SuggestGasTipCap(context.Background())
	if err != nil {
		logger.Error("Failed to suggest gas price", zap.Error(err))
		c.JSON(http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Internal error",
		})
		return
	}
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		logger.Error("Failed to get network ID", zap.Error(err))
		c.JSON(http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to get network ID",
		})
		return
	}
	// 创建交易对象
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		GasTipCap: gasTinCap,
		GasFeeCap: gasPrice,
		Gas:       gasLimit,
		To:        &toAddress,
		Value:     amount,
		Data:      nil,
	})
	signedTx, err := types.SignTx(tx, types.NewLondonSigner(chainID), privateKey)
	if err != nil {
		logger.Error("Failed to sign transaction", zap.Error(err))
		c.JSON(http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to sign transaction",
		})
		return
	}

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		logger.Error("Failed to send transaction", zap.Error(err))
		c.JSON(http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to withdraw: %s", err.Error()),
		})
		return
	}
	type Data struct {
		TxID        string `json:"tx_id"`
		ExplorerUrl string `json:"explorer_url"`
	}
	explorerUrl := fmt.Sprintf("https://%s.etherscan.io/", network)
	c.JSON(http.StatusOK, ApiResponse{
		Success: true,
		Message: signedTx.Hash().Hex(),
		Data: Data{
			TxID:        signedTx.Hash().Hex(),
			ExplorerUrl: explorerUrl,
		},
	})
}

// initLogger 初始化日志记录器
func initLogger() {
	var err error
	logger, err = zap.NewProduction()
	if err != nil {
		fmt.Println("Failed to initialize logger:", err)
		os.Exit(1)
	}
}

// initConfig 初始化配置管理器
func initConfig() (*viper.Viper, error) {
	v := viper.New()
	v.SetConfigName("config")
	v.AddConfigPath("./configs")
	v.SetConfigType("yaml")

	err := v.ReadInConfig()
	if err != nil {
		return nil, err
	}
	logger.Info("Config initialized successfully")
	// 设置默认值
	v.SetDefault("amount", "1")
	v.SetDefault("port", "8080")
	v.SetDefault("rate_limiter", "24")

	v.SetDefault("goerli.node_url", "https://goerli.infura.io/v3/YOUR_INFURA_PROJECT_ID")
	v.SetDefault("goerli.sender_address", "YOUR_GOERLI_SENDER_ADDRESS")

	v.SetDefault("sepolia.node_url", "https://sepolia.infura.io/v3/YOUR_INFURA_PROJECT_ID")
	v.SetDefault("sepolia.sender_address", "YOUR_SEPOLIA_SENDER_ADDRESS")
	return v, nil
}
