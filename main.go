package main

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"math/big"
	"os"

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

func main() {
	// 初始化日志记录器
	initLogger()
	defer logger.Sync()

	// 初始化配置管理器
	var err error
	cfg, err = initConfig()
	if err != nil {
		logger.Error("Failed to initialize config", zap.Error(err))
		os.Exit(1)
	}
	// 创建 Gin 引擎
	r := gin.Default()

	// 设置路由
	r.POST("/transfer", handleWithdraw)

	// 启动 HTTP 服务器
	err = r.Run(":8080")
	if err != nil {
		logger.Fatal("Failed to start server", zap.Error(err))
	}
}

// handleWithdraw 处理提款请求
func handleWithdraw(c *gin.Context) {
	var requestBody RequestBody
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

	c.JSON(http.StatusOK, ApiResponse{
		Success: true,
		Message: "Withdraw successful: " + signedTx.Hash().Hex(),
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
	v.SetDefault("goerli.node_url", "https://goerli.infura.io/v3/YOUR_INFURA_PROJECT_ID")
	v.SetDefault("amount", "1")
	v.SetDefault("goerli.sender_address", "YOUR_GOERLI_SENDER_ADDRESS")
	v.SetDefault("sepolia.node_url", "https://sepolia.infura.io/v3/YOUR_INFURA_PROJECT_ID")
	v.SetDefault("sepolia.sender_address", "YOUR_SEPOLIA_SENDER_ADDRESS")
	return v, nil
}
