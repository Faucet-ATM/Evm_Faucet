# 以太坊水龙头

这是一个使用 Go 语言和 Gin 框架编写的简单以太坊水龙头。

## 使用方法

1. 将仓库克隆到本地：
   ```bash
   git clone https://github.com/Autumn-qy/Evm_Faucet.git
   ```
2. 进入项目目录：
    ```bash
   cd Evm_Faucet
    ```

3. 安装依赖项：
    ```bash
   go mod tidy
    ```

4. 在项目根目录创建一个 `configs` 目录，并添加一个 `config.yaml` 文件。示例内容：
    ```yaml
   amount: 1
   goerli:
      node_url: "https://goerli.infura.io/v3/YOUR_INFURA_PROJECT_ID"
      sender_address: "YOUR_GOERLI_SENDER_ADDRESS"
      private_key: "YOUR_GOERLI_PRIVATE_KEY"
   sepolia:
      node_url: "https://sepolia.infura.io/v3/YOUR_INFURA_PROJECT_ID"
      sender_address: "YOUR_SEPOLIA_SENDER_ADDRESS"
      private_key: "YOUR_SEPOLIA_PRIVATE_KEY"
   ```
5. 运行应用程序：
    ```bash
    go run main.go
    ```

# API 文档

## 水龙头接口

- URL： `/transfer`
- 方法： `POST`
- 请求体:
    ```json
   {
  "network": "goerli",
  "address": "0xRecipientAddress"
  }
   ```
    - `network`：要用于交易的以太坊网络（`goerli` 或 `sepolia`）。
    - `address`：接收方以太坊钱包地址。
- 响应：
   ```json
  {
  "success": true,
  "message": "0x交易哈希"
  }
   ```
    - `success`：领水是否成功。
    - `message`：领水状态以及交易哈希（如果成功）的消息。
