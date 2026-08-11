# Rat Detector Core

Rat Detector Core 是可解釋、離線優先的 BSC／EVM 可疑發幣分析工具。它把已蒐集的觀察資料轉換成可重現的風險訊號、保守的控制關係判定、bytecode 指紋與證據重播結果。

本倉庫刻意不包含錢包、私鑰、簽名、下單、買賣、狙擊、交易送出、RPC、通知機器人或線上服務控制程式；它是公開分析核心，不是交易系統。

## 核心原則

- 必要資料不完整時維持 `unknown`，不會被當成低風險。
- CEX、跨鏈橋與 relay 的轉帳本身不能證明共同控制。
- 只有直接且可驗證的原始來源證據能標記為 `proven`。
- 同一 delivery 的不良判定不會被較晚到達的 unknown 結果覆蓋。
- 所有結果都有機器可讀的訊號與文字解釋。
- 分析核心不執行網路請求，也不寫入磁碟。

## 快速開始

需要 Python 3.11 以上版本；執行期沒有第三方套件依賴。

```powershell
python -m venv .venv
python -m pip install --no-build-isolation -e .
rat-detector analyze examples/suspicious_launch.json
python -m unittest discover -s tests -v
```

更多內容請參考英文 [README](README.md)、[架構說明](docs/architecture.md)、[輸入格式](docs/input-schema.md) 與 [安全政策](SECURITY.md)。

## 公開範圍

包含驗證模型、離線風險分析、資金來源判定、bytecode 指紋、證據重播、合成範例與回歸測試。

不包含任何私密憑證、生產資料、營運地址、交易建構／簽名／送出、買賣路由、即時 RPC、服務控制或部署腳本。

## 授權

本專案採用 [Apache License 2.0](LICENSE)。
