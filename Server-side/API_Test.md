# API 測試（API Test）

By: 1PingSun

Ref: [https://portswigger.net/web-security/api-testing](https://portswigger.net/web-security/api-testing)

---

API（應用程式介面）讓軟體系統和應用程式能夠進行通訊和資料共享。API 測試很重要，因為 API 中的漏洞可能會危及網站機密性、完整性和可用性等核心要素。

所有動態網站都由 API 組成，因此像 SQL 注入等經典的網路漏洞可以歸類為 API 測試。在本主題中，我們將教您如何測試那些並非完全由網站前端使用的 API，重點著重於 RESTful 和 JSON API。我們也會教您如何測試可能影響內部 API 的伺服器端參數污染漏洞。

為了說明 API 測試與一般網路測試之間的重疊性，我們建立了現有主題與 [OWASP API Security Top 10 2023](https://portswigger.net/web-security/api-testing/top-10-api-vulnerabilities)。

![alt text](src/image7.png)

::: info 相關頁面
若要了解更多 GraphQL API 相關內容，請參閱我們的 [GraphQL API 漏洞](https://portswigger.net/web-security/graphql)學院主題。
:::

## API 偵察

要開始進行 API 測試，您首先需要盡可能找出關於 API 的資訊，以發現其攻擊面。

首先，您應該識別 API 端點。這些是 API 接收關於其伺服器上特定資源請求的位置。例如，考慮以下 `GET` 請求：

```raw
GET /api/books HTTP/1.1
Host: example.com
```

此請求的 API 端點是 `/api/books`。這會與 API 互動以從圖書館檢索書籍清單。另一個 API 端點可能是，例如 `/api/books/mystery`，這會檢索推理小說清單。

一旦您識別了端點，就需要確定如何與它們互動。這讓您能夠建構有效的 HTTP 請求來測試 API。例如，您應該找出以下資訊：

* API 處理的輸入資料，包括必要和可選的參數。
* API 接受的請求類型，包括支援的 HTTP 方法和媒體格式。
* 速率限制和身份驗證機制。

## API 文件

API 通常都有文件記錄，以便開發人員了解如何使用和整合它們。

文件可以是人類可讀和機器可讀的形式。人類可讀的文件是為開發人員設計的，幫助他們了解如何使用 API。它可能包含詳細的說明、範例和使用情境。機器可讀的文件是為軟體處理而設計的，用於自動化 API 整合和驗證等任務。它以 JSON 或 XML 等結構化格式編寫。

API 文件通常是公開可用的，特別是如果 API 是供外部開發人員使用的。如果是這種情況，請務必從查看文件開始您的偵察工作。

### 發現 API 文件

即使 API 文件並非公開可用，您仍然可能透過瀏覽使用該 API 的應用程式來存取它。

為此，您可以使用 Burp Scanner 來爬取 API。您也可以使用 Burp 的瀏覽器手動瀏覽應用程式。尋找可能參考 API 文件的端點，例如：

* `/api`
* `/swagger/index.html`
* `/openapi.json`

如果您識別出資源的端點，請務必調查基本路徑。例如，如果您識別出資源端點 `/api/swagger/v1/users/123`，那麼您應該調查以下路徑：

* `/api/swagger/v1`
* `/api/swagger`
* `/api`

您也可以使用 Intruder 透過常見路徑清單來尋找文件。

::: tip **Lab: [Exploiting an API endpoint using documentation](https://portswigger.net/web-security/api-testing/lab-exploiting-api-endpoint-using-documentation)**
1. 嘗試找到 API 文件的路徑： `/api`
2. 點擊 DELETE 使用者的 API，輸入 `carlos` 後刪除使用者通過此關。
:::

### 使用機器可讀文件

您可以使用各種自動化工具來分析您找到的任何機器可讀 API 文件。

您可以使用 Burp Scanner 來爬取和稽核 OpenAPI 文件，或任何其他 JSON 或 YAML 格式的文件。您也可以使用 [OpenAPI Parser](https://portswigger.net/bappstore/6bf7574b632847faaaa4eb5e42f1757c) BApp 來解析 OpenAPI 文件。

您還可能能夠使用專門的工具來測試已記錄的端點，例如 [Postman](https://www.postman.com/) 或 [SoapUI](https://www.soapui.org/)。

## 識別 API 端點

您也可以透過瀏覽使用該 API 的應用程式來收集大量資訊。即使您能夠存取 API 文件，這樣做通常也是值得的，因為有時文件可能不準確或過時。

您可以使用 Burp Scanner 來爬取應用程式，然後使用 Burp 的瀏覽器手動調查有趣的攻擊面。

在瀏覽應用程式時，請留意 URL 結構中暗示 API 端點的模式，例如 `/api/`。同時也要注意 JavaScript 檔案。這些檔案可能包含您尚未透過網路瀏覽器直接觸發的 API 端點參考。Burp Scanner 在爬取過程中會自動提取一些端點，但如果需要更徹底的提取，請使用 JS Link Finder BApp。您也可以在 Burp 中手動檢查 JavaScript 檔案。

### 與 API 端點互動

一旦您識別了 API 端點，就使用 Burp Repeater 和 Burp Intruder 與它們互動。這讓您能夠觀察 API 的行為並發現額外的攻擊面。例如，您可以調查 API 如何回應 HTTP 方法和媒體類型的變更。

當您與 API 端點互動時，請仔細檢查錯誤訊息和其他回應。有時這些會包含您可以用來建構有效 HTTP 請求的資訊。

#### 識別支援的 HTTP 方法

HTTP 方法指定要對資源執行的動作。例如：

* `GET` - 從資源檢索資料。
* `PATCH` - 對資源套用部分變更。
* `OPTIONS` - 檢索可在資源上使用的請求方法類型資訊。

一個 API 端點可能支援不同的 HTTP 方法。因此，在調查 API 端點時測試所有潛在的方法是很重要的。這可能讓您識別額外的端點功能，開啟更多攻擊面。

例如，端點 `/api/tasks` 可能支援以下方法：

* `GET /api/tasks` - 檢索任務清單。
* `POST /api/tasks` - 建立新任務。
* `DELETE /api/tasks/1` - 刪除任務。

您可以使用 Burp Intruder 中內建的 **HTTP verbs** 清單來自動循環測試各種方法。

::: info NOTE
在測試不同 HTTP 方法時，請以低優先級物件為目標。這有助於確保您避免意外後果，例如變更關鍵項目或建立過多記錄。
:::

#### 識別支援的內容類型

API 端點通常期望資料採用特定格式。因此，它們可能會根據請求中提供的資料內容類型而有不同的行為。變更內容類型可能讓您：

* 觸發錯誤以揭露有用資訊。
* 繞過有缺陷的防禦機制。
* 利用處理邏輯的差異。例如，API 在處理 JSON 資料時可能是安全的，但在處理 XML 時可能容易受到注入攻擊。

要變更內容類型，請修改 `Content-Type` 標頭，然後相應地重新格式化請求主體。您可以使用 [Content type converter](https://portswigger.net/bappstore/db57ecbe2cb7446292a94aa6181c9278) BApp 來自動轉換請求中提交的資料在 XML 和 JSON 之間的格式。

::: tip **Lab: [Finding and exploiting an unused API endpoint](https://portswigger.net/web-security/api-testing/lab-exploiting-unused-api-endpoint)**
:::

#### 使用 Intruder 尋找隱藏端點

一旦您識別出一些初始的 API 端點，就可以使用 Intruder 來發現隱藏的端點。例如，考慮一個情境，您已經識別出以下用於更新使用者資訊的 API 端點：

`PUT /api/user/update`

要識別隱藏端點，您可以使用 Burp Intruder 來尋找具有相同結構的其他資源。例如，您可以在路徑的 `/update` 位置添加負載，使用其他常見功能的清單，如 `delete` 和 `add`。

在尋找隱藏端點時，請使用基於常見 API 命名慣例和行業術語的詞彙表。同時確保根據您的初始偵察，也包含與應用程式相關的術語。

