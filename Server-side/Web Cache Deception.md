# 網頁快取詐欺（Web Cache Deception）

By: 孫逸平

Ref: [https://portswigger.net/web-security/web-cache-deception](https://portswigger.net/web-security/web-cache-deception)

---

網頁快取詐欺漏洞允許攻擊者儲存敏感、動態資料在快取伺服器上，網頁快取漏洞的攻擊會讓受害者造訪惡意的連結（URL），使受害者模糊的請求敏感資料，快取伺服器會以為是靜態資料因此將其回覆（Response）儲存，最後攻擊者使用相同的連結（URL）請求，就能在未經驗證的情況下獲得敏感資料。

![alt](src/image.png)

圖片來源：[https://portswigger.net/web-security/web-cache-deception/images/wcd-image-1.png](https://portswigger.net/web-security/web-cache-deception/images/wcd-image-1.png)

> [!Note]
>
> Web cache poisoning 和 Web cache deception 的操作方式是不同：
>
> * Web cache poisoning 是操作快取金鑰（Cache key）注入惡意的內容並儲存在快取伺服器上，接著讓其他使用者存取。
> * Web cache deception 則是透過欺騙快取規則（Cache rules）儲存敏感資料，使攻擊者能夠存取。

## 網頁快取（Web Cache）

網頁快取（Web cache）是一個系統位於原始伺服器和使用者之間，當客戶端請求一個靜態資源時，會先被導向到快取伺服器。如果快取伺服器沒有備份的資源，則會導向到原始伺服器，而回應則會先儲存在快取再回傳給使用者。快取使用預先配置的規則去決定要儲存那些回應。

之後如果有使用者存取相同的資源，快取伺服器會直接回應之前儲存的資源給使用者。

![alt](src/image2.png)

圖片來源：[https://portswigger.net/web-security/images/caching.svg](https://portswigger.net/web-security/images/caching.svg)

快取成為常見且重要的途徑來傳送網頁內容，尤其使用將資料副本儲存在全世界分散的伺服器上的 Content Delivery Networks（CDNs）。CDNs 透過最小化傳輸距離，降低了伺服器傳送到使用者的時間。

### 快取金鑰（Cache Key）

當快取伺服器收到 HTTP 請求，會判斷要直接回傳資料或是需要導向請求到原始伺服器。快取會透過 HTTP 請求中的相關資料生成成「cache key」。例如：使用 URL 路徑、查詢參數等生成，也可以連同其他資料，包含表頭、資料類型等一起加入生成。

如果收到的請求 cache key 與先前的請求相同，則快取會認定為相同的資料並儲存一份副本。

### 快取規則（Cache Rules）

快取規則（Cache rules）能夠決定資料是否要儲存在快取伺服器上、要儲存多久。快取規則通常設定儲存不經常變動且重複使用在多個頁面的靜態資源。動態資料則因為較有可能包含敏感資料，所以不會儲存在，並確保使用者能夠直接存取到原始伺服器上的最新資料。

攻擊者利用快取規則進行網頁快取詐欺（Web cache deception），所以了解不同類型的規則相當重要。尤其根據一些在請求 URL 路徑中的字串，例如：

* 靜態資料副檔名規則：這個規則會判斷請求資源的檔案副檔名，包含 `.css`（樣式檔）、`.js`（JavaScipt 檔）等。
* 靜態資料夾規則：這個規則會判斷請求 URL 路徑是否開始於一些只會儲存靜態的資料夾名稱，包含：`/static`、`/assets` 等。
* 檔案名稱規則：這個規則會判斷檔案名稱是否符合一些網頁操作用的檔案，且很少變更，包含：`robots.txt`、`favicon.ico` 等。

快取也有可能設定一些自定義規則，例如：參考 URL 參數或動態進行分析等。

## 構成網頁快取詐欺

通常，攻擊者進行網頁快取詐欺需要以下步驟：

1. 辨別動態回應中包含敏感資料的目標端點。在 Burp 中查看回應，因為有些敏感資訊可能無法直接在頁面上看到。專注在支援 `GET`、`HEAD`、`OPTIONS` 方法的端點，因為改變伺服器狀態的請求通常不會被快取儲存。
2. 辨別快取伺服器和原始伺服器在解析 URL 路徑不一致的地方。他們在以下幾點有可能有差異：
   * 如何對應 URL 和資源
   * 如何處理特殊符號
   * 如何規範路徑
3. 透過不一致之處製作一個惡意的 URL，用以欺騙快取儲存動態回應。當受害者造訪這個 URL，回應資料會被儲存在快取。然後攻擊者可以使用 Burp 存取相同的 URL 以取得包含受害者資料的回應。應避免使用瀏覽器直接操作，因為有些應用程式會因為沒有會話（Session）重新導向使用者或使本地端的資料無線，這有可能會因此漏洞。

我們將探索構成網頁快取詐欺的不同方法。

### 破壞快取

在測試不一致之處以及進行網頁快取詐欺漏洞利用時，需確認每個請求的 cache key 不同，否則可能會影響快取的回應結果。

在這些 URL 當中，如果有 URL 路徑或任何被加入到 cache key 的查詢參數，可以在每次傳送請求時，將查詢字串加入路徑。Param Miner 插件可以自動化完成這些動作。要使用 Param Miner，可以先下載套件，接著在上方點擊 **Parmam miner > Settings**，然後點擊 **Add dynamic cachebuster**。現在 Burp 新增獨一無二的查詢字串到每個請求中，可以透過 **Logger** 分頁查看新增的查詢字串。

### 識別快取回應

在進行測試時，辨別快取的回應相當重要，你可以觀察回應封包的表頭以及回應封包的時間。

透過回應封包的表頭，有一些不同的跡象能夠判讀資料是否來自快取，例如：

* 可以透過 `X-Cache` 表頭提供是否來自快取的相關資訊，常見的值包含：
  * `X-Cache: hit`：回應是從快取提供的。
  * `X-Cache: miss`：快取不包含請求金鑰的回應，資料存取自原始伺服器。但通常回應都有被快取，透過再次發送請求觀察是否變成 `hit` 值來確定。
  * `X-Cache: dynamic`：原始伺服器生成的內容，通常表示快取伺服器上沒有適合的快取。
  * `X-Cache: refresh`：快取的資料已過期，需要重新存取或重新驗證。
* `Cache-Control` 表頭包含指出快取方向的資訊，例如 `public` 的 `max-age` 值大於 `0`。注意：這只代表資源能夠快取，不永遠表示來自快取，因為快取有時候可能覆蓋這個表頭。

如果你發現兩相同請求的回應時間有巨大差異，有可能表示較快的回應來自快取。

## 利用靜態檔副檔名快取規則

快取規則經常透過檔案副檔名（包含：`.css`、`.js` 等），判斷靜態資源，這也是 CDNs 中最常見的行為。

如果快取和原始伺服器解析 URL 的方式不一致，或使用分隔符號，攻擊者有機會能夠製作一個動態資源的請求並使用靜態資源的副檔名，讓原始伺服器不會理會，但快取會解析。

### 路徑解析不一致

URL 解析是一個把 URL 和伺服器上的資源聯結起來的過程，包含：檔案、腳本、執行指令等。他們有可能使用不同的框架或技術，導致解析方式不同，兩個常見的傳統 URL 轉換和 RESTful URL 轉換。

傳統 URL 轉換會將路徑轉換成系統上的檔案，這裡有一個典型的範例：`http://example.com/path/in/filesystem/resource.html`

* `http://example.com` 指向伺服器。
* `/path/in/fiflesystem` 描述伺服器檔案系統的資料夾路徑。
* `resource.html` 指定存取的檔案。

相較之下，REST-style 的 URL 不會直接對應實體的檔案結構，他們將檔案路徑抽象化為 API 的邏輯部分：`http://example.com/path/resource/param1/param2`

* `http://example.com` 指向伺服器。
* `/path/resource/` 是一個端點描述資源。
* `param1` 和 `param2` 是提供伺服器處理請求使用的路徑參數。

快取和原始伺服器將 URL 路徑對應資源的方式不同，可能造成網頁快取詐欺漏洞。考慮以下範例：`http://example.com/user/123/profile/wcd.css`

* 