# SQL 注入攻擊（SQL Injection）

By: 孫逸平

Link: [https://portswigger.net/web-security/sql-injection](https://portswigger.net/web-security/sql-injection)

---

在本節中，我們將說明：

* 什麼是 SQL 注入攻擊（SQLi）。
* 如何發現和利用不同類型的 SQLi 漏洞。
* 如何防範 SQLi 攻擊。

![alt](./src/image5.png)

## 什麼是 SQL injection (SQLi)？

SQL 注入攻擊（SQLi）是一種網路安全漏洞，允許攻擊者干擾應用程式對其資料庫執行的查詢。這可能讓攻擊者檢視通常無法取得的資料，包括屬於其他使用者的資料，或應用程式能夠存取的任何其他資料。在許多情況下，攻擊者可以修改或刪除這些資料，對應用程式的內容或行為造成持續性的變更。

在某些情況下，攻擊者可以將 SQL 注入攻擊升級，進而入侵底層伺服器或其他後端基礎設施。這也可能使他們能夠執行阻斷服務攻擊。

<iframe width="560" height="315" src="https://www.youtube.com/embed/wX6tszfgYp4?si=cMSa7Qsa_ah97BLg" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

## 成功的 SQL 注入攻擊會造成什麼影響？

成功的 SQL 注入攻擊可能導致未經授權存取敏感資料，例如：

* 密碼。
* 信用卡詳細資訊。
* 個人使用者資訊。

多年來，SQL 注入攻擊已被用於許多備受矚目的資料外洩事件。這些攻擊造成了聲譽損害和監管罰款。在某些情況下，攻擊者可以在組織的系統中獲得持續性的後門，導致長期入侵，而這種入侵可能在很長一段時間內都不會被發現。

## 如何檢測 SQL injection 漏洞？

您可以透過對應用程式中每個輸入點進行系統性測試來手動檢測 SQL 注入漏洞。要做到這一點，您通常需要提交：

* 單引號字元 `'` 並尋找錯誤或其他異常現象。
* 一些 SQL 特定語法，這些語法會評估為輸入點的基礎（原始）值，以及不同的值，並尋找應用程式回應中的系統性差異。
* 布林條件，例如 `OR 1=1` 和 `OR 1=2`，並尋找應用程式回應中的差異。
* 設計用於在 SQL 查詢中執行時觸發時間延遲的有效載荷，並尋找回應時間的差異。
* OAST 有效載荷，設計用於在 SQL 查詢中執行時觸發帶外網路互動，並監控任何產生的互動。

或者，您可以使用 Burp Scanner 快速且可靠地找到大部分的 SQL 注入漏洞。

## 查詢語句不同部分中的 SQL 注入

大多數 SQL 注入漏洞發生在 `SELECT` 查詢語句的 `WHERE` 子句中。大多數有經驗的測試人員都熟悉這種類型的 SQL 注入。

然而，SQL 注入漏洞可能出現在查詢語句的任何位置，以及不同類型的查詢語句中。SQL 注入出現的其他一些常見位置包括：

* 在 `UPDATE` 語句中，位於更新值或 `WHERE` 子句內。
* 在 `INSERT` 語句中，位於插入值內。
* 在 `SELECT` 語句中，位於資料表或欄位名稱內。
* 在 `SELECT` 語句中，位於 `ORDER BY` 子句內。

## SQL 注入範例

有許多 SQL 注入漏洞、攻擊和技術會在不同情況下發生。一些常見的 SQL 注入範例包括：

* 擷取隱藏資料，您可以修改 SQL 查詢語句以返回額外的結果。
* 破壞應用程式邏輯，您可以變更查詢語句來干擾應用程式的邏輯。
* UNION 攻擊，您可以從不同的資料庫資料表中擷取資料。
* 盲注 SQL 注入，您所控制的查詢語句結果不會在應用程式的回應中返回。

## 擷取隱藏資料

想像一個購物應用程式，它會在不同類別中顯示產品。當使用者點擊**禮品**類別時，他們的瀏覽器會請求以下 URL：
`https://insecure-website.com/products?category=Gifts`

這會導致應用程式執行 SQL 查詢語句，從資料庫中擷取相關產品的詳細資訊：
`SELECT * FROM products WHERE category = 'Gifts' AND released = 1`

這個 SQL 查詢語句要求資料庫返回：

* 所有詳細資訊（`*`）
* 從 `products` 資料表
* 其中 `category` 為 `Gifts`
* 且 `released` 為 `1`。

限制條件 `released = 1` 被用來隱藏尚未發布的產品。我們可以假設對於未發布的產品，`released = 0`。

該應用程式沒有實作任何針對 SQL 注入攻擊的防護措施。這意味著攻擊者可以構造以下攻擊，例如：
`https://insecure-website.com/products?category=Gifts'--`

這會產生以下 SQL 查詢語句：
`SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1`

重要的是，請注意 `--` 是 SQL 中的註解指示符。這意味著查詢語句的其餘部分會被解釋為註解，有效地將其移除。在這個範例中，這意味著查詢語句不再包含 `AND released = 1`。因此，所有產品都會被顯示，包括那些尚未發布的產品。

您可以使用類似的攻擊來使應用程式顯示任何類別中的所有產品，包括他們不知道的類別：
`https://insecure-website.com/products?category=Gifts'+OR+1=1--`

這會產生以下 SQL 查詢語句：
`SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1`

修改後的查詢語句會返回所有 `category` 為 `Gifts` 或 `1` 等於 `1` 的項目。由於 `1=1` 永遠為真，查詢語句會返回所有項目。

> [!warning]
> 在 SQL 查詢語句中注入條件 `OR 1=1` 時請小心。即使在您注入的語境中看起來無害，應用程式通常會在多個不同的查詢語句中使用來自單一請求的資料。例如，如果您的條件到達 `UPDATE` 或 `DELETE` 語句，可能會導致意外的資料遺失。

* [**Lab: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data**](https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data)
  1. 點擊 Gift 選項，觀察網址後方為：`?category=Gifts`。
  2. 為了符合題意：「取得所有未發布的品項」，可以將網址 `category=Gifts%27%20OR%201=1%20--`，通常瀏覽器會自動做 URL 編碼，所以改成 `category=Gifts' OR 1=1 --` 也可以。
  3. 修改完並重新整理後，就過關了！

## 破壞應用程式邏輯

想像一個允許使用者使用帳號和密碼登入的應用程式。如果使用者提交帳號 `wiener` 和密碼 `bluecheese`，應用程式會執行以下 SQL 查詢語句來檢查憑證：
`SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'`

如果查詢語句返回使用者的詳細資訊，則登入成功。否則，登入會被拒絕。

在這種情況下，攻擊者可以在不需要密碼的情況下以任何使用者身分登入。他們可以使用 SQL 註解序列 `--` 從查詢語句的 `WHERE` 子句中移除密碼檢查來達成這個目的。例如，提交帳號 `administrator'--` 和空白密碼會產生以下查詢語句：
`SELECT * FROM users WHERE username = 'administrator'--' AND password = ''`

這個查詢語句會返回 `username` 為 `administrator` 的使用者，並成功讓攻擊者以該使用者身分登入。

* [**Lab: SQL injection vulnerability allowing login bypass**](https://portswigger.net/web-security/sql-injection/lab-login-bypass)
  1. 點擊 `My account` 進入登入畫面。
  2. 在使用者名稱欄位輸入 `administrator'--` 並點擊登入。
  3. 發現頁面要求填寫密碼欄位。
  4. 在密碼欄位隨意輸入任何值。
  5. 點擊登入，就過關了！

## 從其他資料庫資料表擷取資料

在應用程式會回應 SQL 查詢語句結果的情況下，攻擊者可以利用 SQL 注入漏洞從資料庫中的其他資料表擷取資料。您可以使用 `UNION` 關鍵字執行額外的 `SELECT` 查詢語句，並將結果附加到原始查詢語句中。

例如，如果應用程式執行以下包含使用者輸入 `Gifts` 的查詢語句：
`SELECT name, description FROM products WHERE category = 'Gifts'`

攻擊者可以提交以下輸入：
`' UNION SELECT username, password FROM users--`

這會導致應用程式返回所有使用者名稱和密碼，以及產品的名稱和描述。

了解更多：[SQL injection UNION attacks](https://portswigger.net/web-security/sql-injection/union-attacks)

## 盲注 SQL 注入漏洞

許多 SQL 注入實例都是盲注漏洞。這意味著應用程式不會在其回應中返回 SQL 查詢語句的結果或任何資料庫錯誤的詳細資訊。盲注漏洞仍然可以被利用來存取未經授權的資料，但所涉及的技術通常更複雜且更難執行。

以下技術可以用來利用盲注 SQL 注入漏洞，具體取決於漏洞的性質和涉及的資料庫：

* 您可以改變查詢語句的邏輯，根據單一條件的真假來觸發應用程式回應中可檢測到的差異。這可能涉及在某些布林邏輯中注入新條件，或有條件地觸發錯誤，例如除零錯誤。
* 您可以有條件地在查詢語句處理中觸發時間延遲。這使您能夠根據應用程式回應所需的時間來推斷條件的真假。
* 您可以使用 OAST 技術觸發帶外網路互動。這種技術極其強大，在其他技術無效的情況下仍然有效。通常，您可以透過帶外通道直接滲透資料。例如，您可以將資料放入對您控制網域的 DNS 查詢中。

了解更多：[Blind SQL injection](https://portswigger.net/web-security/sql-injection/blind)

## 二階 SQL 注入

一階 SQL 注入發生在應用程式處理來自 HTTP 請求的使用者輸入，並以不安全的方式將輸入併入 SQL 查詢語句中。

二階 SQL 注入發生在應用程式從 HTTP 請求中取得使用者輸入並儲存以供日後使用時。這通常是透過將輸入放入資料庫來完成，但在儲存資料的時候並不會發生漏洞。稍後，當處理不同的 HTTP 請求時，應用程式會擷取儲存的資料，並以不安全的方式將其併入 SQL 查詢語句中。因此，二階 SQL 注入也稱為儲存型 SQL 注入。

![alt](./src/image6.png)

二階 SQL 注入通常發生在開發者了解 SQL 注入漏洞的情況下，因此會安全地處理輸入初次放入資料庫的過程。當資料稍後被處理時，由於之前已安全地放入資料庫，因此被認為是安全的。此時，資料會以不安全的方式處理，因為開發者錯誤地認為它是可信任的。

## 檢查資料庫

SQL 語言的一些核心功能在熱門資料庫平台上以相同方式實作，因此許多檢測和利用 SQL 注入漏洞的方法在不同類型的資料庫上運作方式相同。

然而，常見資料庫之間也存在許多差異。這意味著一些檢測和利用 SQL 注入的技術在不同平台上的運作方式會有所不同。例如：

* 字串串接的語法。
* 註解。
* 批次（或堆疊）查詢語句。
* 平台特定的 API。
* 錯誤訊息。

了解更多：[SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

在您識別出 SQL 注入漏洞後，取得資料庫相關資訊通常很有用。這些資訊可以幫助您利用該漏洞。

您可以查詢資料庫的版本詳細資訊。不同的方法適用於不同的資料庫類型。這意味著如果您發現某個特定方法有效，就可以推斷出資料庫類型。例如，在 Oracle 上您可以執行：
`SELECT * FROM v$version`

您也可以識別存在哪些資料庫資料表，以及它們包含的欄位。例如，在大多數資料庫上您可以執行以下查詢語句來列出資料表：
`SELECT * FROM information_schema.tables`

了解更多：[Examining the database in SQL injection attacks](https://portswigger.net/web-security/sql-injection/examining-the-database)

## 不同語境中的 SQL 注入

在先前的實驗中，您使用查詢字串來注入惡意的 SQL 有效載荷。然而，您可以使用任何可控制的輸入來執行 SQL 注入攻擊，只要該輸入被應用程式作為 SQL 查詢語句處理。例如，某些網站接受 JSON 或 XML 格式的輸入，並使用它來查詢資料庫。

這些不同的格式可能為您提供不同的方式來混淆攻擊，以繞過因 WAF 和其他防禦機制而被封鎖的攻擊。弱實作通常會在請求中尋找常見的 SQL 注入關鍵字，因此您可能能夠透過對禁用關鍵字中的字元進行編碼或跳脫來繞過這些過濾器。例如，以下基於 XML 的 SQL 注入使用 XML 跳脫序列來編碼 `SELECT` 中的 `S` 字元：

```xml
<stockCheck>
  <productId>123</productId>
  <storeId>999 &#x53;ELECT * FROM information_schema.tables</storeId>
</stockCheck>
```

這將在傳遞給 SQL 解釋器之前在伺服器端被解碼。

## 如何防範 SQL 注入

您可以透過使用參數化查詢語句而非在查詢語句中使用字串串接來防範大多數的 SQL 注入實例。這些參數化查詢語句也稱為「預備語句」。

以下程式碼容易受到 SQL 注入攻擊，因為使用者輸入直接串接到查詢語句中：

```sql
String query = "SELECT * FROM products WHERE category = '"+ input + "'";
Statement statement = connection.createStatement();
ResultSet resultSet = statement.executeQuery(query);
```

您可以重新編寫此程式碼，以防止使用者輸入干擾查詢語句結構：

```sql
PreparedStatement statement = connection.prepareStatement("SELECT * FROM products WHERE category = ?");
statement.setString(1, input);
ResultSet resultSet = statement.executeQuery();
```

您可以在不可信輸入作為查詢語句中的資料出現的任何情況下使用參數化查詢語句，包括 `WHERE` 子句以及 `INSERT` 或 `UPDATE` 語句中的值。它們無法用於處理查詢語句其他部分的不可信輸入，例如資料表或欄位名稱，或 `ORDER BY` 子句。將不可信資料放入查詢語句這些部分的應用程式功能需要採用不同的方法，例如：

* 將允許的輸入值列入白名單。
* 使用不同的邏輯來實現所需的行為。

要使參數化查詢語句有效防範 SQL 注入，查詢語句中使用的字串必須始終是硬編碼的常數。它絕不能包含來自任何來源的變數資料。不要試圖逐案判斷某項資料是否可信，並在被認為安全的情況下繼續在查詢語句中使用字串串接。很容易對資料的可能來源產生誤判，或者其他程式碼的變更可能會污染可信資料。

了解更多：[Find SQL injection vulnerabilities using Burp Suite's web vulnerability scanner](https://portswigger.net/burp/vulnerability-scanner)
