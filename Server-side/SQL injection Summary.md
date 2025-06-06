# SQL Injection Summary

By: 孫逸平

Link: [https://portswigger.net/web-security/sql-injection](https://portswigger.net/web-security/sql-injection)

---

在本節中，我們將說明：

* 什麼是 SQL 注入攻擊（SQLi）。
* 如何發現和利用不同類型的 SQLi 漏洞。
* 如何防範 SQLi 攻擊。

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
> 
> 在 SQL 查詢語句中注入條件 `OR 1=1` 時請小心。即使在您注入的語境中看起來無害，應用程式通常會在多個不同的查詢語句中使用來自單一請求的資料。例如，如果您的條件到達 `UPDATE` 或 `DELETE` 語句，可能會導致意外的資料遺失。

* [**Lab: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data**](https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data)
  1. 點擊 Gift 選項，觀察網址後方為：`?category=Gifts`。
  2. 為了符合題意：「取得所有未發布的品項」，可以將網址 `category=Gifts%27%20OR%201=1%20--`，通常瀏覽器會自動做 URL 編碼，所以改成 `category=Gifts' OR 1=1 --` 也可以。
  3. 修改完並重新整理後，就過關了！

## 破壞應用程式邏輯

想像一個登入介面，使用者輸入使用者名稱（username）`wiener`，以及密碼（password）`bluecheese`，則 SQL 語句為：

```SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'```

如果 SQL 語句回傳使用者的詳細資訊，則登入成功。

攻擊者可透過 SQL 的註解語法 `--` 繞過密碼的確認。例如：在使用者名稱的欄位輸入 `administrator'--`，然後在密碼的欄位留白，使 SQL 語句變成：

```SELECT * FROM users WHERE username = 'administrator'--' AND password = ''```

就可以繞過密碼驗證，直接登入使用者名稱為 `administrator` 的帳號。

* [**Lab: SQL injection vulnerability allowing login bypass**](https://portswigger.net/web-security/sql-injection/lab-login-bypass)
  1. 點擊 `My account` 進入登入畫面。
  2. 在使用者名稱欄位輸入 `administrator'--` 並點擊登入。
  3. 發現頁面要求填寫密碼欄位。
  4. 在密碼欄位隨意輸入任何值。
  5. 點擊登入，就過關了！

## 抓取其他資料表的資料

`UNION` 指令可以用來組合 SQL 語句，攻擊者就能利用組合新的指令取得其他資料表的資訊。

舉例，當使用者輸入 `Gift` 後，SQL 語句會變成：

```SELECT name, description FROM products WHERE category = 'Gifts'```

攻擊者可以輸入：

```' UNION SELECT username, password FROM users--```

網站就會回傳所有使用者的帳號密碼。

了解更多：[SQL injection UNION attacks](https://portswigger.net/web-security/sql-injection/union-attacks)

## 盲目的 SQL 注入漏洞

許多的 SQL 注入實例都是盲目的漏洞，網站不會回傳 SQL 的查詢結果或其他錯誤訊息，但仍然可以取得未授權的資料，但涉及的技術複雜。

* 可以更改查詢語句的邏輯，讓查詢出現差異。可加入一些布林邏輯，或觸法錯誤，例如：除以 0。
* 可以透過時間延遲判斷條件是否被執行。

了解更多：[Blind SQL injection](https://portswigger.net/web-security/sql-injection/blind)

## 二階 SQL 注入

一階 SQL 注入是將攻擊者的 HTTP 請求內容合併到 SQL 語句中，以進行 SQL 注入。

二階 SQL 注入是攻擊者將 HTTP 請求的內容儲存進 SQL 資料庫中，在儲存資料時不會進行攻擊，之後再透過其他 HTTP 請求，取得資料庫的資料，因此二階 SQL 注入也被稱為儲存 SQL 注入。
