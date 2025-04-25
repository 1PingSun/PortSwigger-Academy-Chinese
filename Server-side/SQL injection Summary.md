# SQL Injection Summary

By: 孫逸平

Link: [https://portswigger.net/web-security/sql-injection](https://portswigger.net/web-security/sql-injection)

---

## 什麼是 SQL injection (SQLi)？

攻擊者可以透過 SQL injection 在資料庫中，取得、修改、刪除一些不被允許存取的資料，例如：其他用戶的資料。

## SQL injection 會造成什麼影響？

SQL injection 可以讓攻擊者取得不被允許取得的資訊，包含：密碼、信用卡資料、個人資料等。

許多資料洩漏事件都是透過 SQL injection 攻擊的，這些都造成了聲譽的受損或罰款。攻擊者也可能進入系統長期入侵。

## 如何檢測 SQL injection 漏洞？

可以透過以下方式手動檢測：

* 輸入單引號 `'` 並觀察是否有錯誤訊息或異常
* 輸入布林條件，例如：`OR 1=1` 和 `OR 1=2`，並查看回應中的差異。
* 檢查回應時間差異

## SQL 的各種子句

大多數的漏洞都發生在 `WHERE` 語法子句中，但 SQL injection 漏洞可能出現在任何指令，包含：

* 在 `UPDATE` 語句中，有欲更新的值或 `WHERE` 子句指定的位置。
* 在 `INSERT` 語句中，有欲插入的值。
* 在 `SELECT` 語句中，有資料表的名稱或列名。
* 在 `SELECT` 語句中，有 `ORDER BY` 子句。

## SQL injection 的範例

* 透過修改 SQL 語法，查詢資料庫中隱藏的數據，並回傳查詢後的值。
* 更改內容，以干擾其邏輯。
* UNION 攻擊，獲得其他資料表的數據。
* Blind SQL injection：控制查詢結果，但不會回傳數據。

## 取得隱藏的資料

假設一個購物網站，使用者點擊了 `Gift` 品項，網址就會變成：

```https://insecure-website.com/products?category=Gifts```

此時的 SQL 語句為：

```SELECT * FROM products WHERE category = 'Gifts' AND released = 1```

其中的 `AND released = 1` 假設用意為只回傳上架的商品，避免隱藏的商品被回傳，並假設隱藏的商品的 `released` 值為 `0`。

可以將網址改成：

```https://insecure-website.com/products?category=Gifts' --```

當中的 `--` 為 SQL 中的註解，可忽略之後的內容，

因此後方的 `AND released = 1` 條件就會被忽略

也可以將網址改成：

```https://insecure-website.com/products?category=Gifts'+OR+1=1--```

此時的 SQL 語句就變成：

```SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1```

因為 `1=1` 一直都會是真（true），所以會回傳整個資料表的值。

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
