# SQL injection Summary

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
  1. 點擊 Gift 選項，觀察網址後方為：`?category=Gifts`
  2. 為了符合題意：「取得所有未發布的品項」，可以將網址 `category=Gifts%27%20OR%201=1%20--`，通常瀏覽器會自動做 URL 編碼，所以改成 `category=Gifts' OR 1=1 --` 也可以。
  3. 修改完並重新整理後，就過關了！

  
  


