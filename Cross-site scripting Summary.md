# Cross-site scripting Summary

By: 孫逸平

Link: [https://portswigger.net/web-security/cross-site-scripting](https://portswigger.net/web-security/cross-site-scripting)

---

## 什麼是 cross-site scripting (XSS)？

跨網站腳本攻擊（XSS）是一種網路完全漏洞，此漏洞使攻擊者可取得其他使用之任何資料，若受害的使用者擁有特殊權限，攻擊者將可取得所有資料或進行任意操作。

## XSS 如何運作的？

XSS 是透過對脆弱的網站進行操作，使其他使用者收到惡意的 Javascrit 指令。

## 驗證 XSS

為了測試是否存在 XSS 漏洞，可以執行一些無害的 Javascript 指令，而 `alert()` 函式是最常見的方式，因為它簡短且無害，並且成功執行時很難錯過彈跳的視窗。

但 Chrome 瀏覽器在版本 92 開始（2021 年 7 月 20 日），建議改用 `print()` 函式。

