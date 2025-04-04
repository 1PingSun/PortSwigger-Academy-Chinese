# 路徑遍歷（Path traversal）

By: 孫逸平

Ref: [https://portswigger.net/web-security/file-path-traversal](https://portswigger.net/web-security/file-path-traversal)

---

在這個章節中，將說明以下內容：

* 什麼是路徑遍歷
* 如何進行路徑遍歷攻擊並繞過常見的阻擋
* 如何防範路徑遍歷漏洞

![](src/image3.png)

## 什麼是路徑遍歷

路徑遍歷 Path traversal 也被稱為 directory traversal，這個漏洞允許攻擊讀取執行中應用的伺服器上的任意檔案。這可能包含：

* 應用的程式與資料
* 後端系統的憑證
* 敏感的作業系統檔案

在某些情況，攻擊者能夠修改伺服器上的任意檔案，進而修改應用的資料或行為，最後完全控制伺服器。

<iframe width="560" height="315" src="https://www.youtube.com/embed/NQwUDLMOrHo?si=p4UnKX7sEKNKIPWB" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

