import { defineConfig } from 'vitepress'

// https://vitepress.dev/reference/site-config
export default defineConfig({
  base: "/",
  title: "PortSwigger Academy 翻譯",
  description: "嘗試翻譯 PortSwigger Academy 上的文章中...",
  themeConfig: {
    // https://vitepress.dev/reference/default-theme-config
    outline: {
      level: [2, 7],
    },

    nav: [
      { text: 'Home', link: '/' }
    ],

    sidebar: [
      {
        text: 'Server-side topics',
        items: [
          { text: 'SQL 注入攻擊（SQL Injection）', link: '/Server-side/SQL_Injection' },
          { text: '身分驗證漏洞（Authentication Vulnerabilities）', link: '/Server-side/Authentication_Vulnerabilities' },
          { text: '路徑遍歷（Path Traversal）', link: '/Server-side/Path_Traversal' },
          { text: '指令注入（OS command injection）', link: '/Server-side/OS_Command_Injection' },
          { text: '任意檔案上傳漏洞（File Upload Vulnerabilities）', link: '/Server-side/File_Upload_Vulnerabilities' },
          { text: '伺服器端請求偽造（SSRF）', link: '/Server-side/Server-Side_Request_Forgery' },
          { text: 'XXE（XXE Injection）', link: '/Server-side/XXE_Injection' },
          { text: 'API 測試（API Test）', link: '/Server-side/API_Test' },
          { text: '網頁快取詐欺（Web Cache Deception）', link: '/Server-side/Web_Cache_Deception' }
        ]
      },
      {
        text: 'Advanced topics',
        items: [
          { text: 'HTTP 請求走私（HTTP Request Smuggling）', link: '/Advanced/HTTP_Request_Smuggling' },
        ]
      },
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/1PingSun/PortSwigger-Academy-Chinese' }
    ]
  }
})
