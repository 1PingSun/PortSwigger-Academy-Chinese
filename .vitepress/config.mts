import { defineConfig } from 'vitepress'

// https://vitepress.dev/reference/site-config
export default defineConfig({
  base: "/",
  title: "PortSwigger Academy 翻譯",
  description: "嘗試翻譯 PortSwigger Academy 上的文章中...",
  themeConfig: {
    // https://vitepress.dev/reference/default-theme-config
    nav: [
      { text: 'Home', link: '/' }
    ],

    sidebar: [
      {
        text: 'Server-side topics',
        items: [
          { text: '任意檔案上傳漏洞（File Upload Vulnerabilities）', link: '/Server-side/File Upload Vulnerabilities' },
          { text: '網頁快取詐欺（Web Cache Deception）', link: '/Server-side/Web Cache Deception' },
          { text: '路徑遍歷（Path traversal）', link: '/Server-side/Path Traversal' },
          { text: '指令注入（OS command injection）', link: '/Server-side/OS Command Injection' }
        ]
      }
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/1PingSun/PortSwigger-Academy-Chinese' }
    ]
  }
})
