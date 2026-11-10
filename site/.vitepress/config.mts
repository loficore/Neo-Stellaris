import { defineConfig } from 'vitepress'
import nav from './nav.json'

// The nav data source lives in `nav.json` so the Python fence
// (`scripts/test_docs_site.py`) can read the very same list the site renders:
// one source, two consumers.
const repo = 'https://github.com/loficore/Neo-Stellaris'

function topNav(sections: { text: string; items: { text: string; link: string }[] }[]) {
  return sections.map((section) => ({
    text: section.text,
    link: section.items[0].link
  }))
}

export default defineConfig({
  base: '/Neo-Stellaris/',
  cleanUrls: true,
  title: 'Neo-Stellaris',
  description: 'Runtime JavaScript mods for Stellaris — SDK, examples and known limits.',
  lang: 'en-US',
  lastUpdated: false,
  ignoreDeadLinks: false,
  themeConfig: {
    socialLinks: [{ icon: 'github', link: repo }],
    search: { provider: 'local' }
  },
  locales: {
    root: {
      label: 'English',
      lang: 'en-US',
      themeConfig: {
        nav: [...topNav(nav.en), { text: 'GitHub', link: repo }],
        sidebar: nav.en
      }
    },
    zh: {
      label: '中文',
      lang: 'zh-CN',
      link: '/zh/',
      themeConfig: {
        nav: [...topNav(nav.zh), { text: 'GitHub', link: repo }],
        sidebar: nav.zh
      }
    }
  }
})
