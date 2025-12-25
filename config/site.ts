export type SiteConfig = typeof siteConfig;

export const siteConfig = {
  name: "MiniSecureDrop",
  description: "端到端加密文件共享（AES-GCM 256 + PBKDF2 120k）",
  navItems: [
    { label: "Home", href: "/" },
  ],
  navMenuItems: [],
  links: {
    github: "https://github.com/heroui-inc/heroui",
    twitter: "https://twitter.com/hero_ui",
    docs: "https://heroui.com",
    discord: "https://discord.gg/9b6yyZKmH4",
    sponsor: "https://patreon.com/jrgarciadev",
  },
};
