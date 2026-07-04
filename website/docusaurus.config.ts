import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

// If a custom domain is later attached, change baseUrl to '/' and add a
// static/CNAME file containing the domain.
const config: Config = {
  title: 'tenant-emit',
  tagline: 'Emit signed governance certificates from a finished run, with no trust required to verify them.',
  favicon: 'img/favicon.ico',

  url: 'https://stagecraft-ing.github.io',
  baseUrl: '/tenant-emit/',
  organizationName: 'stagecraft-ing',
  projectName: 'tenant-emit',

  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',

  markdown: {
    mermaid: true,
  },

  themes: ['@docusaurus/theme-mermaid'],

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          routeBasePath: '/docs',
          editUrl:
            'https://github.com/stagecraft-ing/tenant-emit/tree/main/website/',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    navbar: {
      title: 'tenant-emit',
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'docsSidebar',
          position: 'left',
          label: 'Docs',
        },
        {
          href: 'https://github.com/stagecraft-ing/tenant-emit',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Documentation',
          items: [
            {
              label: 'Getting Started',
              to: '/docs/getting-started/installation',
            },
            {
              label: 'CLI Reference',
              to: '/docs/cli-reference',
            },
          ],
        },
        {
          title: 'Related Tools',
          items: [
            {
              label: 'tenant-tail (verifier)',
              href: 'https://github.com/stagecraft-ing/tenant-tail',
            },
            {
              label: 'spec-spine (corpus compiler)',
              href: 'https://github.com/stagecraft-ing/spec-spine',
            },
          ],
        },
        {
          title: 'More',
          items: [
            {
              label: 'GitHub',
              href: 'https://github.com/stagecraft-ing/tenant-emit',
            },
          ],
        },
      ],
      copyright: `Copyright ${new Date().getFullYear()} Bartek Kus. Apache-2.0.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['bash', 'json', 'toml', 'rust'],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
