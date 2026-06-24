import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  docsSidebar: [
    {
      type: 'category',
      label: 'Getting Started',
      items: [
        'getting-started/installation',
        'getting-started/quickstart',
        'getting-started/key-custody',
      ],
    },
    {
      type: 'category',
      label: 'Core Concepts',
      items: [
        'core-concepts/governance-certificate',
        'core-concepts/emit-vs-verify',
        'core-concepts/signer-and-identity',
        'core-concepts/corpus-binding',
        'core-concepts/run-directory',
      ],
    },
    {
      type: 'doc',
      id: 'cli-reference',
      label: 'CLI Reference',
    },
    {
      type: 'category',
      label: 'Integration',
      items: [
        'integration/typescript-js',
        'integration/python',
        'integration/rust',
        'integration/custom-stages',
        'integration/business-docs',
      ],
    },
    {
      type: 'doc',
      id: 'corpus-binding-advanced',
      label: 'Corpus Binding (Advanced)',
    },
    {
      type: 'category',
      label: 'Architecture and Theory',
      items: [
        'architecture/emit-only-design',
        'architecture/certificate-json-shape',
        'architecture/determinism',
        'architecture/extraction-and-relicensing',
      ],
    },
    {
      type: 'category',
      label: 'Development',
      items: [
        'development/build-from-source',
        'development/testing',
        'development/self-governance',
        'development/contributing',
      ],
    },
    {
      type: 'category',
      label: 'Release and Distribution',
      items: [
        'release/overview',
        'release/npm-resolution',
        'release/pypi-wheels',
        'release/supply-chain-artifacts',
      ],
    },
  ],
};

export default sidebars;
