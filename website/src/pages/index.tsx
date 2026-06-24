import React from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';
import CodeBlock from '@theme/CodeBlock';

import styles from './index.module.css';

function HomepageHeader() {
  const {siteConfig} = useDocusaurusContext();
  return (
    <header className={clsx('hero hero--primary', styles.heroBanner)}>
      <div className="container">
        <Heading as="h1" className="hero__title">
          {siteConfig.title}
        </Heading>
        <p className="hero__subtitle">{siteConfig.tagline}</p>
        
        <div className={styles.installBox}>
          <CodeBlock language="bash">
            npm i -D tenant-emit
          </CodeBlock>
        </div>

        <div className={styles.buttons}>
          <Link
            className="button button--secondary button--lg"
            to="/docs/getting-started/quickstart">
            Quickstart Tutorial
          </Link>
          <Link
            className="button button--outline button--secondary button--lg"
            to="/docs/cli-reference">
            CLI Reference
          </Link>
        </div>
      </div>
    </header>
  );
}

function FeatureCards() {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          <div className="col col--4">
            <div className="text--center padding-horiz--md">
              <Heading as="h3">Emit-only by construction</Heading>
              <p>
                No verify verb, no verifier dependency. The verify/emit boundary is
                load-bearing, ensuring the emitter stays separate from the verifier.
              </p>
            </div>
          </div>
          <div className="col col--4">
            <div className="text--center padding-horiz--md">
              <Heading as="h3">Operator-key custody</Heading>
              <p>
                The Ed25519 signing key is an operator-supplied tenant secret held
                outside the repository and outside any agent's write scope.
              </p>
            </div>
          </div>
          <div className="col col--4">
            <div className="text--center padding-horiz--md">
              <Heading as="h3">Verifiable-but-unsealed</Heading>
              <p>
                Carries no platform countersign. A tenant-emitted certificate
                round-trips perfectly offline under <code>tenant-tail</code>.
              </p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

export default function Home(): JSX.Element {
  const {siteConfig} = useDocusaurusContext();
  return (
    <Layout
      title={siteConfig.title}
      description={siteConfig.tagline}>
      <HomepageHeader />
      <main>
        <FeatureCards />
      </main>
    </Layout>
  );
}
