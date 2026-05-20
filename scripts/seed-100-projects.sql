-- Seed 100 famous open-source GitHub repos as standalone projects
-- Compatible with schema v031+
--
-- Usage:
--   docker compose exec -T postgres psql -U aspm -d aspm < scripts/seed-100-projects.sql
--
-- Idempotent: safe to re-run (uses ON CONFLICT DO NOTHING).

DO $$
DECLARE
    v_project_id UUID;
    v_now TIMESTAMPTZ := NOW();
    v_projects TEXT[][] := ARRAY[
        -- ── Frontend Frameworks & Libraries ──────────────────────────────
        ['facebook/react', 'React', 'A declarative, efficient, and flexible JavaScript library for building user interfaces'],
        ['vuejs/vue', 'Vue.js', 'Progressive JavaScript framework for building UI on the web'],
        ['angular/angular', 'Angular', 'One framework for mobile and desktop web applications'],
        ['sveltejs/svelte', 'Svelte', 'Cybernetically enhanced web apps — compiler-based frontend framework'],
        ['vercel/next.js', 'Next.js', 'The React framework for production with SSR and static generation'],
        ['gatsbyjs/gatsby', 'Gatsby', 'Fast React-based framework for building static websites and apps'],
        ['nuxt/nuxt', 'Nuxt.js', 'Intuitive Vue framework for building server-rendered applications'],
        ['twbs/bootstrap', 'Bootstrap', 'The most popular HTML, CSS, and JS framework for responsive sites'],
        ['tailwindlabs/tailwindcss', 'Tailwind CSS', 'Utility-first CSS framework for rapid UI development'],
        ['marmelab/react-admin', 'react-admin', 'Frontend framework for building admin applications with React'],

        -- ── JavaScript / Node.js Ecosystem ───────────────────────────────
        ['nodejs/node', 'Node.js', 'JavaScript runtime built on Chrome V8 engine'],
        ['expressjs/express', 'Express', 'Fast, unopinionated, minimalist web framework for Node.js'],
        ['nestjs/nest', 'NestJS', 'Progressive Node.js framework for building efficient server-side apps'],
        ['reduxjs/redux', 'Redux', 'Predictable state container for JavaScript applications'],
        ['remix-run/react-router', 'React Router', 'Declarative routing for React applications'],
        ['webpack/webpack', 'Webpack', 'Static module bundler for modern JavaScript applications'],
        ['vitejs/vite', 'Vite', 'Next-generation frontend tooling with instant hot module replacement'],
        ['prettier/prettier', 'Prettier', 'Opinionated code formatter supporting multiple languages'],
        ['eslint/eslint', 'ESLint', 'Find and fix problems in your JavaScript code'],
        ['microsoft/TypeScript', 'TypeScript', 'TypeScript is a superset of JavaScript that compiles to clean JavaScript'],

        -- ── Editors & IDEs ───────────────────────────────────────────────
        ['microsoft/vscode', 'VS Code', 'Visual Studio Code — code editor redefined and optimized for builds'],
        ['electron/electron', 'Electron', 'Build cross-platform desktop apps with JavaScript, HTML, and CSS'],
        ['atom/atom', 'Atom', 'The hackable text editor by GitHub'],

        -- ── Database & ORMs ──────────────────────────────────────────────
        ['prisma/prisma', 'Prisma', 'Next-generation Node.js and TypeScript ORM for PostgreSQL, MySQL, SQLite'],
        ['sequelize/sequelize', 'Sequelize', 'Promise-based Node.js ORM for Postgres, MySQL, MariaDB, SQLite, MSSQL'],
        ['typeorm/typeorm', 'TypeORM', 'ORM for TypeScript and JavaScript that supports active record pattern'],
        ['knex/knex', 'Knex.js', 'SQL query builder for PostgreSQL, MySQL, CockroachDB, MSSQL, SQLite3'],
        ['redis/redis', 'Redis', 'In-memory data structure store used as database, cache, and message broker'],
        ['mongodb/mongo', 'MongoDB', 'The most popular document database for modern applications'],
        ['neo4j/neo4j', 'Neo4j', 'The world leading graph database management system'],
        ['apache/cassandra', 'Cassandra', 'Highly scalable distributed NoSQL database management system'],
        ['cockroachdb/cockroach', 'CockroachDB', 'Cloud-native distributed SQL database for global applications'],
        ['timescale/timescaledb', 'TimescaleDB', 'Time-series database built on PostgreSQL for fast analytics'],

        -- ── Python Ecosystem ─────────────────────────────────────────────
        ['django/django', 'Django', 'The web framework for perfectionists with deadlines — batteries included'],
        ['pallets/flask', 'Flask', 'Lightweight WSGI web application framework for Python'],
        ['tiangolo/fastapi', 'FastAPI', 'Fast web framework for building APIs with Python 3.8+'],
        ['pandas-dev/pandas', 'pandas', 'Flexible and powerful data analysis / manipulation library for Python'],
        ['numpy/numpy', 'NumPy', 'Fundamental package for scientific computing with Python'],
        ['scikit-learn/scikit-learn', 'scikit-learn', 'Machine learning library for Python with simple and efficient tools'],
        ['tensorflow/tensorflow', 'TensorFlow', 'End-to-end open source platform for machine learning'],
        ['pytorch/pytorch', 'PyTorch', 'Tensors and dynamic neural networks in Python with strong GPU acceleration'],
        ['huggingface/transformers', 'Transformers', 'State-of-the-art Machine Learning for PyTorch, TensorFlow, and JAX'],
        ['apache/airflow', 'Apache Airflow', 'Platform to programmatically author, schedule and monitor workflows'],
        ['certbot/certbot', 'Certbot', 'Automatically enable HTTPS with Let Encrypt certificates on web servers'],

        -- ── Infrastructure & Cloud Native ────────────────────────────────
        ['kubernetes/kubernetes', 'Kubernetes', 'Production-Grade Container Scheduling and Management System'],
        ['docker/compose', 'Docker Compose', 'Define and run multi-container applications with Docker'],
        ['moby/moby', 'Moby (Docker Engine)', 'Open-source container engine for building and shipping apps'],
        ['containerd/containerd', 'containerd', 'Industry-standard container runtime with emphasis on simplicity'],
        ['prometheus/prometheus', 'Prometheus', 'Systems monitoring and alerting toolkit with time-series database'],
        ['grafana/grafana', 'Grafana', 'Observability and data visualization platform for metrics and logs'],
        ['elastic/elasticsearch', 'Elasticsearch', 'Distributed RESTful search engine built for the cloud'],
        ['nginx/nginx', 'Nginx', 'High-performance HTTP server, reverse proxy, and load balancer'],
        ['apache/kafka', 'Apache Kafka', 'Distributed event streaming platform for high-performance pipelines'],
        ['rabbitmq/rabbitmq-server', 'RabbitMQ', 'Open-source message broker implementing AMQP protocol'],
        ['etcd-io/etcd', 'etcd', 'Distributed reliable key-value store for critical distributed systems'],
        ['hashicorp/terraform', 'Terraform', 'Infrastructure as Code tool for building and versioning cloud resources'],
        ['hashicorp/vault', 'Vault', 'Tool for secrets management, encryption, and privileged access management'],
        ['hashicorp/consul', 'Consul', 'Service networking platform for service discovery and configuration'],
        ['ansible/ansible', 'Ansible', 'Radically simple IT automation platform for configuration management'],

        -- ── DevOps & CI/CD ────────────────────────────────────────────────
        ['jenkinsci/jenkins', 'Jenkins', 'Leading open-source automation server for building CI/CD pipelines'],
        ['gitlabhq/gitlabhq', 'GitLab', 'DevOps lifecycle tool with Git repository management and CI/CD'],
        ['gogs/gogs', 'Gogs', 'Painless self-hosted Git service written in Go'],
        ['go-gitea/gitea', 'Gitea', 'Lightweight self-hosted Git service powered by Go'],

        -- ── Identity & Security ──────────────────────────────────────────
        ['keycloak/keycloak', 'Keycloak', 'Open-source identity and access management with SSO capabilities'],
        ['OWASP/CheatSheetSeries', 'OWASP Cheat Sheet Series', 'Comprehensive collection of security cheat sheets for developers and defenders'],
        ['openssl/openssl', 'OpenSSL', 'TLS/SSL and crypto library — cryptographic toolkit for secure communications'],

        -- ── Programming Languages & Runtimes ────────────────────────────
        ['golang/go', 'Go', 'Statically typed, compiled programming language for building scalable systems'],
        ['rust-lang/rust', 'Rust', 'Safe, concurrent, practical language empowering everyone to build reliable software'],
        ['rails/rails', 'Ruby on Rails', 'Full-stack web framework optimized for programmer happiness'],
        ['laravel/laravel', 'Laravel', 'PHP framework for web artisans with expressive and elegant syntax'],
        ['spring-projects/spring-boot', 'Spring Boot', 'Framework for creating stand-alone production-grade Spring applications'],
        ['dotnet/aspnetcore', 'ASP.NET Core', 'Cross-platform framework for building modern web applications with .NET'],

        -- ── System Tools & Operating Systems ─────────────────────────────
        ['torvalds/linux', 'Linux Kernel', 'The Linux kernel — the core of the world operating system'],
        ['git/git', 'Git', 'Distributed version control system by Linus Torvalds'],
        ['curl/curl', 'curl', 'Command-line tool and library for transferring data with URL syntax'],
        ['libuv/libuv', 'libuv', 'Cross-platform asynchronous I/O library — the backbone of Node.js'],
        ['tmux/tmux', 'tmux', 'Terminal multiplexer — enables multiple terminal sessions in one window'],
        ['neovim/neovim', 'Neovim', 'Modern refactoring of Vim with better extensibility and usability'],

        -- ── Data Science & Big Data ──────────────────────────────────────
        ['apache/spark', 'Apache Spark', 'Unified engine for large-scale data analytics and machine learning'],
        ['apache/hadoop', 'Hadoop', 'Framework for distributed processing of large data sets across clusters'],
        ['dbt-labs/dbt-core', 'dbt', 'Data transformation tool for analytics engineering in the modern data stack'],
        ['scipy/scipy', 'SciPy', 'Fundamental algorithms for scientific computing in Python'],
        ['keras-team/keras', 'Keras', 'Deep learning API for humans, running on TensorFlow, JAX, and PyTorch'],

        -- ── Learning & Knowledge ─────────────────────────────────────────
        ['freeCodeCamp/freeCodeCamp', 'freeCodeCamp', 'Open-source codebase and curriculum for learning to code for free'],
        ['EbookFoundation/free-programming-books', 'Free Programming Books', 'Freely available programming books — one of the most popular repos on GitHub'],
        ['ossu/computer-science', 'OSSU Computer Science', 'Path to a free self-taught education in Computer Science'],
        ['public-apis/public-apis', 'Public APIs', 'Collective list of free APIs for use in software and web development'],
        ['sindresorhus/awesome', 'Awesome Lists', 'Curated list of awesome lists — a meta-list of resources for everything'],
        ['kamranahmedse/developer-roadmap', 'Developer Roadmap', 'Interactive roadmaps and guides to becoming a developer'],
        ['donnemartin/system-design-primer', 'System Design Primer', 'Learn how to design large-scale systems with real-world examples'],
        ['jlevy/the-art-of-command-line', 'Art of Command Line', 'Master the command line in one page — productivity tips and tricks'],
        ['iluwatar/java-design-patterns', 'Java Design Patterns', 'Collection of design patterns demonstrated in Java'],

        -- ── Authentication & Authorization ────────────────────────────────
        ['ory/hydra', 'Ory Hydra', 'OpenID Certified OAuth 2.0 and OpenID Connect provider for any web application'],
        ['dexidp/dex', 'Dex', 'OpenID Connect (OIDC) identity and OAuth 2.0 provider with multiple backends'],
        ['apereo/cas', 'CAS (Apereo)', 'Enterprise Single Sign-On platform for the web and beyond'],
        ['zitadel/zitadel', 'Zitadel', 'Identity infrastructure platform for secure and scalable authentication'],

        -- ── API & Communication ───────────────────────────────────────────
        ['grpc/grpc', 'gRPC', 'High-performance universal RPC framework by Google'],
        ['graphql/graphql-spec', 'GraphQL', 'Query language for APIs with a type system defined in terms of your data'],
        ['apache/thrift', 'Apache Thrift', 'Cross-language serialization and RPC framework for scalable services'],
        ['temporalio/temporal', 'Temporal', 'Workflow as Code platform for building reliable distributed applications']
    ];
    v_item TEXT[];
BEGIN

    -- Loop through each project in the array
    FOREACH v_item SLICE 1 IN ARRAY v_projects
    LOOP
        -- v_item[1] = "org/repo" (full path), v_item[2] = display name, v_item[3] = description
        -- Insert into projects table as standalone project (app_id IS NULL)
        INSERT INTO projects (name, description, app_id, repo_url, provider, default_branch, created_at, updated_at)
        VALUES (
            v_item[2],
            v_item[3],
            NULL,           -- standalone project (no app)
            'https://github.com/' || v_item[1],
            'github',
            'main',
            v_now,
            v_now
        )
        ON CONFLICT (name) WHERE app_id IS NULL DO NOTHING
        RETURNING id INTO v_project_id;

        IF v_project_id IS NOT NULL THEN
            RAISE NOTICE 'Created project: % (%)', v_item[2], v_item[1];
        END IF;
    END LOOP;

    RAISE NOTICE 'Done. Seeded % projects from famous GitHub repos.', array_length(v_projects, 1);

END $$;
