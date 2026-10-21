/**
 * DependencyScanner - Detects malicious or vulnerable dependencies
 * Identifies known malicious packages, typosquatting, and suspicious install patterns
 */
export class DependencyScanner {
  constructor() {
    // Known malicious npm packages (this is an example, should connect to threat intelligence source)
    this.knownMaliciousPackages = [
      // Actual malicious packages
      'event-stream',           // Famous bitcoin stealing incident
      'flatmap-stream',         // Malicious dependency of event-stream
      'ua-parser-js',           // Compromised version
      'coa',                    // Compromised version
      'rc',                     // Compromised version
      'colors',                 // Sabotaged by author
      'faker',                  // Sabotaged by author
      'node-ipc',               // Protestware
      'peacenotwar',            // Protestware dependency
      // Common malicious package name patterns
      'cross-env-',             // Typosquat of cross-env
      'crossenv',               // Typosquat of cross-env
      'lodash-',                // Typosquat attempts
      'babelcli',               // Typosquat of babel-cli
      'mongose',                // Typosquat of mongoose
    ];

    // Typosquatting detection patterns
    this.typosquatPatterns = [
      // Common typos of popular packages
      {
        legitimate: 'lodash',
        typos: ['lodash-', 'lodas', 'lodahs', 'lodesh', 'lod-ash', 'loadash'],
        risk: 'critical'
      },
      {
        legitimate: 'express',
        typos: ['expres', 'expresss', 'expess', 'exprss', 'xpress'],
        risk: 'critical'
      },
      {
        legitimate: 'mongoose',
        typos: ['mongose', 'mongoos', 'mongooose', 'mongoosee'],
        risk: 'critical'
      },
      {
        legitimate: 'react',
        typos: ['reac', 'reactt', 'raect', 'reakt'],
        risk: 'critical'
      },
      {
        legitimate: 'webpack',
        typos: ['webpck', 'webpackk', 'wepback', 'wepack'],
        risk: 'critical'
      },
      {
        legitimate: 'axios',
        typos: ['axois', 'axioss', 'axxios', 'axos'],
        risk: 'critical'
      },
      {
        legitimate: 'babel-cli',
        typos: ['babelcli', 'babel_cli', 'babeli-cli'],
        risk: 'critical'
      },
      {
        legitimate: 'cross-env',
        typos: ['crossenv', 'cross-env-', 'cros-env', 'crosss-env'],
        risk: 'critical'
      },
      {
        legitimate: 'typescript',
        typos: ['typscript', 'tyescript', 'typesript', 'typescrip'],
        risk: 'critical'
      },
      {
        legitimate: 'eslint',
        typos: ['eslit', 'eslnt', 'eslintt', 'elint'],
        risk: 'critical'
      }
    ];

    // Suspicious installation patterns
    this.suspiciousInstallPatterns = [
      {
        pattern: /npm\s+install\s+[^-\s]{0,300}@\d+\.\d+\.\d+-[a-z]+/gi,
        risk: 'medium',
        title: 'Installing prerelease version',
        description: 'Installing alpha/beta/rc version, may be unstable or contain malicious code'
      },
      {
        pattern: /npm\s+install\s+https?:\/\//gi,
        risk: 'high',
        title: 'Installing package from URL',
        description: 'Installing npm package directly from URL, cannot verify integrity'
      },
      {
        pattern: /npm\s+install\s+git\+/gi,
        risk: 'medium',
        title: 'Installing package from Git',
        description: 'Installing from Git repository, may point to malicious branch'
      },
      {
        pattern: /npm\s+install\s+--ignore-scripts/gi,
        risk: 'low',
        title: 'Ignoring install scripts',
        description: 'While this is a security measure, it may also hide other issues'
      },
      {
        pattern: /npm\s+install\s+--force/gi,
        risk: 'medium',
        title: 'Force install',
        description: 'Force install may override security warnings'
      },
      {
        pattern: /npm\s+set\s+registry/gi,
        risk: 'high',
        title: 'Modifying npm registry',
        description: 'Changing npm registry may redirect to malicious mirror'
      }
    ];

    // pip malicious packages
    this.maliciousPipPackages = [
      'colourama',              // Typosquat of colorama
      'python-sqlite',          // Typosquat of sqlite3
      'python-mysql',           // Typosquat
      'reqeusts',               // Typosquat of requests
      'djanga',                 // Typosquat of django
      'beautifulsoup',          // Old/wrong name
    ];

    // pip suspicious installation
    this.suspiciousPipPatterns = [
      {
        pattern: /pip\s+install\s+--trusted-host/gi,
        risk: 'high',
        title: 'pip trusting insecure host',
        description: 'Trusting unverified pip host'
      },
      {
        pattern: /pip\s+install\s+--index-url\s+http:/gi,
        risk: 'critical',
        title: 'pip using HTTP index',
        description: 'Using insecure HTTP connection for package installation'
      },
      {
        pattern: /pip\s+install\s+git\+/gi,
        risk: 'medium',
        title: 'pip installing from Git',
        description: 'Installing Python package from Git'
      }
    ];

    // Package manager command detection
    this.packageManagerPatterns = [
      {
        pattern: /npm\s+i(?:nstall)?\s+([^\s&|;]{1,300})/gi,
        type: 'npm'
      },
      {
        pattern: /yarn\s+add\s+([^\s&|;]{1,300})/gi,
        type: 'yarn'
      },
      {
        pattern: /pnpm\s+(?:add|install)\s+([^\s&|;]{1,300})/gi,
        type: 'pnpm'
      },
      {
        pattern: /pip\s+install\s+([^\s&|;]{1,300})/gi,
        type: 'pip'
      },
      {
        pattern: /gem\s+install\s+([^\s&|;]{1,300})/gi,
        type: 'gem'
      },
      {
        pattern: /cargo\s+install\s+([^\s&|;]{1,300})/gi,
        type: 'cargo'
      },
      {
        pattern: /go\s+get\s+([^\s&|;]{1,300})/gi,
        type: 'go'
      },
      {
        pattern: /composer\s+require\s+([^\s&|;]{1,300})/gi,
        type: 'composer'
      }
    ];

    // postinstall script risks
    this.postinstallRisks = [
      {
        pattern: /"(pre|post)?install"\s*:\s*"[^"]{0,300}curl/gi,
        risk: 'critical',
        title: 'Install script downloads',
        description: 'package.json install script contains download operation'
      },
      {
        pattern: /"(pre|post)?install"\s*:\s*"[^"]{0,300}wget/gi,
        risk: 'critical',
        title: 'Install script downloads',
        description: 'package.json install script contains wget'
      },
      {
        pattern: /"(pre|post)?install"\s*:\s*"[^"]{0,300}eval/gi,
        risk: 'critical',
        title: 'Install script eval',
        description: 'package.json install script uses eval'
      },
      {
        pattern: /"(pre|post)?install"\s*:\s*"[^"]{0,300}node\s+-e/gi,
        risk: 'high',
        title: 'Install script executes Node',
        description: 'Install script directly executes Node code'
      },
      {
        pattern: /"(pre|post)?install"\s*:\s*"[^"]{0,300}python/gi,
        risk: 'medium',
        title: 'Install script executes Python',
        description: 'Install script executes Python'
      }
    ];
  }

  async scan(skillContent) {
    const findings = {
      critical: [],
      high: [],
      medium: [],
      low: [],
      info: []
    };

    const content = this.getAllContent(skillContent);

    // Detect known malicious packages
    this.checkMaliciousPackages(content, findings);

    // Detect typosquatting
    this.checkTyposquatting(content, findings);

    // Check suspicious installation patterns
    for (const { pattern, risk, title, description } of this.suspiciousInstallPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        findings[risk].push({
          title: `[npm] ${title}`,
          description,
          matches: matches.slice(0, 3),
          scanner: 'DependencyScanner'
        });
      }
    }

    // Check pip malicious packages
    for (const pkg of this.maliciousPipPackages) {
      const pattern = new RegExp(`pip\\s+install\\s+[^\\n]{0,300}\\b${pkg}\\b`, 'gi');
      if (pattern.test(content)) {
        findings.critical.push({
          title: '[pip] Known malicious package',
          description: `Detected known malicious Python package: ${pkg}`,
          scanner: 'DependencyScanner'
        });
      }
    }

    // Check pip suspicious installation
    for (const { pattern, risk, title, description } of this.suspiciousPipPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        findings[risk].push({
          title: `[pip] ${title}`,
          description,
          matches: matches.slice(0, 3),
          scanner: 'DependencyScanner'
        });
      }
    }

    // Check postinstall script risks
    for (const { pattern, risk, title, description } of this.postinstallRisks) {
      const matches = content.match(pattern);
      if (matches) {
        findings[risk].push({
          title: `[package.json] ${title}`,
          description,
          matches: matches.slice(0, 2),
          scanner: 'DependencyScanner'
        });
      }
    }

    // Summarize installed packages
    this.summarizePackages(content, findings);

    return findings;
  }

  getAllContent(skillContent) {
    let content = skillContent.rawContent || '';
    for (const file of skillContent.files) {
      content += '\n' + file.content;
    }
    return content;
  }

  checkMaliciousPackages(content, findings) {
    for (const pkg of this.knownMaliciousPackages) {
      // Check npm install commands
      const npmPattern = new RegExp(`npm\\s+i(?:nstall)?\\s+[^\\n]{0,300}\\b${pkg}\\b`, 'gi');
      const yarnPattern = new RegExp(`yarn\\s+add\\s+[^\\n]{0,300}\\b${pkg}\\b`, 'gi');
      const pnpmPattern = new RegExp(`pnpm\\s+(?:add|install)\\s+[^\\n]{0,300}\\b${pkg}\\b`, 'gi');

      if (npmPattern.test(content) || yarnPattern.test(content) || pnpmPattern.test(content)) {
        findings.critical.push({
          title: '[npm] Known malicious/problematic package',
          description: `Detected known problematic package: ${pkg}, this package has had security incidents or has been abandoned`,
          scanner: 'DependencyScanner'
        });
      }

      // Also check package.json dependencies
      const depPattern = new RegExp(`"${pkg}"\\s*:\\s*"`, 'gi');
      if (depPattern.test(content)) {
        findings.critical.push({
          title: '[package.json] Known problematic dependency',
          description: `package.json contains known problematic package: ${pkg}`,
          scanner: 'DependencyScanner'
        });
      }
    }
  }

  checkTyposquatting(content, findings) {
    for (const { legitimate, typos, risk } of this.typosquatPatterns) {
      for (const typo of typos) {
        const pattern = new RegExp(`\\b${typo}\\b`, 'gi');
        if (pattern.test(content)) {
          findings[risk].push({
            title: '[Typosquatting] Suspicious package name',
            description: `Detected "${typo}", may be a typo of "${legitimate}" (typosquatting attack)`,
            scanner: 'DependencyScanner'
          });
        }
      }
    }
  }

  summarizePackages(content, findings) {
    const packages = new Set();

    for (const { pattern, type } of this.packageManagerPatterns) {
      // Reset regex
      const regex = new RegExp(pattern.source, pattern.flags);
      let match;
      while ((match = regex.exec(content)) !== null) {
        if (match[1]) {
          packages.add(`${type}:${match[1]}`);
        }
      }
    }

    if (packages.size > 0) {
      findings.info.push({
        title: `Detected ${packages.size} package install commands`,
        description: `Packages: ${[...packages].slice(0, 10).join(', ')}${packages.size > 10 ? '...' : ''}`,
        scanner: 'DependencyScanner'
      });
    }

    // Alert if installing many packages
    if (packages.size > 10) {
      findings.medium.push({
        title: 'Large number of package installations',
        description: `Skill installs ${packages.size} packages, please review each package carefully`,
        scanner: 'DependencyScanner'
      });
    }
  }
}
