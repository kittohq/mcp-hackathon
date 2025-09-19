# MCP BrightData Integration Specification

## Executive Summary

This specification defines the integration architecture between Model Context Protocol (MCP) and BrightData's web data collection infrastructure for security automation systems. The integration enables autonomous security agents to leverage BrightData's proxy networks and web scraping capabilities for threat intelligence gathering, vulnerability reconnaissance, and security monitoring while maintaining production safety and compliance.

## 1. Integration Overview

### 1.1 Purpose and Scope

The MCP-BrightData integration enables:
- **Threat Intelligence Collection**: Automated gathering of threat data from public sources
- **Dark Web Monitoring**: Safe reconnaissance of threat actor forums and marketplaces
- **Attack Surface Discovery**: External asset discovery and monitoring
- **Vulnerability Intelligence**: Real-time CVE and exploit monitoring
- **Brand Protection**: Detection of phishing sites and brand impersonation
- **Compliance Monitoring**: Automated compliance verification across web properties

### 1.2 Architecture Overview

```mermaid
graph TB
    subgraph "MCP Security Platform"
        MCP[MCP Server]
        AR[Auto-Remediation]
        AP[Agentic Pentesting]
        TI[Threat Intelligence]
    end

    subgraph "BrightData Infrastructure"
        PM[Proxy Manager]
        DC[Data Collector]
        WU[Web Unlocker]
        SI[Search Engine API]
        RP[Residential Proxies]
        DP[Datacenter Proxies]
    end

    subgraph "Data Processing"
        DP1[Data Parser]
        DV[Data Validator]
        DS[Data Sanitizer]
        DC1[Data Cache]
    end

    MCP --> PM
    PM --> RP
    PM --> DP
    MCP --> DC
    MCP --> WU
    MCP --> SI

    DC --> DP1
    WU --> DP1
    SI --> DP1

    DP1 --> DV
    DV --> DS
    DS --> DC1

    DC1 --> AR
    DC1 --> AP
    DC1 --> TI
```

## 2. MCP Server Configuration

### 2.1 Server Implementation

```typescript
// mcp-brightdata-server.ts
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { BrightDataClient } from './brightdata-client';
import { SecurityDataProcessor } from './security-processor';

interface BrightDataConfig {
  customer_id: string;
  password: string;
  proxy_zone: string;
  datacenter_zone?: string;
  collector_token?: string;
  unlocker_token?: string;
  search_api_token?: string;
  safety_mode: 'production' | 'staging' | 'development';
}

class MCPBrightDataServer {
  private server: Server;
  private brightdata: BrightDataClient;
  private processor: SecurityDataProcessor;
  private config: BrightDataConfig;

  constructor(config: BrightDataConfig) {
    this.config = config;
    this.server = new Server(
      {
        name: 'mcp-brightdata-security',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {
            search: true,
            collect: true,
            monitor: true,
            analyze: true
          }
        }
      }
    );

    this.brightdata = new BrightDataClient(config);
    this.processor = new SecurityDataProcessor();
    this.setupTools();
  }

  private setupTools(): void {
    // Threat Intelligence Collection Tool
    this.server.setRequestHandler('tools/threat_intelligence', async (request) => {
      const { sources, keywords, depth } = request.params;

      // Safety checks for production mode
      if (this.config.safety_mode === 'production') {
        this.validateProductionSafety(sources);
      }

      // Collect threat data
      const data = await this.brightdata.collectThreatIntel({
        sources,
        keywords,
        depth,
        proxy_type: 'residential',
        rotation: 'per_request'
      });

      // Process and sanitize
      const processed = await this.processor.processThreatData(data);

      return {
        tool: 'threat_intelligence',
        result: processed,
        metadata: {
          sources_scanned: sources.length,
          data_points: processed.indicators.length,
          confidence: processed.confidence_score
        }
      };
    });

    // External Asset Discovery Tool
    this.server.setRequestHandler('tools/asset_discovery', async (request) => {
      const { domain, scope, recursive } = request.params;

      const discovered = await this.brightdata.discoverAssets({
        root_domain: domain,
        scope: scope || 'subdomain',
        recursive: recursive || false,
        methods: ['dns', 'certificate', 'search_engine', 'web_crawl']
      });

      return {
        tool: 'asset_discovery',
        result: {
          domains: discovered.domains,
          ip_addresses: discovered.ips,
          technologies: discovered.technologies,
          services: discovered.services
        }
      };
    });

    // Dark Web Monitoring Tool
    this.server.setRequestHandler('tools/darkweb_monitor', async (request) => {
      const { keywords, forums, alert_threshold } = request.params;

      // Enhanced safety for dark web operations
      const safetyConfig = {
        use_tor: true,
        residential_only: true,
        fingerprint_protection: true,
        javascript_disabled: true
      };

      const findings = await this.brightdata.monitorDarkWeb({
        keywords,
        forums: forums || this.getDefaultDarkWebSources(),
        safety: safetyConfig,
        alert_threshold: alert_threshold || 0.7
      });

      return {
        tool: 'darkweb_monitor',
        result: this.processor.sanitizeDarkWebFindings(findings)
      };
    });

    // Phishing Detection Tool
    this.server.setRequestHandler('tools/phishing_detection', async (request) => {
      const { brand_keywords, domain_variations, check_newly_registered } = request.params;

      const phishingSites = await this.brightdata.detectPhishing({
        brand_keywords,
        domain_variations,
        check_newly_registered: check_newly_registered || true,
        screenshot: true,
        similarity_threshold: 0.85
      });

      return {
        tool: 'phishing_detection',
        result: {
          confirmed_phishing: phishingSites.confirmed,
          suspicious_sites: phishingSites.suspicious,
          screenshots: phishingSites.screenshots,
          risk_scores: phishingSites.risk_scores
        }
      };
    });
  }

  private validateProductionSafety(sources: string[]): void {
    const prohibited = [
      'internal.company.com',
      'admin.company.com',
      '10.0.0.0/8',
      '172.16.0.0/12',
      '192.168.0.0/16'
    ];

    for (const source of sources) {
      if (prohibited.some(p => source.includes(p))) {
        throw new Error(`Production safety violation: Cannot scan internal resource ${source}`);
      }
    }
  }

  async start(): Promise<void> {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('MCP BrightData Security Server running');
  }
}
```

### 2.2 BrightData Client Implementation

```typescript
// brightdata-client.ts
import axios, { AxiosInstance } from 'axios';
import { SocksProxyAgent } from 'socks-proxy-agent';
import * as puppeteer from 'puppeteer';

export class BrightDataClient {
  private proxyManager: AxiosInstance;
  private dataCollector: AxiosInstance;
  private webUnlocker: AxiosInstance;
  private searchAPI: AxiosInstance;
  private config: any;

  constructor(config: any) {
    this.config = config;
    this.initializeClients();
  }

  private initializeClients(): void {
    // Proxy Manager client
    const proxyUrl = `http://${this.config.customer_id}-zone-${this.config.proxy_zone}:${this.config.password}@zproxy.lum-superproxy.io:22225`;

    this.proxyManager = axios.create({
      httpsAgent: new SocksProxyAgent(proxyUrl),
      timeout: 30000,
      headers: {
        'User-Agent': this.getRotatingUserAgent()
      }
    });

    // Data Collector client
    this.dataCollector = axios.create({
      baseURL: 'https://api.brightdata.com/dca/v2',
      headers: {
        'Authorization': `Bearer ${this.config.collector_token}`,
        'Content-Type': 'application/json'
      }
    });

    // Web Unlocker client
    this.webUnlocker = axios.create({
      proxy: {
        host: 'unlocker.brightdata.com',
        port: 22225,
        auth: {
          username: `${this.config.customer_id}-zone-unlocker`,
          password: this.config.password
        }
      }
    });

    // Search Engine API
    this.searchAPI = axios.create({
      baseURL: 'https://api.brightdata.com/serp/v2',
      headers: {
        'Authorization': `Bearer ${this.config.search_api_token}`
      }
    });
  }

  async collectThreatIntel(params: any): Promise<any> {
    const collectionTasks = params.sources.map(async (source: string) => {
      try {
        // Use appropriate collection method based on source type
        if (this.isSearchEngine(source)) {
          return await this.searchEngineScrape(source, params.keywords);
        } else if (this.requiresJavaScript(source)) {
          return await this.browserScrape(source, params);
        } else {
          return await this.httpScrape(source, params);
        }
      } catch (error) {
        console.error(`Failed to collect from ${source}:`, error);
        return { source, error: error.message, data: null };
      }
    });

    const results = await Promise.all(collectionTasks);
    return this.aggregateThreatData(results);
  }

  private async searchEngineScrape(engine: string, keywords: string[]): Promise<any> {
    const searchResults = await this.searchAPI.post('/search', {
      engine,
      q: keywords.join(' OR '),
      num: 100,
      include_html: true,
      country: 'us'
    });

    return {
      source: engine,
      type: 'search_engine',
      results: searchResults.data.organic_results,
      metadata: {
        total_results: searchResults.data.total_results,
        search_time: searchResults.data.search_time
      }
    };
  }

  private async browserScrape(url: string, params: any): Promise<any> {
    const browser = await puppeteer.launch({
      args: [
        `--proxy-server=${this.getProxyUrl()}`,
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage'
      ]
    });

    try {
      const page = await browser.newPage();

      // Set up request interception for safety
      await page.setRequestInterception(true);
      page.on('request', (request) => {
        if (this.shouldBlockRequest(request.url())) {
          request.abort();
        } else {
          request.continue();
        }
      });

      // Navigate with timeout
      await page.goto(url, {
        waitUntil: 'networkidle2',
        timeout: 30000
      });

      // Extract threat intelligence data
      const data = await page.evaluate(() => {
        // Custom extraction logic based on page structure
        return {
          title: document.title,
          content: document.body.innerText,
          links: Array.from(document.querySelectorAll('a')).map(a => a.href),
          metadata: {
            // Extract threat indicators
            ips: (document.body.innerText.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g) || []),
            hashes: (document.body.innerText.match(/\b[a-fA-F0-9]{32,64}\b/g) || []),
            emails: (document.body.innerText.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [])
          }
        };
      });

      return {
        source: url,
        type: 'browser_scrape',
        data,
        screenshot: await page.screenshot({ encoding: 'base64' })
      };
    } finally {
      await browser.close();
    }
  }

  private async httpScrape(url: string, params: any): Promise<any> {
    const response = await this.proxyManager.get(url, {
      headers: {
        'Accept': 'text/html,application/json',
        'Accept-Language': 'en-US,en;q=0.9',
        'Cache-Control': 'no-cache'
      }
    });

    return {
      source: url,
      type: 'http_scrape',
      data: response.data,
      headers: response.headers,
      status: response.status
    };
  }

  async discoverAssets(params: any): Promise<any> {
    const discovery = {
      domains: new Set<string>(),
      ips: new Set<string>(),
      technologies: new Map<string, any>(),
      services: new Map<string, any>()
    };

    // Search engine discovery
    const searchEngines = ['google', 'bing', 'duckduckgo'];
    for (const engine of searchEngines) {
      const results = await this.searchAPI.post('/search', {
        engine,
        q: `site:${params.root_domain} OR "${params.root_domain}"`,
        num: 100
      });

      results.data.organic_results.forEach((result: any) => {
        const url = new URL(result.url);
        discovery.domains.add(url.hostname);
      });
    }

    // Certificate transparency logs
    const ctLogs = await this.queryCertificateTransparency(params.root_domain);
    ctLogs.forEach((cert: any) => {
      cert.dns_names.forEach((name: string) => {
        if (name.includes(params.root_domain)) {
          discovery.domains.add(name);
        }
      });
    });

    // Technology detection on discovered domains
    for (const domain of discovery.domains) {
      try {
        const tech = await this.detectTechnologies(`https://${domain}`);
        discovery.technologies.set(domain, tech);
      } catch (error) {
        console.error(`Technology detection failed for ${domain}:`, error);
      }
    }

    return {
      domains: Array.from(discovery.domains),
      ips: Array.from(discovery.ips),
      technologies: Object.fromEntries(discovery.technologies),
      services: Object.fromEntries(discovery.services)
    };
  }

  async monitorDarkWeb(params: any): Promise<any> {
    // Enhanced safety for dark web monitoring
    const torProxy = `socks5://${this.config.customer_id}-zone-residential-tor:${this.config.password}@zproxy.lum-superproxy.io:22226`;

    const torClient = axios.create({
      httpsAgent: new SocksProxyAgent(torProxy),
      timeout: 60000,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0'
      }
    });

    const findings = [];

    for (const forum of params.forums) {
      try {
        // Safe crawling with rate limiting
        await this.delay(this.getRandomDelay());

        const response = await torClient.get(forum.url, {
          maxRedirects: 0,
          validateStatus: (status) => status < 500
        });

        // Search for keywords in content
        const matches = this.searchKeywords(response.data, params.keywords);

        if (matches.length > 0) {
          findings.push({
            source: forum.name,
            url: forum.url,
            matches,
            timestamp: new Date().toISOString(),
            risk_score: this.calculateRiskScore(matches, forum.reputation)
          });
        }
      } catch (error) {
        console.error(`Dark web monitoring error for ${forum.name}:`, error);
      }
    }

    return findings;
  }

  async detectPhishing(params: any): Promise<any> {
    const phishingResults = {
      confirmed: [],
      suspicious: [],
      screenshots: {},
      risk_scores: {}
    };

    // Generate domain variations
    const domainVariations = this.generateDomainVariations(params.brand_keywords);

    // Check newly registered domains
    if (params.check_newly_registered) {
      const newDomains = await this.checkNewlyRegisteredDomains(domainVariations);

      for (const domain of newDomains) {
        const analysis = await this.analyzePhishingSite(domain, params);

        if (analysis.risk_score > 0.9) {
          phishingResults.confirmed.push(domain);
        } else if (analysis.risk_score > 0.6) {
          phishingResults.suspicious.push(domain);
        }

        phishingResults.risk_scores[domain] = analysis.risk_score;

        if (params.screenshot && analysis.screenshot) {
          phishingResults.screenshots[domain] = analysis.screenshot;
        }
      }
    }

    // Search for existing phishing sites
    const searchResults = await this.searchForPhishing(params.brand_keywords);

    for (const result of searchResults) {
      const analysis = await this.analyzePhishingSite(result.url, params);

      if (analysis.risk_score > params.similarity_threshold) {
        if (analysis.risk_score > 0.9) {
          phishingResults.confirmed.push(result.url);
        } else {
          phishingResults.suspicious.push(result.url);
        }

        phishingResults.risk_scores[result.url] = analysis.risk_score;
      }
    }

    return phishingResults;
  }

  // Helper methods
  private getRotatingUserAgent(): string {
    const userAgents = [
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
    ];
    return userAgents[Math.floor(Math.random() * userAgents.length)];
  }

  private getProxyUrl(): string {
    return `http://${this.config.customer_id}-zone-${this.config.proxy_zone}:${this.config.password}@zproxy.lum-superproxy.io:22225`;
  }

  private shouldBlockRequest(url: string): boolean {
    const blocked = ['analytics', 'tracking', 'advertisement', 'doubleclick', 'facebook'];
    return blocked.some(b => url.includes(b));
  }

  private isSearchEngine(source: string): boolean {
    return ['google', 'bing', 'duckduckgo', 'shodan'].includes(source.toLowerCase());
  }

  private requiresJavaScript(source: string): boolean {
    return source.includes('twitter') || source.includes('linkedin') || source.includes('facebook');
  }

  private getRandomDelay(): number {
    return Math.floor(Math.random() * 3000) + 2000; // 2-5 seconds
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private async queryCertificateTransparency(domain: string): Promise<any[]> {
    const response = await axios.get(`https://crt.sh/?q=${domain}&output=json`);
    return response.data;
  }

  private async detectTechnologies(url: string): Promise<any> {
    // Implement Wappalyzer-like technology detection
    try {
      const response = await this.webUnlocker.get(url);
      const technologies = {
        server: response.headers.server,
        powered_by: response.headers['x-powered-by'],
        cms: this.detectCMS(response.data),
        javascript_frameworks: this.detectJSFrameworks(response.data),
        security_headers: this.analyzeSecurityHeaders(response.headers)
      };
      return technologies;
    } catch (error) {
      return { error: error.message };
    }
  }

  private detectCMS(html: string): string[] {
    const cms = [];
    if (html.includes('wp-content')) cms.push('WordPress');
    if (html.includes('Drupal')) cms.push('Drupal');
    if (html.includes('Joomla')) cms.push('Joomla');
    return cms;
  }

  private detectJSFrameworks(html: string): string[] {
    const frameworks = [];
    if (html.includes('react')) frameworks.push('React');
    if (html.includes('angular')) frameworks.push('Angular');
    if (html.includes('vue')) frameworks.push('Vue.js');
    return frameworks;
  }

  private analyzeSecurityHeaders(headers: any): any {
    return {
      has_hsts: !!headers['strict-transport-security'],
      has_csp: !!headers['content-security-policy'],
      has_x_frame_options: !!headers['x-frame-options'],
      has_x_content_type_options: !!headers['x-content-type-options']
    };
  }

  private searchKeywords(content: string, keywords: string[]): any[] {
    const matches = [];
    const contentLower = content.toLowerCase();

    for (const keyword of keywords) {
      const keywordLower = keyword.toLowerCase();
      if (contentLower.includes(keywordLower)) {
        // Find context around keyword
        const index = contentLower.indexOf(keywordLower);
        const contextStart = Math.max(0, index - 100);
        const contextEnd = Math.min(content.length, index + keyword.length + 100);
        const context = content.substring(contextStart, contextEnd);

        matches.push({
          keyword,
          context,
          position: index
        });
      }
    }

    return matches;
  }

  private calculateRiskScore(matches: any[], forumReputation: number): number {
    const matchScore = Math.min(matches.length * 0.1, 0.5);
    const reputationScore = forumReputation * 0.5;
    return Math.min(matchScore + reputationScore, 1.0);
  }

  private generateDomainVariations(keywords: string[]): string[] {
    const variations = [];
    const tlds = ['.com', '.net', '.org', '.io', '.app', '.site'];

    for (const keyword of keywords) {
      // Typosquatting variations
      variations.push(...this.generateTypos(keyword));

      // Homograph attacks
      variations.push(...this.generateHomographs(keyword));

      // Subdomain variations
      variations.push(`${keyword}-login`, `${keyword}-secure`, `${keyword}-verify`);

      // Add different TLDs
      for (const variation of variations) {
        for (const tld of tlds) {
          variations.push(variation + tld);
        }
      }
    }

    return [...new Set(variations)];
  }

  private generateTypos(word: string): string[] {
    const typos = [];
    const keyboard = {
      'a': ['s', 'q', 'z'],
      'b': ['v', 'g', 'n'],
      // ... more keyboard adjacency mappings
    };

    // Character substitution
    for (let i = 0; i < word.length; i++) {
      const char = word[i];
      if (keyboard[char]) {
        for (const replacement of keyboard[char]) {
          typos.push(word.substring(0, i) + replacement + word.substring(i + 1));
        }
      }
    }

    // Character omission
    for (let i = 0; i < word.length; i++) {
      typos.push(word.substring(0, i) + word.substring(i + 1));
    }

    return typos;
  }

  private generateHomographs(word: string): string[] {
    const homographs = [];
    const replacements = {
      'a': ['а', 'ɑ'],  // Cyrillic and IPA
      'e': ['е', 'ё'],  // Cyrillic
      'o': ['о', '0'],  // Cyrillic and zero
      // ... more homograph mappings
    };

    for (let i = 0; i < word.length; i++) {
      const char = word[i];
      if (replacements[char]) {
        for (const replacement of replacements[char]) {
          homographs.push(word.substring(0, i) + replacement + word.substring(i + 1));
        }
      }
    }

    return homographs;
  }

  private async checkNewlyRegisteredDomains(domains: string[]): Promise<string[]> {
    const newDomains = [];
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

    for (const domain of domains) {
      try {
        const whoisData = await this.getWhoisData(domain);
        if (whoisData.created_date > thirtyDaysAgo) {
          newDomains.push(domain);
        }
      } catch (error) {
        // Domain doesn't exist or WHOIS failed
        continue;
      }
    }

    return newDomains;
  }

  private async getWhoisData(domain: string): Promise<any> {
    // Implement WHOIS lookup
    // This would typically use a WHOIS API service
    return {
      domain,
      created_date: new Date(),
      registrar: 'Unknown',
      name_servers: []
    };
  }

  private async analyzePhishingSite(url: string, params: any): Promise<any> {
    let risk_score = 0;
    let screenshot = null;

    try {
      // Visual similarity check
      if (params.screenshot) {
        const browser = await puppeteer.launch({
          args: [`--proxy-server=${this.getProxyUrl()}`, '--no-sandbox']
        });

        const page = await browser.newPage();
        await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });
        screenshot = await page.screenshot({ encoding: 'base64' });

        // Compare with legitimate site screenshot
        const similarity = await this.compareVisualSimilarity(screenshot, params.legitimate_screenshot);
        risk_score += similarity * 0.5;

        await browser.close();
      }

      // Content analysis
      const response = await this.webUnlocker.get(url);
      const content = response.data;

      // Check for brand keywords
      const brandMatches = params.brand_keywords.filter((kw: string) =>
        content.toLowerCase().includes(kw.toLowerCase())
      );
      risk_score += (brandMatches.length / params.brand_keywords.length) * 0.3;

      // Check for phishing indicators
      const phishingIndicators = [
        'verify your account',
        'suspended account',
        'click here immediately',
        'confirm your identity',
        'update payment information'
      ];

      const indicatorMatches = phishingIndicators.filter(ind =>
        content.toLowerCase().includes(ind)
      );
      risk_score += (indicatorMatches.length / phishingIndicators.length) * 0.2;

    } catch (error) {
      console.error(`Failed to analyze ${url}:`, error);
    }

    return { risk_score: Math.min(risk_score, 1.0), screenshot };
  }

  private async compareVisualSimilarity(screenshot1: string, screenshot2: string): Promise<number> {
    // Implement visual similarity comparison
    // This would typically use image comparison libraries or ML models
    return 0.85; // Placeholder
  }

  private async searchForPhishing(keywords: string[]): Promise<any[]> {
    const results = [];

    // Search for potential phishing sites
    const searchQueries = keywords.map(kw => `"${kw}" login OR "${kw}" password`);

    for (const query of searchQueries) {
      const searchResults = await this.searchAPI.post('/search', {
        engine: 'google',
        q: query,
        num: 50
      });

      results.push(...searchResults.data.organic_results.map((r: any) => ({
        url: r.url,
        title: r.title,
        snippet: r.snippet
      })));
    }

    return results;
  }

  private aggregateThreatData(results: any[]): any {
    const aggregated = {
      indicators: [],
      sources: [],
      confidence_score: 0,
      metadata: {}
    };

    for (const result of results) {
      if (result.data) {
        aggregated.sources.push(result.source);

        // Extract indicators
        if (result.data.metadata) {
          aggregated.indicators.push(...(result.data.metadata.ips || []));
          aggregated.indicators.push(...(result.data.metadata.hashes || []));
          aggregated.indicators.push(...(result.data.metadata.emails || []));
        }
      }
    }

    // Remove duplicates
    aggregated.indicators = [...new Set(aggregated.indicators)];

    // Calculate confidence based on source diversity
    aggregated.confidence_score = Math.min(aggregated.sources.length / 10, 1.0);

    return aggregated;
  }

  private getDefaultDarkWebSources(): any[] {
    return [
      { name: 'Forum1', url: 'http://example.onion/forum', reputation: 0.8 },
      { name: 'Market1', url: 'http://example.onion/market', reputation: 0.7 },
      // Note: These are placeholders. Real onion URLs would be configured securely
    ];
  }
}
```

### 2.3 Security Data Processor

```typescript
// security-processor.ts
export class SecurityDataProcessor {
  private readonly sensitivePatterns: RegExp[];
  private readonly iocPatterns: Map<string, RegExp>;

  constructor() {
    this.sensitivePatterns = [
      /\b(?:\d{3}-\d{2}-\d{4})\b/g, // SSN
      /\b(?:\d{4}[-\s]?){3}\d{4}\b/g, // Credit card
      /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g // Email
    ];

    this.iocPatterns = new Map([
      ['ipv4', /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g],
      ['ipv6', /(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}/g],
      ['md5', /\b[a-fA-F0-9]{32}\b/g],
      ['sha1', /\b[a-fA-F0-9]{40}\b/g],
      ['sha256', /\b[a-fA-F0-9]{64}\b/g],
      ['domain', /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g],
      ['url', /https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)/g],
      ['cve', /CVE-\d{4}-\d{4,7}/g]
    ]);
  }

  async processThreatData(data: any): Promise<any> {
    // Sanitize sensitive information
    const sanitized = this.sanitizeSensitiveData(data);

    // Extract IOCs
    const iocs = this.extractIOCs(sanitized);

    // Enrich with threat intelligence
    const enriched = await this.enrichWithThreatIntel(iocs);

    // Calculate threat scores
    const scored = this.calculateThreatScores(enriched);

    return {
      indicators: scored,
      raw_data: sanitized,
      confidence_score: this.calculateConfidence(scored),
      timestamp: new Date().toISOString()
    };
  }

  sanitizeDarkWebFindings(findings: any[]): any[] {
    return findings.map(finding => {
      // Remove any PII or sensitive data
      const sanitized = { ...finding };

      if (sanitized.content) {
        for (const pattern of this.sensitivePatterns) {
          sanitized.content = sanitized.content.replace(pattern, '[REDACTED]');
        }
      }

      // Anonymize sources if needed
      if (sanitized.source && sanitized.source.includes('.onion')) {
        sanitized.source = this.hashSource(sanitized.source);
      }

      return sanitized;
    });
  }

  private sanitizeSensitiveData(data: any): any {
    const sanitize = (obj: any): any => {
      if (typeof obj === 'string') {
        let sanitized = obj;
        for (const pattern of this.sensitivePatterns) {
          sanitized = sanitized.replace(pattern, '[REDACTED]');
        }
        return sanitized;
      } else if (Array.isArray(obj)) {
        return obj.map(item => sanitize(item));
      } else if (typeof obj === 'object' && obj !== null) {
        const result: any = {};
        for (const key in obj) {
          result[key] = sanitize(obj[key]);
        }
        return result;
      }
      return obj;
    };

    return sanitize(data);
  }

  private extractIOCs(data: any): Map<string, Set<string>> {
    const iocs = new Map<string, Set<string>>();

    // Initialize sets for each IOC type
    for (const [type] of this.iocPatterns) {
      iocs.set(type, new Set<string>());
    }

    // Recursive extraction
    const extract = (obj: any): void => {
      if (typeof obj === 'string') {
        for (const [type, pattern] of this.iocPatterns) {
          const matches = obj.match(pattern) || [];
          matches.forEach(match => iocs.get(type)!.add(match));
        }
      } else if (Array.isArray(obj)) {
        obj.forEach(item => extract(item));
      } else if (typeof obj === 'object' && obj !== null) {
        Object.values(obj).forEach(value => extract(value));
      }
    };

    extract(data);
    return iocs;
  }

  private async enrichWithThreatIntel(iocs: Map<string, Set<string>>): Promise<any[]> {
    const enriched = [];

    for (const [type, values] of iocs) {
      for (const value of values) {
        const enrichment = await this.lookupThreatIntel(type, value);
        enriched.push({
          type,
          value,
          ...enrichment
        });
      }
    }

    return enriched;
  }

  private async lookupThreatIntel(type: string, value: string): Promise<any> {
    // This would integrate with threat intelligence APIs
    // For now, return mock enrichment
    return {
      reputation: Math.random(),
      first_seen: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000),
      last_seen: new Date(),
      tags: ['malware', 'phishing', 'botnet'][Math.floor(Math.random() * 3)],
      confidence: Math.random()
    };
  }

  private calculateThreatScores(indicators: any[]): any[] {
    return indicators.map(indicator => {
      let score = 0;

      // Base score on reputation
      score += (1 - indicator.reputation) * 40;

      // Recency factor
      const daysSinceLastSeen = (Date.now() - indicator.last_seen) / (24 * 60 * 60 * 1000);
      if (daysSinceLastSeen < 1) score += 30;
      else if (daysSinceLastSeen < 7) score += 20;
      else if (daysSinceLastSeen < 30) score += 10;

      // Tag severity
      if (indicator.tags?.includes('malware')) score += 20;
      if (indicator.tags?.includes('phishing')) score += 15;
      if (indicator.tags?.includes('botnet')) score += 15;

      return {
        ...indicator,
        threat_score: Math.min(score, 100)
      };
    });
  }

  private calculateConfidence(indicators: any[]): number {
    if (indicators.length === 0) return 0;

    const avgConfidence = indicators.reduce((sum, ind) => sum + (ind.confidence || 0), 0) / indicators.length;
    const sourceDiv = new Set(indicators.map(ind => ind.source)).size / 10;

    return Math.min((avgConfidence + sourceDiv) / 2, 1.0);
  }

  private hashSource(source: string): string {
    // Simple hash for anonymization
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(source).digest('hex').substring(0, 16);
  }
}
```

## 3. Configuration and Deployment

### 3.1 MCP Configuration File

```json
{
  "mcpServers": {
    "brightdata-security": {
      "command": "node",
      "args": ["/path/to/mcp-brightdata-server.js"],
      "env": {
        "BRIGHTDATA_CUSTOMER_ID": "${BRIGHTDATA_CUSTOMER_ID}",
        "BRIGHTDATA_PASSWORD": "${BRIGHTDATA_PASSWORD}",
        "BRIGHTDATA_PROXY_ZONE": "security_residential",
        "BRIGHTDATA_DATACENTER_ZONE": "security_datacenter",
        "BRIGHTDATA_COLLECTOR_TOKEN": "${BRIGHTDATA_COLLECTOR_TOKEN}",
        "BRIGHTDATA_UNLOCKER_TOKEN": "${BRIGHTDATA_UNLOCKER_TOKEN}",
        "BRIGHTDATA_SEARCH_API_TOKEN": "${BRIGHTDATA_SEARCH_API_TOKEN}",
        "SAFETY_MODE": "production"
      }
    }
  }
}
```

### 3.2 Docker Deployment

```dockerfile
FROM node:18-alpine

# Install Chrome for Puppeteer
RUN apk add --no-cache \
    chromium \
    nss \
    freetype \
    freetype-dev \
    harfbuzz \
    ca-certificates \
    ttf-freefont

# Set Puppeteer to use installed Chromium
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser

WORKDIR /app

# Copy package files
COPY package*.json ./
RUN npm ci --only=production

# Copy source code
COPY . .

# Build TypeScript
RUN npm run build

# Security hardening
RUN addgroup -g 1001 -S mcpuser && \
    adduser -u 1001 -S mcpuser -G mcpuser && \
    chown -R mcpuser:mcpuser /app

USER mcpuser

EXPOSE 3000

CMD ["node", "dist/server.js"]
```

### 3.3 Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-brightdata-security
  namespace: security-automation
spec:
  replicas: 3
  selector:
    matchLabels:
      app: mcp-brightdata
  template:
    metadata:
      labels:
        app: mcp-brightdata
    spec:
      serviceAccountName: mcp-brightdata-sa
      securityContext:
        runAsNonRoot: true
        runAsUser: 1001
        fsGroup: 1001
      containers:
      - name: mcp-server
        image: mcp-brightdata-security:latest
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        env:
        - name: BRIGHTDATA_CUSTOMER_ID
          valueFrom:
            secretKeyRef:
              name: brightdata-credentials
              key: customer_id
        - name: BRIGHTDATA_PASSWORD
          valueFrom:
            secretKeyRef:
              name: brightdata-credentials
              key: password
        - name: SAFETY_MODE
          value: "production"
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 3000
          initialDelaySeconds: 10
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: mcp-brightdata-service
  namespace: security-automation
spec:
  selector:
    app: mcp-brightdata
  ports:
    - protocol: TCP
      port: 3000
      targetPort: 3000
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: mcp-brightdata-hpa
  namespace: security-automation
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: mcp-brightdata-security
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

## 4. Integration Use Cases

### 4.1 Automated Threat Hunting

```typescript
class ThreatHunter {
  private mcpClient: MCPClient;

  async huntForThreats(organization: string): Promise<ThreatReport> {
    // Phase 1: Asset Discovery
    const assets = await this.mcpClient.call('tools/asset_discovery', {
      domain: organization,
      scope: 'full',
      recursive: true
    });

    // Phase 2: Dark Web Monitoring
    const darkWebFindings = await this.mcpClient.call('tools/darkweb_monitor', {
      keywords: [organization, ...assets.domains],
      alert_threshold: 0.6
    });

    // Phase 3: Phishing Detection
    const phishingSites = await this.mcpClient.call('tools/phishing_detection', {
      brand_keywords: [organization],
      domain_variations: true,
      check_newly_registered: true
    });

    // Phase 4: Threat Intelligence Collection
    const threatIntel = await this.mcpClient.call('tools/threat_intelligence', {
      sources: ['shodan', 'virustotal', 'threatcrowd'],
      keywords: [...assets.ips, ...assets.domains],
      depth: 'comprehensive'
    });

    return this.compileThreatReport({
      assets,
      darkWebFindings,
      phishingSites,
      threatIntel
    });
  }
}
```

### 4.2 Continuous Security Monitoring

```typescript
class SecurityMonitor {
  private mcpClient: MCPClient;
  private alertManager: AlertManager;

  async startMonitoring(config: MonitoringConfig): Promise<void> {
    // Set up scheduled monitoring tasks
    setInterval(async () => {
      try {
        // Monitor for new phishing domains
        const phishing = await this.mcpClient.call('tools/phishing_detection', {
          brand_keywords: config.brand_keywords,
          check_newly_registered: true
        });

        if (phishing.confirmed.length > 0) {
          await this.alertManager.sendAlert({
            severity: 'critical',
            type: 'phishing_detected',
            data: phishing.confirmed
          });
        }

        // Monitor dark web for data leaks
        const darkWeb = await this.mcpClient.call('tools/darkweb_monitor', {
          keywords: config.sensitive_keywords,
          alert_threshold: 0.7
        });

        if (darkWeb.length > 0) {
          await this.alertManager.sendAlert({
            severity: 'high',
            type: 'darkweb_mention',
            data: darkWeb
          });
        }

      } catch (error) {
        console.error('Monitoring error:', error);
      }
    }, config.interval || 3600000); // Default: 1 hour
  }
}
```

## 5. Security Considerations

### 5.1 Data Protection

```yaml
data_protection:
  encryption:
    - at_rest: AES-256-GCM
    - in_transit: TLS 1.3
    - key_management: HSM-backed

  privacy:
    - pii_detection: automatic
    - pii_handling: redaction
    - data_retention: 30_days
    - gdpr_compliant: true

  access_control:
    - authentication: mTLS + API keys
    - authorization: RBAC
    - audit_logging: comprehensive
```

### 5.2 Rate Limiting and Quotas

```typescript
class RateLimiter {
  private limits = {
    threat_intelligence: { requests: 100, window: 3600000 },
    asset_discovery: { requests: 10, window: 3600000 },
    darkweb_monitor: { requests: 5, window: 3600000 },
    phishing_detection: { requests: 20, window: 3600000 }
  };

  async checkLimit(tool: string, userId: string): Promise<boolean> {
    const key = `${tool}:${userId}`;
    const limit = this.limits[tool];

    const current = await this.getRequestCount(key);
    if (current >= limit.requests) {
      throw new Error(`Rate limit exceeded for ${tool}`);
    }

    await this.incrementCounter(key, limit.window);
    return true;
  }
}
```

## 6. Monitoring and Observability

### 6.1 Metrics Collection

```yaml
metrics:
  operational:
    - requests_per_second
    - response_time_p95
    - error_rate
    - proxy_rotation_rate

  business:
    - threats_detected
    - phishing_sites_found
    - assets_discovered
    - dark_web_mentions

  cost:
    - bandwidth_usage
    - api_calls_count
    - proxy_minutes_used
    - data_collector_credits
```

### 6.2 Logging Configuration

```typescript
class SecurityLogger {
  private logger: Logger;

  constructor() {
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.json(),
      transports: [
        new winston.transports.File({ filename: 'security-ops.log' }),
        new winston.transports.Console({
          format: winston.format.simple()
        })
      ]
    });
  }

  logSecurityOperation(operation: any): void {
    this.logger.info('Security operation executed', {
      timestamp: new Date().toISOString(),
      operation: operation.type,
      target: operation.target,
      result: operation.result,
      metadata: this.sanitizeMetadata(operation.metadata)
    });
  }

  private sanitizeMetadata(metadata: any): any {
    // Remove sensitive information from logs
    const sanitized = { ...metadata };
    delete sanitized.api_keys;
    delete sanitized.passwords;
    delete sanitized.personal_data;
    return sanitized;
  }
}
```

## 7. Performance Optimization

### 7.1 Caching Strategy

```typescript
class SecurityCache {
  private cache: Map<string, CacheEntry>;
  private ttl: Map<string, number>;

  constructor() {
    this.cache = new Map();
    this.ttl = new Map([
      ['asset_discovery', 86400000], // 24 hours
      ['threat_intelligence', 3600000], // 1 hour
      ['phishing_detection', 1800000], // 30 minutes
      ['darkweb_monitor', 7200000] // 2 hours
    ]);
  }

  async get(key: string, operation: string): Promise<any> {
    const entry = this.cache.get(key);

    if (entry && Date.now() - entry.timestamp < this.ttl.get(operation)!) {
      return entry.data;
    }

    return null;
  }

  async set(key: string, operation: string, data: any): Promise<void> {
    this.cache.set(key, {
      data,
      timestamp: Date.now(),
      operation
    });

    // Clean up old entries
    this.cleanup();
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.cache.entries()) {
      const ttl = this.ttl.get(entry.operation);
      if (ttl && now - entry.timestamp > ttl) {
        this.cache.delete(key);
      }
    }
  }
}

interface CacheEntry {
  data: any;
  timestamp: number;
  operation: string;
}
```

## 8. Testing and Validation

### 8.1 Integration Tests

```typescript
describe('MCP BrightData Integration', () => {
  let mcpServer: MCPBrightDataServer;
  let testClient: MCPClient;

  beforeAll(async () => {
    mcpServer = new MCPBrightDataServer({
      customer_id: 'test_customer',
      password: 'test_password',
      proxy_zone: 'test_zone',
      safety_mode: 'development'
    });
    await mcpServer.start();
    testClient = new MCPClient('localhost:3000');
  });

  describe('Threat Intelligence Collection', () => {
    it('should collect threat data from multiple sources', async () => {
      const result = await testClient.call('tools/threat_intelligence', {
        sources: ['test_source_1', 'test_source_2'],
        keywords: ['test_threat'],
        depth: 'basic'
      });

      expect(result.tool).toBe('threat_intelligence');
      expect(result.result.indicators).toBeDefined();
      expect(result.result.confidence_score).toBeGreaterThan(0);
    });

    it('should sanitize sensitive data', async () => {
      const result = await testClient.call('tools/threat_intelligence', {
        sources: ['test_source_with_pii'],
        keywords: ['test'],
        depth: 'basic'
      });

      const jsonString = JSON.stringify(result.result);
      expect(jsonString).not.toContain('123-45-6789'); // SSN
      expect(jsonString).not.toContain('4111111111111111'); // Credit card
    });
  });

  describe('Production Safety', () => {
    it('should block internal network scanning', async () => {
      await expect(
        testClient.call('tools/asset_discovery', {
          domain: '192.168.1.1',
          scope: 'full'
        })
      ).rejects.toThrow('Production safety violation');
    });

    it('should enforce rate limits', async () => {
      const promises = [];
      for (let i = 0; i < 150; i++) {
        promises.push(
          testClient.call('tools/threat_intelligence', {
            sources: ['test'],
            keywords: ['test']
          })
        );
      }

      await expect(Promise.all(promises)).rejects.toThrow('Rate limit exceeded');
    });
  });
});
```

## 9. Troubleshooting Guide

### 9.1 Common Issues

```yaml
troubleshooting:
  connection_errors:
    symptom: "Failed to connect to BrightData proxy"
    causes:
      - Invalid credentials
      - IP not whitelisted
      - Proxy zone misconfigured
    solutions:
      - Verify customer_id and password
      - Add server IP to BrightData whitelist
      - Check proxy zone exists and is active

  rate_limiting:
    symptom: "429 Too Many Requests errors"
    causes:
      - Exceeded BrightData plan limits
      - Too many concurrent connections
      - Insufficient proxy rotation
    solutions:
      - Upgrade BrightData plan
      - Implement request queuing
      - Increase rotation frequency

  data_quality:
    symptom: "Incomplete or incorrect data returned"
    causes:
      - Target site blocking
      - JavaScript rendering required
      - Captcha challenges
    solutions:
      - Use Web Unlocker for difficult sites
      - Enable browser-based scraping
      - Implement captcha solving service

  performance_issues:
    symptom: "Slow response times"
    causes:
      - Network latency
      - Proxy location mismatch
      - Large data volumes
    solutions:
      - Use geographically closer proxies
      - Implement caching layer
      - Paginate large requests
```

## Appendices

### A. BrightData API Reference
### B. MCP Protocol Specification
### C. Security Tool Mappings
### D. Compliance Requirements
### E. Cost Optimization Strategies
### F. Emergency Response Procedures