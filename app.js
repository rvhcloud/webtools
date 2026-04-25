// ============================================
// DNS & Domain Lookup Tool - Application Logic
// ============================================

// State Management
const state = {
  currentDomain: '',
  currentTest: null,
  results: {},
  ipMetadataCache: {},
  activeTab: null,
  theme: localStorage.getItem('theme') || 'dark',
  history: JSON.parse(localStorage.getItem('searchHistory') || '[]')
};

const SHAREABLE_ACTION_TYPES = new Set([
  'A',
  'AAAA',
  'MX',
  'CNAME',
  'NS',
  'SOA',
  'TXT',
  'SPF',
  'DMARC',
  'PTR',
  'WHOIS',
  'IP_WHOIS',
  'ALL_RECORDS',
  'PROPAGATION',
  'REVERSE',
  'SSL_CHECK'
]);

// DNS Providers for multi-location checking
const DNS_PROVIDERS = {
  google: {
    name: 'Google DNS',
    endpoint: 'https://dns.google/resolve',
    location: 'Global (USA)'
  },
  cloudflare: {
    name: 'Cloudflare DNS',
    endpoint: 'https://cloudflare-dns.com/dns-query',
    location: 'Global (Multi-CDN)'
  },
  quad9: {
    name: 'Quad9 DNS',
    endpoint: 'https://dns.quad9.net/dns-query',
    location: 'Global (Switzerland)'
  },
  adguard: {
    name: 'AdGuard DNS',
    endpoint: 'https://dns.adguard-dns.com/dns-query',
    location: 'Global (Cyprus)'
  }
};

const PROPAGATION_PROVIDERS = [
  { id: 'google', name: 'Google DNS', endpoint: 'https://dns.google/resolve', location: 'Global Resolver' },
  { id: 'cloudflare', name: 'Cloudflare DNS', endpoint: 'https://cloudflare-dns.com/dns-query', location: 'Global Resolver' },
  { id: 'quad9', name: 'Quad9 DNS', endpoint: 'https://dns.quad9.net/dns-query', location: 'Global Resolver' },
  { id: 'adguard', name: 'AdGuard DNS', endpoint: 'https://dns.adguard-dns.com/dns-query', location: 'Global Resolver' },
  {
    id: 'google-us-east',
    name: 'Google DNS',
    endpoint: 'https://dns.google/resolve',
    location: 'Regional View (US East)',
    params: { edns_client_subnet: '8.8.8.0/24' }
  },
  {
    id: 'google-europe',
    name: 'Google DNS',
    endpoint: 'https://dns.google/resolve',
    location: 'Regional View (Europe)',
    params: { edns_client_subnet: '2.16.0.0/13' }
  },
  {
    id: 'google-india',
    name: 'Google DNS',
    endpoint: 'https://dns.google/resolve',
    location: 'Regional View (India)',
    params: { edns_client_subnet: '49.32.0.0/11' }
  },
  {
    id: 'google-singapore',
    name: 'Google DNS',
    endpoint: 'https://dns.google/resolve',
    location: 'Regional View (Singapore)',
    params: { edns_client_subnet: '43.255.140.0/22' }
  },
  {
    id: 'google-australia',
    name: 'Google DNS',
    endpoint: 'https://dns.google/resolve',
    location: 'Regional View (Australia)',
    params: { edns_client_subnet: '1.128.0.0/11' }
  }
];

// ============================================
// Initialization
// ============================================

document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initEventListeners();
  loadHistory();
  focusDomainInput();
  initializeSharedReportFromUrl();
});

function initTheme() {
  document.documentElement.setAttribute('data-theme', state.theme);
  updateThemeIcon();
}

function updateThemeIcon() {
  const sunIcon = document.getElementById('sunIcon');
  const moonIcon = document.getElementById('moonIcon');

  if (state.theme === 'dark') {
    sunIcon.classList.add('hidden');
    moonIcon.classList.remove('hidden');
  } else {
    sunIcon.classList.remove('hidden');
    moonIcon.classList.add('hidden');
  }
}

function initEventListeners() {
  const domainInput = document.getElementById('domainInput');

  // Theme toggle
  document.getElementById('themeToggle').addEventListener('click', toggleTheme);

  // Action buttons
  document.querySelectorAll('.action-btn').forEach(btn => {
    btn.addEventListener('click', handleAction);
  });

  // Domain input - Enter key
  domainInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
      const firstBtn = document.querySelector('.action-btn');
      if (firstBtn) firstBtn.click();
    }
  });

  domainInput.addEventListener('blur', () => {
    domainInput.value = normalizeDomainInput(domainInput.value);
  });

  // Export and Clear buttons
  document.getElementById('exportBtn').addEventListener('click', exportResults);
  document.getElementById('clearBtn').addEventListener('click', clearResults);
}

function focusDomainInput() {
  const domainInput = document.getElementById('domainInput');

  if (domainInput) {
    domainInput.focus();
  }
}

function setActiveActionButton(type = null) {
  document.querySelectorAll('.action-btn').forEach(btn => {
    btn.classList.toggle('is-active', btn.dataset.type === type);
  });
}

// ============================================
// Theme Management
// ============================================

function toggleTheme() {
  state.theme = state.theme === 'light' ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', state.theme);
  localStorage.setItem('theme', state.theme);
  updateThemeIcon();
}

// ============================================
// Action Handler
// ============================================

async function handleAction(e) {
  const btn = e.currentTarget;
  const type = btn.dataset.type;
  const domainInput = document.getElementById('domainInput');
  const domain = normalizeDomainInput(domainInput.value);

  domainInput.value = domain;

  if (!domain) {
    showError('Please enter a domain name or IP address');
    return;
  }

  // Validate input
  if (!isValidDomain(domain) && !isValidIP(domain)) {
    showError('Please enter a valid domain name or IP address');
    return;
  }

  if (type === 'SSL_CHECK') {
    state.currentDomain = domain;
    state.currentTest = type;
    updateSharableUrl(domain, type);
    const url = `https://www.sslshopper.com/ssl-checker.html#hostname=${encodeURIComponent(domain)}`;
    window.open(url, '_blank', 'noopener,noreferrer');
    return;
  }

  // Clear previous results if domain has changed
  if (state.currentDomain && state.currentDomain !== domain) {
    state.results = {};
    state.activeTab = null;
  }

  state.currentDomain = domain;
  state.currentTest = type;
  updateSharableUrl(domain, type);
  setActiveActionButton(type);

  // Add loading state to button
  btn.classList.add('loading');
  btn.disabled = true;

  try {
    showLoading(type);

    switch (type) {
      case 'A':
      case 'AAAA':
      case 'MX':
      case 'CNAME':
      case 'NS':
      case 'SOA':
      case 'TXT':
        await lookupDNS(domain, type);
        break;
      case 'SPF':
        await lookupSPF(domain);
        break;
      case 'DMARC':
        await lookupDMARC(domain);
        break;
      case 'PTR':
        // PTR can work with both IPs and domains
        await reverseDNS(domain);
        break;
      case 'WHOIS':
        await lookupWhois(domain);
        break;
      case 'IP_WHOIS':
        await lookupIPWhois(domain);
        break;
      case 'ALL_RECORDS':
        await lookupAllRecords(domain);
        break;
      case 'PROPAGATION':
        await checkPropagation(domain);
        break;
      case 'REVERSE':
        await reverseDNS(domain);
        break;
    }

    addToHistory(domain, type);
    saveHistory();

  } catch (error) {
    showError(`Error: ${error.message}`);
  } finally {
    btn.classList.remove('loading');
    btn.disabled = false;
  }
}

// ============================================
// DNS Lookup Functions
// ============================================

async function lookupDNS(domain, type, provider = 'google') {
  const providerInfo = typeof provider === 'string' ? { id: provider, ...DNS_PROVIDERS[provider] } : provider;

  const data = await fetchDNSResult(domain, type, providerInfo);

  if (!state.results[type]) {
    state.results[type] = {};
  }

  state.results[type][providerInfo.id || provider] = {
    provider: providerInfo.name,
    location: providerInfo.location,
    data: data,
    timestamp: new Date().toISOString()
  };

  displayResults(type);
}

async function fetchDNSResult(domain, type, provider = 'google') {
  const providerInfo = typeof provider === 'string' ? { id: provider, ...DNS_PROVIDERS[provider] } : provider;

  if (!providerInfo?.endpoint) {
    throw new Error(`Unknown DNS provider: ${provider}`);
  }

  const params = new URLSearchParams({
    name: domain,
    type
  });

  Object.entries(providerInfo.params || {}).forEach(([key, value]) => {
    if (value) {
      params.set(key, value);
    }
  });

  const url = `${providerInfo.endpoint}?${params.toString()}`;

  const headers = providerInfo.id === 'cloudflare'
    ? { 'Accept': 'application/dns-json' }
    : {};

  try {
    const response = await fetch(url, { headers });

    if (!response.ok) {
      throw new Error(`DNS lookup failed: ${response.statusText}`);
    }

    return await response.json();
  } catch (error) {
    throw new Error(`Failed to lookup ${type} record: ${error.message}`);
  }
}

async function lookupAllRecords(domain) {
  const types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME'];
  const promises = types.map(type =>
    lookupDNS(domain, type).catch(err => {
      console.error(`Failed to lookup ${type}:`, err);
      return null;
    })
  );

  await Promise.all(promises);

  // Display the first available result
  const firstType = types.find(type => state.results[type]);
  if (firstType) {
    displayResults(firstType);
  }
}

async function checkPropagation(domain) {
  showLoading('PROPAGATION');
  state.results['PROPAGATION'] = {};

  for (const provider of PROPAGATION_PROVIDERS) {
    try {
      document.getElementById('loadingMessage').textContent = `Checking ${provider.name} - ${provider.location}...`;
      const data = await fetchDNSResult(domain, 'A', provider);
      state.results['PROPAGATION'][provider.id] = {
        provider: provider.name,
        location: provider.location,
        data,
        timestamp: new Date().toISOString()
      };
      // Small delay to avoid rate limiting
      await new Promise(resolve => setTimeout(resolve, 200));
    } catch (err) {
      console.error(`Failed ${provider}:`, err);
      state.results['PROPAGATION'][provider.id] = {
        provider: provider.name,
        location: provider.location,
        data: { Answer: [] },
        error: err.message,
        timestamp: new Date().toISOString()
      };
    }
  }

  displayResults('PROPAGATION');
}

async function lookupSPF(domain) {
  const txtData = await fetchDNSResult(domain, 'TXT');
  const spfRecords = (txtData.Answer || [])
    .map(answer => cleanTxtValue(answer.data))
    .filter(value => value.toLowerCase().startsWith('v=spf1'));
  const primaryRecord = spfRecords[0] || '';

  state.results['SPF'] = {
    google: {
      provider: 'Google DNS',
      location: 'Global (USA)',
      data: {
        domain,
        record: primaryRecord,
        records: spfRecords,
        analysis: analyzeSpfRecord(primaryRecord, spfRecords.length)
      },
      timestamp: new Date().toISOString()
    }
  };

  displayResults('SPF');
}

async function lookupDMARC(domain) {
  const dmarcHost = `_dmarc.${domain}`;
  const txtData = await fetchDNSResult(dmarcHost, 'TXT');
  const dmarcRecords = (txtData.Answer || [])
    .map(answer => cleanTxtValue(answer.data))
    .filter(value => value.toLowerCase().startsWith('v=dmarc1'));
  const primaryRecord = dmarcRecords[0] || '';

  state.results['DMARC'] = {
    google: {
      provider: 'Google DNS',
      location: 'Global (USA)',
      data: {
        domain,
        hostname: dmarcHost,
        record: primaryRecord,
        records: dmarcRecords,
        analysis: analyzeDmarcRecord(primaryRecord, dmarcRecords.length)
      },
      timestamp: new Date().toISOString()
    }
  };

  displayResults('DMARC');
}

async function reverseDNS(domain) {
  let ip = domain;

  // If domain name is provided instead of IP, resolve it first
  if (!isValidIP(domain)) {
    document.getElementById('loadingMessage').textContent = 'Resolving domain to IP first...';

    try {
      // Look up A record first
      await lookupDNS(domain, 'A');
      const data = state.results['A']?.google?.data;

      if (data?.Answer?.[0]?.data) {
        ip = data.Answer[0].data;
        document.getElementById('loadingMessage').textContent = `Got IP ${ip}, performing reverse DNS...`;
      } else {
        throw new Error('Could not resolve domain to IP address');
      }
    } catch (error) {
      throw new Error(`Failed to resolve domain: ${error.message}`);
    }
  }

  // Convert IP to reverse DNS format (e.g., 8.8.8.8 -> 8.8.8.8.in-addr.arpa)
  const reverseLookupName = getReverseLookupName(ip);

  try {
    await lookupDNS(reverseLookupName, 'PTR');
  } catch (error) {
    // If PTR fails, still show the result
    if (!state.results['PTR']) {
      state.results['PTR'] = {};
    }
    state.results['PTR']['google'] = {
      provider: 'Google DNS',
      location: 'Global (USA)',
      data: { Answer: [] },
      timestamp: new Date().toISOString(),
      error: error.message
    };
    displayResults('PTR');
  }
}

// ============================================
// WHOIS Lookup Functions
// ============================================

async function lookupWhois(domain) {
  try {
    // Clean domain - remove protocol and www if present
    const cleanDomain = domain.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0];

    // Try using RDAP (Registration Data Access Protocol) - more modern than WHOIS
    // First, we'll try a simple approach using a WHOIS lookup service
    const response = await fetch(`https://rdap.org/domain/${encodeURIComponent(cleanDomain)}`);

    if (response.ok) {
      const data = await response.json();

      // Parse RDAP response
      const whoisInfo = {
        domain: cleanDomain,
        status: data.status || [],
        created: data.events?.find(e => e.eventAction === 'registration')?.eventDate || 'N/A',
        updated: data.events?.find(e => e.eventAction === 'last changed')?.eventDate || 'N/A',
        expires: data.events?.find(e => e.eventAction === 'expiration')?.eventDate || 'N/A',
        registrar: data.entities?.find(e => e.roles?.includes('registrar'))?.vcardArray?.[1]?.find(v => v[0] === 'fn')?.[3] || 'N/A',
        nameservers: data.nameservers?.map(ns => ns.ldhName).join(', ') || 'N/A'
      };

      state.results['WHOIS'] = {
        google: {
          provider: 'RDAP Service',
          data: whoisInfo,
          rawData: data,
          timestamp: new Date().toISOString()
        }
      };
      displayResults('WHOIS');
    } else {
      throw new Error('RDAP lookup failed');
    }
  } catch (error) {
    console.error('WHOIS lookup error:', error);
    // If WHOIS API fails, show DNS-based info
    await showBasicDomainInfo(domain);
  }
}

async function lookupIPWhois(domain) {
  let ip = domain;

  // If domain name provided, resolve to IP first
  if (!isValidIP(domain)) {
    const aRecord = await lookupDNS(domain, 'A');
    const data = state.results['A']?.google?.data;
    if (data?.Answer?.[0]?.data) {
      ip = data.Answer[0].data;
    } else {
      throw new Error('Could not resolve domain to IP');
    }
  }

  try {
    const data = await fetchIPWhoisData(ip);

    state.results['IP_WHOIS'] = {
      rdap: {
        provider: data.provider,
        data: data,
        timestamp: new Date().toISOString()
      }
    };
    displayResults('IP_WHOIS');
  } catch (error) {
    throw new Error(`IP WHOIS error: ${error.message}`);
  }
}

async function checkSSL(domain) {
  showLoading('SSL_CHECK');

  try {
    const response = await fetch('/api/ssl-check', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ domain })
    });

    if (response.status === 404) {
      throw new Error('Please run "python server.py" to enable local SSL checks.');
    }

    const data = await response.json();

    if (!data.success) {
      throw new Error(data.error || 'SSL check failed');
    }

    state.results['SSL_CHECK'] = {
      local: {
        provider: 'Local Python Server',
        data: data,
        timestamp: new Date().toISOString()
      }
    };

    displayResults('SSL_CHECK');

  } catch (error) {
    if (error.message.includes('python server.py')) {
      showError(error.message);
    } else {
      throw new Error(`SSL Check failed: ${error.message}`);
    }
  }
}

async function showBasicDomainInfo(domain) {
  // Fallback: Get basic info from DNS records
  await lookupAllRecords(domain);

  state.results['WHOIS'] = {
    google: {
      provider: 'Basic Domain Info (DNS-based)',
      data: {
        domain: domain,
        note: 'WHOIS API unavailable. Showing DNS-based information.',
        records: state.results
      },
      timestamp: new Date().toISOString()
    }
  };
  displayResults('WHOIS');
}

// ============================================
// Display Functions
// ============================================

function showLoading(type) {
  document.getElementById('emptyState').classList.add('hidden');
  document.getElementById('loadingState').classList.remove('hidden');
  document.getElementById('resultsContent').classList.remove('active');

  const messages = {
    'A': 'Looking up A records...',
    'AAAA': 'Looking up IPv6 addresses...',
    'MX': 'Checking mail servers...',
    'CNAME': 'Checking canonical names...',
    'NS': 'Looking up nameservers...',
    'SOA': 'Checking zone authority...',
    'TXT': 'Fetching TXT records...',
    'SPF': 'Validating SPF record...',
    'DMARC': 'Validating DMARC policy...',
    'PTR': 'Performing reverse DNS lookup...',
    'WHOIS': 'Fetching WHOIS information...',
    'IP_WHOIS': 'Looking up IP information...',
    'ALL_RECORDS': 'Fetching all DNS records...',
    'PROPAGATION': 'Checking DNS propagation across multiple locations...',
    'REVERSE': 'Performing reverse DNS lookup...',
    'SSL_CHECK': 'Analyzing SSL certificate...'
  };

  document.getElementById('loadingMessage').textContent = messages[type] || 'Processing...';
}

function displayResults(type) {
  document.getElementById('loadingState').classList.add('hidden');
  document.getElementById('emptyState').classList.add('hidden');
  document.getElementById('resultsContent').classList.add('active');

  document.getElementById('exportBtn').style.display = 'block';
  document.getElementById('clearBtn').style.display = 'block';

  createTabs();
  switchTab(type);
}

function createTabs() {
  const tabsContainer = document.getElementById('resultTabs');
  tabsContainer.style.display = 'flex';
  tabsContainer.innerHTML = '';

  const types = Object.keys(state.results);

  types.forEach(type => {
    const tab = document.createElement('button');
    tab.className = 'tab';
    tab.textContent = formatTabName(type);
    tab.dataset.type = type;
    tab.addEventListener('click', () => switchTab(type));
    tabsContainer.appendChild(tab);
  });
}

function switchTab(type) {
  state.activeTab = type;

  // Update active tab
  document.querySelectorAll('.tab').forEach(tab => {
    tab.classList.toggle('active', tab.dataset.type === type);
  });

  // Render content
  renderResultContent(type);
}

async function renderResultContent(type) {
  const container = document.getElementById('resultsContent');
  container.innerHTML = '';

  const results = state.results[type];

  if (!results) {
    container.innerHTML = '<p class="text-center">No results available</p>';
    return;
  }

  // Render based on type
  switch (type) {
    case 'A':
    case 'AAAA':
      await renderIPRecords(container, results, type);
      break;
    case 'MX':
      await renderMXRecords(container, results);
      break;
    case 'NS':
      await renderNSRecords(container, results);
      break;
    case 'CNAME':
      renderCNAMERecords(container, results);
      break;
    case 'TXT':
      renderTXTRecords(container, results);
      break;
    case 'SPF':
      renderSPFResults(container, results);
      break;
    case 'DMARC':
      renderDMARCResults(container, results);
      break;
    case 'SOA':
      renderSOARecords(container, results);
      break;
    case 'PTR':
      renderPTRRecords(container, results);
      break;
    case 'WHOIS':
      renderWhoisInfo(container, results);
      break;
    case 'IP_WHOIS':
      renderIPWhoisInfo(container, results);
      break;
    case 'SSL_CHECK':
      renderSSLInfo(container, results);
      break;
    case 'PROPAGATION':
      renderPropagationResults(container, results);
      break;
    default:
      renderGenericRecords(container, results, type);
  }
}

async function renderIPRecords(container, results, type) {
  for (const result of Object.values(results)) {
    const card = createResultCard(result.provider, result.location);

    if (result.data.Answer && result.data.Answer.length > 0) {
      for (let index = 0; index < result.data.Answer.length; index++) {
        const answer = result.data.Answer[index];
        const ipAddress = answer.data;

        addResultItem(card, `IP Address ${index + 1}`, ipAddress);

        // Fetch country information for the IP
        try {
          const ipData = await fetchIPWhoisData(ipAddress);
          if (ipData.country) {
            addResultItem(card, 'Country', ipData.country);
          }
          if (ipData.org) {
            addResultItem(card, 'Owner', ipData.org);
          }
        } catch (err) {
          console.error(`Failed to get location for ${ipAddress}:`, err);
        }

        if (answer.TTL) {
          addResultItem(card, 'TTL', `${answer.TTL} seconds`);
        }

        if (index < result.data.Answer.length - 1) {
          const hr = document.createElement('hr');
          hr.style.margin = 'var(--space-md) 0';
          hr.style.border = 'none';
          hr.style.borderTop = '1px solid var(--border-color)';
          card.appendChild(hr);
        }
      }
    } else {
      addResultItem(card, 'Status', 'No records found');
    }

    addResultItem(card, 'Query Time', formatTime(result.timestamp));
    container.appendChild(card);
  }
}

async function renderMXRecords(container, results) {
  for (const result of Object.values(results)) {
    const card = createResultCard(result.provider, result.location);

    if (result.data.Answer && result.data.Answer.length > 0) {
      const sortedAnswers = result.data.Answer.sort((a, b) => {
        const priorityA = parseInt(a.data.split(' ')[0]) || 0;
        const priorityB = parseInt(b.data.split(' ')[0]) || 0;
        return priorityA - priorityB;
      });

      for (let index = 0; index < sortedAnswers.length; index++) {
        const answer = sortedAnswers[index];
        const parts = answer.data.split(' ');
        const priority = parts[0];
        const server = parts.slice(1).join(' ').replace(/\.$/, ''); // Remove trailing dot

        addResultItem(card, `Mail Server ${index + 1}`, server);
        addResultItem(card, 'Priority', priority);

        // Resolve IP address for the mail server
        try {
          const ipResponse = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(server)}&type=A`);
          if (ipResponse.ok) {
            const ipData = await ipResponse.json();
            if (ipData.Answer && ipData.Answer.length > 0) {
              const ips = ipData.Answer.map(a => a.data).join(', ');
              addResultItem(card, 'IP Address', ips);
            }
          }
        } catch (err) {
          console.error(`Failed to resolve IP for ${server}:`, err);
        }

        if (answer.TTL) {
          addResultItem(card, 'TTL', `${answer.TTL} seconds`);
        }

        if (index < sortedAnswers.length - 1) {
          const hr = document.createElement('hr');
          hr.style.margin = 'var(--space-md) 0';
          hr.style.border = 'none';
          hr.style.borderTop = '1px solid var(--border-color)';
          card.appendChild(hr);
        }
      }
    } else {
      addResultItem(card, 'Status', 'No MX records found');
    }

    container.appendChild(card);
  }
}

async function renderNSRecords(container, results) {
  for (const result of Object.values(results)) {
    const card = createResultCard(result.provider, result.location);

    if (result.data.Answer && result.data.Answer.length > 0) {
      for (let index = 0; index < result.data.Answer.length; index++) {
        const answer = result.data.Answer[index];
        const server = answer.data.replace(/\.$/, ''); // Remove trailing dot

        addResultItem(card, `Nameserver ${index + 1}`, server);

        // Resolve IP address for the nameserver
        try {
          const ipResponse = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(server)}&type=A`);
          if (ipResponse.ok) {
            const ipData = await ipResponse.json();
            if (ipData.Answer && ipData.Answer.length > 0) {
              const ips = ipData.Answer.map(a => a.data).join(', ');
              addResultItem(card, 'IP Address', ips);
            }
          }
        } catch (err) {
          console.error(`Failed to resolve IP for ${server}:`, err);
        }

        if (index < result.data.Answer.length - 1) {
          const hr = document.createElement('hr');
          hr.style.margin = 'var(--space-md) 0';
          hr.style.border = 'none';
          hr.style.borderTop = '1px solid var(--border-color)';
          card.appendChild(hr);
        }
      }
    } else {
      addResultItem(card, 'Status', 'No NS records found');
    }

    container.appendChild(card);
  }
}

function renderCNAMERecords(container, results) {
  Object.values(results).forEach(result => {
    const card = createResultCard(result.provider, result.location);

    if (result.data.Answer && result.data.Answer.length > 0) {
      result.data.Answer.forEach((answer, index) => {
        addResultItem(card, 'Canonical Name', answer.data);
        if (answer.TTL) {
          addResultItem(card, 'TTL', `${answer.TTL} seconds`);
        }
      });
    } else {
      addResultItem(card, 'Status', 'No CNAME records found');
    }

    container.appendChild(card);
  });
}

function renderTXTRecords(container, results) {
  Object.values(results).forEach(result => {
    const card = createResultCard(result.provider, result.location);

    if (result.data.Answer && result.data.Answer.length > 0) {
      result.data.Answer.forEach((answer, index) => {
        const txtValue = answer.data.replace(/^"|"$/g, '');
        addResultItem(card, `TXT Record ${index + 1}`, txtValue);

        // Detect common TXT record types
        if (txtValue.startsWith('v=spf')) {
          addResultItem(card, 'Type', 'SPF Record');
        } else if (txtValue.includes('v=DKIM')) {
          addResultItem(card, 'Type', 'DKIM Record');
        } else if (txtValue.startsWith('v=DMARC')) {
          addResultItem(card, 'Type', 'DMARC Record');
        }

        if (index < result.data.Answer.length - 1) {
          card.appendChild(document.createElement('hr'));
        }
      });
    } else {
      addResultItem(card, 'Status', 'No TXT records found');
    }

    container.appendChild(card);
  });
}

function renderSOARecords(container, results) {
  Object.values(results).forEach(result => {
    const card = createResultCard(result.provider, result.location);

    if (result.data.Answer && result.data.Answer.length > 0) {
      const soa = result.data.Answer[0].data.split(' ');

      addResultItem(card, 'Primary NS', soa[0] || 'N/A');
      addResultItem(card, 'Admin Email', (soa[1] || 'N/A').replace('.', '@', 1));
      addResultItem(card, 'Serial', soa[2] || 'N/A');
      addResultItem(card, 'Refresh', `${soa[3] || 'N/A'} seconds`);
      addResultItem(card, 'Retry', `${soa[4] || 'N/A'} seconds`);
      addResultItem(card, 'Expire', `${soa[5] || 'N/A'} seconds`);
      addResultItem(card, 'Minimum TTL', `${soa[6] || 'N/A'} seconds`);
    } else {
      addResultItem(card, 'Status', 'No SOA records found');
    }

    container.appendChild(card);
  });
}

function renderPTRRecords(container, results) {
  Object.values(results).forEach(result => {
    const card = createResultCard(result.provider, result.location);

    if (result.data.Answer && result.data.Answer.length > 0) {
      result.data.Answer.forEach((answer, index) => {
        addResultItem(card, `Hostname ${index + 1}`, answer.data.replace(/\.$/, ''));
      });
    } else {
      addResultItem(card, 'Status', 'No PTR records found');
    }

    container.appendChild(card);
  });
}

function renderPropagationResults(container, results) {
  Object.values(results).forEach(result => {
    const card = createResultCard(result.provider, result.location);
    const answers = result.data?.Answer || [];

    if (answers.length > 0) {
      const uniqueIps = [...new Set(answers.map(answer => answer.data))];
      addResultItem(card, 'Resolved IPs', uniqueIps.join(', '));
      addResultItem(card, 'Answer Count', String(answers.length));

      const ttlValues = answers.map(answer => answer.TTL).filter(Boolean);
      if (ttlValues.length > 0) {
        addResultItem(card, 'TTL', `${Math.min(...ttlValues)}-${Math.max(...ttlValues)} seconds`);
      }
    } else if (result.error) {
      addResultItem(card, 'Status', 'Lookup failed');
      addResultItem(card, 'Error', result.error);
    } else {
      addResultItem(card, 'Status', 'No A records returned');
    }

    addResultItem(card, 'Checked At', formatTime(result.timestamp));
    container.appendChild(card);
  });
}

function renderWhoisInfo(container, results) {
  Object.values(results).forEach(result => {
    const card = createResultCard(result.provider);

    if (result.data.note) {
      const note = document.createElement('p');
      note.style.color = 'var(--text-secondary)';
      note.style.marginBottom = 'var(--space-md)';
      note.textContent = result.data.note;
      card.appendChild(note);
    }

    // Display available WHOIS data
    const whoisData = result.data;

    if (whoisData.domain) addResultItem(card, 'Domain', whoisData.domain);
    if (whoisData.registrar && whoisData.registrar !== 'N/A') addResultItem(card, 'Registrar', whoisData.registrar);

    // Created date with age calculation
    if (whoisData.created && whoisData.created !== 'N/A') {
      const createdDate = new Date(whoisData.created);
      const now = new Date();
      const ageInDays = Math.floor((now - createdDate) / (1000 * 60 * 60 * 24));
      const ageInYears = Math.floor(ageInDays / 365);
      const remainingDays = ageInDays % 365;

      let ageText = '';
      if (ageInYears > 0) {
        ageText = `${ageInYears} year${ageInYears > 1 ? 's' : ''}`;
        if (remainingDays > 0) {
          ageText += `, ${remainingDays} day${remainingDays > 1 ? 's' : ''}`;
        }
      } else {
        ageText = `${ageInDays} day${ageInDays > 1 ? 's' : ''}`;
      }

      addResultItem(card, 'Created', createdDate.toLocaleString());
      addResultItem(card, 'Domain Age', ageText);
    }

    if (whoisData.updated && whoisData.updated !== 'N/A') {
      addResultItem(card, 'Updated', new Date(whoisData.updated).toLocaleString());
    }

    // Expiration date with days remaining and warning
    if (whoisData.expires && whoisData.expires !== 'N/A') {
      const expiresDate = new Date(whoisData.expires);
      const now = new Date();
      const daysUntilExpiry = Math.floor((expiresDate - now) / (1000 * 60 * 60 * 24));

      addResultItem(card, 'Expires', expiresDate.toLocaleString());

      // Create expiration warning item
      const expiryItem = document.createElement('div');
      expiryItem.className = 'result-item';

      const expiryLabel = document.createElement('div');
      expiryLabel.className = 'result-label';
      expiryLabel.textContent = 'Days Until Expiry';

      const expiryValue = document.createElement('div');
      expiryValue.className = 'result-value';

      let expiryText = '';
      let shouldHighlight = false;

      if (daysUntilExpiry < 0) {
        expiryText = `Expired ${Math.abs(daysUntilExpiry)} days ago`;
        shouldHighlight = true;
      } else if (daysUntilExpiry === 0) {
        expiryText = 'Expires today!';
        shouldHighlight = true;
      } else if (daysUntilExpiry <= 15) {
        expiryText = `${daysUntilExpiry} day${daysUntilExpiry > 1 ? 's' : ''} (âš ï¸ EXPIRING SOON!)`;
        shouldHighlight = true;
      } else if (daysUntilExpiry <= 30) {
        expiryText = `${daysUntilExpiry} days`;
        expiryValue.style.color = 'var(--accent-orange)';
      } else {
        const yearsUntilExpiry = Math.floor(daysUntilExpiry / 365);
        const remainingDays = daysUntilExpiry % 365;
        if (yearsUntilExpiry > 0) {
          expiryText = `${yearsUntilExpiry} year${yearsUntilExpiry > 1 ? 's' : ''}, ${remainingDays} day${remainingDays > 1 ? 's' : ''}`;
        } else {
          expiryText = `${daysUntilExpiry} days`;
        }
      }

      expiryValue.textContent = expiryText;

      // Highlight critical expirations
      if (shouldHighlight) {
        expiryValue.style.color = 'hsl(0, 85%, 60%)';
        expiryValue.style.fontWeight = '700';
        expiryItem.style.background = 'hsla(0, 85%, 60%, 0.1)';
        expiryItem.style.padding = 'var(--space-sm)';
        expiryItem.style.borderRadius = 'var(--radius-sm)';
        expiryItem.style.border = '1px solid hsla(0, 85%, 60%, 0.3)';
      }

      const copyBtn = document.createElement('button');
      copyBtn.className = 'copy-btn';
      copyBtn.textContent = 'Copy';
      copyBtn.addEventListener('click', () => copyToClipboard(`${daysUntilExpiry} days`, copyBtn));

      expiryItem.appendChild(expiryLabel);
      expiryItem.appendChild(expiryValue);
      expiryItem.appendChild(copyBtn);
      card.appendChild(expiryItem);
    }

    if (whoisData.status && whoisData.status.length > 0) {
      addResultItem(card, 'Status', Array.isArray(whoisData.status) ? whoisData.status.join(', ') : whoisData.status);
    }
    if (whoisData.nameservers && whoisData.nameservers !== 'N/A') {
      addResultItem(card, 'Nameservers', whoisData.nameservers);
    }

    // If we have DNS records as fallback
    if (whoisData.records) {
      const info = document.createElement('p');
      info.style.marginTop = 'var(--space-md)';
      info.innerHTML = '<strong>Available DNS Information:</strong>';
      card.appendChild(info);

      Object.keys(whoisData.records).forEach(recordType => {
        addResultItem(card, recordType + ' Records', 'Available (see tabs above)');
      });
    }

    container.appendChild(card);
  });
}



function renderIPWhoisInfo(container, results) {
  Object.values(results).forEach(result => {
    const card = createResultCard(result.provider);
    const data = result.data;

    if (data.query) addResultItem(card, 'IP Address', data.query);
    if (data.networkName) addResultItem(card, 'Network', data.networkName);
    if (data.handle) addResultItem(card, 'Handle', data.handle);
    if (data.cidr) addResultItem(card, 'CIDR', data.cidr);
    if (data.startAddress && data.endAddress) addResultItem(card, 'IP Range', `${data.startAddress} - ${data.endAddress}`);
    if (data.country) addResultItem(card, 'Country', data.country);
    if (data.type) addResultItem(card, 'Allocation Type', data.type);
    if (data.org) addResultItem(card, 'Organization', data.org);
    if (data.abuseEmail) addResultItem(card, 'Abuse Contact', data.abuseEmail);
    if (data.status) addResultItem(card, 'Status', data.status);
    if (data.created) addResultItem(card, 'Registered', new Date(data.created).toLocaleString());
    if (data.updated) addResultItem(card, 'Updated', new Date(data.updated).toLocaleString());
    if (data.port43) addResultItem(card, 'WHOIS Server', data.port43);

    container.appendChild(card);
  });
}

function renderSPFResults(container, results) {
  Object.values(results).forEach(result => {
    const card = createResultCard(result.provider, result.location);
    const data = result.data;

    addResultItem(card, 'Domain', data.domain);

    if (data.record) {
      addResultItem(card, 'SPF Record', data.record);
      addResultItem(card, 'Status', data.analysis.status);
      addResultItem(card, 'Mode', data.analysis.mode);
      addResultItem(card, 'DNS Lookups', String(data.analysis.lookupCount));
      addResultItem(card, 'Includes', data.analysis.includes || 'None');
      addResultItem(card, 'Warnings', data.analysis.warnings.join(' | ') || 'None');
    } else {
      addResultItem(card, 'Status', 'No SPF record found');
      addResultItem(card, 'Warnings', data.analysis.warnings.join(' | ') || 'None');
    }

    container.appendChild(card);
  });
}

function renderDMARCResults(container, results) {
  Object.values(results).forEach(result => {
    const card = createResultCard(result.provider, result.location);
    const data = result.data;

    addResultItem(card, 'Domain', data.domain);
    addResultItem(card, 'DMARC Host', data.hostname);

    if (data.record) {
      addResultItem(card, 'DMARC Record', data.record);
      addResultItem(card, 'Policy', data.analysis.policy);
      addResultItem(card, 'Subdomain Policy', data.analysis.subdomainPolicy);
      addResultItem(card, 'Percentage', data.analysis.percentage);
      addResultItem(card, 'Alignment', data.analysis.alignment);
      addResultItem(card, 'Aggregate Reports', data.analysis.rua || 'Not set');
      addResultItem(card, 'Forensic Reports', data.analysis.ruf || 'Not set');
      addResultItem(card, 'Warnings', data.analysis.warnings.join(' | ') || 'None');
    } else {
      addResultItem(card, 'Status', 'No DMARC record found');
      addResultItem(card, 'Warnings', data.analysis.warnings.join(' | ') || 'None');
    }

    container.appendChild(card);
  });
}

function renderSSLInfo(container, results) {
  Object.values(results).forEach(result => {
    const card = createResultCard(result.provider);
    const data = result.data;

    if (data.domain) addResultItem(card, 'Domain', data.domain);
    if (data.port) addResultItem(card, 'Port', String(data.port));
    if (data.subject_common_name) addResultItem(card, 'Common Name', data.subject_common_name);
    if (data.subject_organization) addResultItem(card, 'Subject Organization', data.subject_organization);
    if (data.issuer_common_name) addResultItem(card, 'Issuer', data.issuer_common_name);
    if (data.issuer_organization) addResultItem(card, 'Issuer Organization', data.issuer_organization);
    if (data.serial_number) addResultItem(card, 'Serial Number', data.serial_number);
    if (data.signature_algorithm) addResultItem(card, 'Signature Algorithm', data.signature_algorithm);
    if (data.version) addResultItem(card, 'Certificate Version', data.version);
    if (data.not_before) addResultItem(card, 'Valid From', new Date(data.not_before).toLocaleString());
    if (data.not_after) addResultItem(card, 'Valid Until', new Date(data.not_after).toLocaleString());
    if (typeof data.days_remaining === 'number') {
      const daysLabel = data.days_remaining < 0
        ? `Expired ${Math.abs(data.days_remaining)} day${Math.abs(data.days_remaining) === 1 ? '' : 's'} ago`
        : `${data.days_remaining} day${data.days_remaining === 1 ? '' : 's'}`;
      addResultItem(card, 'Days Remaining', daysLabel);
    }
    if (data.is_valid_now !== undefined) {
      addResultItem(card, 'Current Status', data.is_valid_now ? 'Valid' : 'Not currently valid');
    }
    if (data.subject_alt_names && data.subject_alt_names.length > 0) {
      addResultItem(card, 'Subject Alt Names', data.subject_alt_names.join(', '));
    }
    if (data.resolved_ip) addResultItem(card, 'Resolved IP', data.resolved_ip);
    if (result.timestamp) addResultItem(card, 'Checked At', formatTime(result.timestamp));

    container.appendChild(card);
  });
}

function renderGenericRecords(container, results, type) {
  Object.values(results).forEach(result => {
    const card = createResultCard(result.provider, result.location);

    if (result.data.Answer && result.data.Answer.length > 0) {
      result.data.Answer.forEach((answer, index) => {
        addResultItem(card, `Record ${index + 1}`, answer.data);
        if (answer.TTL) {
          addResultItem(card, 'TTL', `${answer.TTL} seconds`);
        }
      });
    } else {
      addResultItem(card, 'Status', `No ${type} records found`);
    }

    container.appendChild(card);
  });
}

// ============================================
// UI Helper Functions
// ============================================

function createResultCard(title, subtitle = '') {
  const card = document.createElement('div');
  card.className = 'result-card';

  const header = document.createElement('h4');
  header.textContent = title;
  if (subtitle) {
    const sub = document.createElement('span');
    sub.style.fontSize = 'var(--font-size-sm)';
    sub.style.color = 'var(--text-tertiary)';
    sub.style.fontWeight = 'normal';
    sub.textContent = ` • ${subtitle}`;
    header.appendChild(sub);
  }

  card.appendChild(header);
  return card;
}

function addResultItem(card, label, value) {
  const item = document.createElement('div');
  item.className = 'result-item';

  const labelEl = document.createElement('div');
  labelEl.className = 'result-label';
  labelEl.textContent = label;

  const valueEl = document.createElement('div');
  valueEl.className = 'result-value';
  valueEl.textContent = value;

  const copyBtn = document.createElement('button');
  copyBtn.className = 'copy-btn';
  copyBtn.textContent = 'Copy';
  copyBtn.addEventListener('click', () => copyToClipboard(value, copyBtn));

  item.appendChild(labelEl);
  item.appendChild(valueEl);
  item.appendChild(copyBtn);

  card.appendChild(item);
}

function showError(message) {
  document.getElementById('loadingState').classList.add('hidden');
  document.getElementById('emptyState').classList.add('hidden');
  document.getElementById('resultsContent').classList.add('active');

  const container = document.getElementById('resultsContent');
  container.innerHTML = `
    <div class="error-state">
      <h4>âš ï¸ Error</h4>
      <p>${message}</p>
    </div>
  `;
}

// ============================================
// Utility Functions
// ============================================

function normalizeDomainInput(value) {
  if (!value) {
    return '';
  }

  let normalized = value.trim();
  normalized = normalized.replace(/^https?:\/\//i, '');
  normalized = normalized.replace(/^\/+|\/+$/g, '');
  normalized = normalized.replace(/\/.*$/, '');

  return normalized.trim();
}

function cleanTxtValue(value) {
  return String(value || '').replace(/^"|"$/g, '').replace(/"\s+"/g, '');
}

function analyzeSpfRecord(record, recordCount) {
  const warnings = [];

  if (!record) {
    warnings.push('No SPF TXT record found on the root domain');
    return {
      status: 'Missing',
      mode: 'N/A',
      lookupCount: 0,
      includes: '',
      warnings
    };
  }

  if (recordCount > 1) {
    warnings.push('Multiple SPF records found; receivers may treat this as invalid');
  }

  const tokens = record.split(/\s+/).filter(Boolean);
  const includes = tokens.filter(token => token.startsWith('include:')).map(token => token.slice(8));
  const redirect = tokens.find(token => token.startsWith('redirect='));
  const lookupCount = tokens.filter(token =>
    token.startsWith('include:') ||
    token === 'a' ||
    token.startsWith('a:') ||
    token === 'mx' ||
    token.startsWith('mx:') ||
    token.startsWith('ptr') ||
    token.startsWith('exists:') ||
    token.startsWith('redirect=')
  ).length;

  if (lookupCount > 10) {
    warnings.push('SPF exceeds the 10-DNS-lookup limit');
  }

  if (tokens.includes('+all')) {
    warnings.push('Uses +all, which effectively authorizes any sender');
  }

  const terminal = tokens[tokens.length - 1] || '';
  const mode = ['-all', '~all', '?all', '+all'].includes(terminal) ? terminal : 'No explicit all mechanism';

  if (mode === 'No explicit all mechanism') {
    warnings.push('SPF record does not end with an explicit all mechanism');
  }

  return {
    status: warnings.length === 0 ? 'Valid-looking' : 'Needs review',
    mode,
    lookupCount,
    includes: includes.join(', ') || (redirect ? redirect.replace('redirect=', 'redirect -> ') : ''),
    warnings
  };
}

function analyzeDmarcRecord(record, recordCount) {
  const warnings = [];

  if (!record) {
    warnings.push('No DMARC TXT record found at _dmarc');
    return {
      policy: 'Missing',
      subdomainPolicy: 'N/A',
      percentage: 'N/A',
      alignment: 'N/A',
      rua: '',
      ruf: '',
      warnings
    };
  }

  if (recordCount > 1) {
    warnings.push('Multiple DMARC records found; receivers may ignore DMARC');
  }

  const tags = Object.fromEntries(
    record.split(';')
      .map(part => part.trim())
      .filter(Boolean)
      .map(part => {
        const [key, ...rest] = part.split('=');
        return [key.trim().toLowerCase(), rest.join('=').trim()];
      })
  );

  if (!tags.p) {
    warnings.push('DMARC policy tag p= is missing');
  }

  if (!tags.rua) {
    warnings.push('Aggregate reporting address rua= is not configured');
  }

  if (tags.p === 'none') {
    warnings.push('Policy is monitor-only (p=none)');
  }

  return {
    policy: tags.p || 'Missing',
    subdomainPolicy: tags.sp || tags.p || 'Not set',
    percentage: tags.pct || '100',
    alignment: `DKIM ${tags.adkim || 'r'}, SPF ${tags.aspf || 'r'}`,
    rua: tags.rua || '',
    ruf: tags.ruf || '',
    warnings
  };
}

async function fetchIPWhoisData(ip) {
  if (state.ipMetadataCache[ip]) {
    return state.ipMetadataCache[ip];
  }

  const response = await fetch(`https://rdap.org/ip/${encodeURIComponent(ip)}`);

  if (!response.ok) {
    if (response.status === 429) {
      throw new Error('IP RDAP service rate limit reached');
    }

    throw new Error(`IP RDAP lookup failed: ${response.status}`);
  }

  const data = await response.json();
  const registrantEntity = findEntityByRole(data.entities, 'registrant') || data.entities?.[0];
  const abuseEntity = findEntityByRole(data.entities, 'abuse');
  const record = {
    provider: 'RDAP Service',
    query: ip,
    networkName: data.name,
    handle: data.handle,
    startAddress: data.startAddress,
    endAddress: data.endAddress,
    cidr: formatCidr(data.cidr0_cidrs),
    country: data.country || extractCountryFromEntity(registrantEntity),
    type: data.type,
    org: getEntityField(registrantEntity, 'org') || getEntityField(registrantEntity, 'fn'),
    abuseEmail: getEntityField(abuseEntity, 'email'),
    status: Array.isArray(data.status) ? data.status.join(', ') : '',
    created: data.events?.find(event => event.eventAction === 'registration')?.eventDate,
    updated: data.events?.find(event => event.eventAction === 'last changed')?.eventDate,
    port43: data.port43
  };

  state.ipMetadataCache[ip] = record;
  return record;
}

function getReverseLookupName(ip) {
  if (isIPv4(ip)) {
    return `${ip.split('.').reverse().join('.')}.in-addr.arpa`;
  }

  if (isIPv6(ip)) {
    const expanded = expandIPv6Address(ip);
    const nibbles = expanded.replace(/:/g, '').split('').reverse().join('.');
    return `${nibbles}.ip6.arpa`;
  }

  throw new Error('Invalid IP address for PTR lookup');
}

function isIPv4(value) {
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipv4Regex.test(value);
}

function isIPv6(value) {
  const ipv6Regex = /^((?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,7}:|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}|:(?::[0-9A-Fa-f]{1,4}){1,7}|::)$/;
  return ipv6Regex.test(value);
}

function expandIPv6Address(ip) {
  const [left = '', right = ''] = ip.split('::');
  const leftParts = left ? left.split(':') : [];
  const rightParts = right ? right.split(':') : [];
  const missingGroups = 8 - (leftParts.length + rightParts.length);
  const expandedParts = [
    ...leftParts,
    ...Array(Math.max(missingGroups, 0)).fill('0'),
    ...rightParts
  ];

  return expandedParts.map(part => part.padStart(4, '0')).join(':');
}

function findEntityByRole(entities = [], role) {
  for (const entity of entities) {
    if (entity.roles?.includes(role)) {
      return entity;
    }

    const nestedMatch = findEntityByRole(entity.entities || [], role);
    if (nestedMatch) {
      return nestedMatch;
    }
  }

  return null;
}

function getEntityField(entity, fieldName) {
  const entries = entity?.vcardArray?.[1];

  if (!Array.isArray(entries)) {
    return '';
  }

  const match = entries.find(entry => entry[0] === fieldName);
  return typeof match?.[3] === 'string' ? match[3] : '';
}

function extractCountryFromEntity(entity) {
  const addressLabel = entity?.vcardArray?.[1]?.find(entry => entry[0] === 'adr')?.[1]?.label || '';
  return addressLabel.split('\n').pop() || '';
}

function formatCidr(cidrBlocks = []) {
  if (!Array.isArray(cidrBlocks) || cidrBlocks.length === 0) {
    return '';
  }

  return cidrBlocks.map(block => {
    if (block.v4prefix) {
      return `${block.v4prefix}/${block.length}`;
    }

    if (block.v6prefix) {
      return `${block.v6prefix}/${block.length}`;
    }

    return '';
  }).filter(Boolean).join(', ');
}

function initializeSharedReportFromUrl() {
  const sharedState = parseSharedReportFromHash(window.location.hash);

  if (!sharedState.domain) {
    return;
  }

  const domainInput = document.getElementById('domainInput');
  const actionType = sharedState.type || 'ALL_RECORDS';
  const reportButton = document.querySelector(`.action-btn[data-type="${actionType}"]`);

  if (!domainInput || !reportButton) {
    return;
  }

  domainInput.value = sharedState.domain;
  reportButton.click();
}

function parseSharedReportFromHash(hash) {
  const hashValue = (hash || '').replace(/^#/, '');

  if (!hashValue) {
    return { domain: '', type: null };
  }

  if (!hashValue.includes('=')) {
    return {
      domain: normalizeDomainInput(decodeURIComponent(hashValue)),
      type: null
    };
  }

  const params = new URLSearchParams(hashValue);
  const domain = normalizeDomainInput(params.get('domain') || '');
  const requestedType = (params.get('test') || '').trim().toUpperCase();

  return {
    domain,
    type: SHAREABLE_ACTION_TYPES.has(requestedType) ? requestedType : null
  };
}

function updateSharableUrl(domain, type = state.currentTest) {
  const normalizedDomain = normalizeDomainInput(domain);
  const normalizedType = SHAREABLE_ACTION_TYPES.has(type) ? type : null;
  let newHash = '';

  if (normalizedDomain) {
    if (normalizedType) {
      const params = new URLSearchParams({
        test: normalizedType,
        domain: normalizedDomain
      });
      newHash = `#${params.toString()}`;
    } else {
      newHash = `#${encodeURIComponent(normalizedDomain)}`;
    }
  }

  const nextUrl = `${window.location.origin}${window.location.pathname}${newHash}`;

  if (window.location.href !== nextUrl) {
    window.history.replaceState({}, '', nextUrl);
  }
}

function isValidDomain(domain) {
  const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i;
  return domainRegex.test(domain);
}

function isValidIP(ip) {
  return isIPv4(ip) || isIPv6(ip);
}

function formatTabName(type) {
  const names = {
    'A': 'A Records',
    'AAAA': 'IPv6',
    'MX': 'Mail',
    'NS': 'Nameservers',
    'CNAME': 'CNAME',
    'TXT': 'TXT',
    'SPF': 'SPF',
    'DMARC': 'DMARC',
    'SOA': 'SOA',
    'PTR': 'Reverse DNS',
    'PROPAGATION': 'Propagation',
    'WHOIS': 'WHOIS',
    'IP_WHOIS': 'IP Info',
    'SSL_CHECK': 'SSL Report'
  };

  return names[type] || type;
}

function formatTime(timestamp) {
  return new Date(timestamp).toLocaleString();
}

async function copyToClipboard(text, button) {
  try {
    await navigator.clipboard.writeText(text);
    const originalText = button.textContent;
    button.textContent = 'âœ“ Copied';
    button.style.background = 'var(--accent-green)';
    button.style.color = 'white';

    setTimeout(() => {
      button.textContent = originalText;
      button.style.background = '';
      button.style.color = '';
    }, 2000);
  } catch (err) {
    console.error('Failed to copy:', err);
  }
}

// ============================================
// Export & History Functions
// ============================================

function exportResults() {
  const data = {
    domain: state.currentDomain,
    timestamp: new Date().toISOString(),
    results: state.results
  };

  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `dns-lookup-${state.currentDomain}-${Date.now()}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function clearResults() {
  state.results = {};
  state.activeTab = null;
  state.currentDomain = '';
  state.currentTest = null;
  updateSharableUrl('');

  document.getElementById('resultsContent').classList.remove('active');
  document.getElementById('resultTabs').style.display = 'none';
  document.getElementById('emptyState').classList.remove('hidden');
  document.getElementById('exportBtn').style.display = 'none';
  document.getElementById('clearBtn').style.display = 'none';
}

function addToHistory(domain, type) {
  const entry = {
    domain,
    type,
    timestamp: new Date().toISOString()
  };

  // Remove duplicates
  state.history = state.history.filter(h =>
    !(h.domain === domain && h.type === type)
  );

  // Add to beginning
  state.history.unshift(entry);

  // Keep last 50
  state.history = state.history.slice(0, 50);
}

function saveHistory() {
  localStorage.setItem('searchHistory', JSON.stringify(state.history));
}

function loadHistory() {
  // History could be displayed in a sidebar or dropdown in future versions
  console.log('Search history loaded:', state.history.length, 'entries');
}
// Ping Results Renderer
