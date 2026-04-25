# 🌐 DNS & Domain Lookup Tool

A modern, serverless DNS and domain lookup tool designed for hosting company support teams. Consolidates multiple DNS diagnostic tools into one beautiful, fast interface.

![DNS Lookup Tool](https://img.shields.io/badge/DNS-Lookup%20Tool-blue)
![No Dependencies](https://img.shields.io/badge/dependencies-none-green)
![Serverless](https://img.shields.io/badge/serverless-100%25-brightgreen)

## ✨ Features

### 🔍 DNS Record Lookups
- **A Records** - IPv4 addresses
- **AAAA Records** - IPv6 addresses
- **MX Records** - Mail server information with priorities
- **CNAME Records** - Canonical name aliases
- **NS Records** - Nameserver information
- **SOA Records** - Start of Authority zone info
- **TXT Records** - Text records (SPF, DKIM, DMARC detection)
- **PTR Records** - Reverse DNS lookup

### 🌍 Advanced Features
- **DNS Propagation Check** - Query from multiple global DNS providers
- **WHOIS Lookup** - Domain registration information
- **IP WHOIS** - IP geolocation and ISP information
- **All Records** - Fetch all DNS records at once
- **Multi-Location Testing** - Compare results from Google DNS and Cloudflare DNS

### 🎨 Modern UI/UX
- **Dark Mode** - Eye-friendly theme toggle
- **Glassmorphism Design** - Modern frosted glass effects
- **Responsive Layout** - Works on mobile, tablet, and desktop
- **Smooth Animations** - Micro-interactions for better UX
- **Rich Color Palette** - Professional, vibrant design

### 💾 Data Management
- **Export Results** - Download results as JSON
- **Search History** - Automatically saved in browser (last 50 searches)
- **Copy to Clipboard** - One-click copy for any value
- **No Page Refresh** - Single-page application

## 🚀 Quick Start

### Option 1: Direct Usage
Simply open `index.html` in any modern web browser. No installation or build process required!

### Option 2: Local Server (Recommended)
```bash
# Using Python
python -m http.server 8000

# Using Node.js
npx http-server

# Using PHP
php -S localhost:8000
```

Then open `http://localhost:8000` in your browser.

### Option 3: Deploy to Static Hosting

This tool can be deployed to any static hosting service:

**GitHub Pages:**
1. Push files to a GitHub repository
2. Enable GitHub Pages in repository settings
3. Done!

**Netlify:**
```bash
# Install Netlify CLI
npm install -g netlify-cli

# Deploy
netlify deploy --prod
```

**Vercel:**
```bash
# Install Vercel CLI
npm install -g vercel

# Deploy
vercel
```

**Cloudflare Pages, AWS S3, or any static host works too!**

## 📖 How to Use

1. **Enter a domain or IP** in the input field (e.g., `google.com` or `8.8.8.8`)
2. **Click any action button** to perform that lookup
3. **View results** in the organized results section
4. **Switch between tabs** if multiple record types were queried
5. **Copy values** using the copy button next to each result
6. **Export results** as JSON for record-keeping
7. **Toggle dark mode** using the button in the top-right corner

## 🔧 Technical Details

### Architecture
- **100% Client-Side** - No backend server required
- **Serverless** - Uses public DNS-over-HTTPS APIs
- **Zero Dependencies** - Pure HTML, CSS, and JavaScript
- **No Build Process** - Works immediately

### DNS Providers Used
- **Google Public DNS** - `https://dns.google/resolve`
- **Cloudflare DNS** - `https://cloudflare-dns.com/dns-query`

### WHOIS APIs
- Domain WHOIS via public WHOIS services
- IP Geolocation via ip-api.com (free for non-commercial use)
- Fallback to DNS-based information when APIs unavailable

### Browser Compatibility
| Browser | Version |
|---------|---------|
| Chrome  | ✅ Latest |
| Firefox | ✅ Latest |
| Safari  | ✅ Latest |
| Edge    | ✅ Latest |

**Requirements:**
- ES6+ JavaScript support
- Fetch API
- CSS Grid & Custom Properties
- Clipboard API (for copy feature)

## 📁 File Structure

```
dns-lookup-tool/
├── index.html      # Main HTML structure
├── styles.css      # Complete design system
├── app.js          # Application logic
└── README.md       # This file
```

## 🎨 Design System

The tool uses a comprehensive design system with:
- **CSS Custom Properties** for theming
- **HSL Color System** for rich, harmonious colors
- **Responsive Grid Layouts**
- **Smooth Transitions** (150ms-350ms cubic-bezier)
- **Glassmorphism Effects** with backdrop-filter
- **Modern Typography** (Inter + Fira Code from Google Fonts)

## 🔐 Privacy & Security

- **No data collection** - Everything runs in your browser
- **No tracking** - No analytics or third-party scripts
- **Local storage only** - Search history saved locally
- **HTTPS APIs** - All DNS queries over HTTPS
- **No authentication** - No login or API keys required

## 🛠️ Customization

### Change Color Scheme
Edit the CSS custom properties in `styles.css`:
```css
:root {
  --primary-hue: 250;  /* Change to any hue (0-360) */
  --primary-sat: 85%;  /* Saturation */
  --primary-light: 60%; /* Lightness */
}
```

### Add More DNS Providers
Edit the `DNS_PROVIDERS` object in `app.js`:
```javascript
const DNS_PROVIDERS = {
  yourprovider: {
    name: 'Your DNS Provider',
    endpoint: 'https://your-dns-api.com/resolve',
    location: 'Your Location'
  }
};
```

## 🐛 Troubleshooting

**Issue: CORS errors when querying DNS**
- Solution: Some DNS-over-HTTPS providers require specific headers. The tool uses Google DNS and Cloudflare DNS which support CORS.

**Issue: WHOIS lookups not working**
- Solution: Free WHOIS APIs have rate limits. The tool will fall back to showing DNS-based information.

**Issue: Dark mode not persisting**
- Solution: Ensure browser localStorage is enabled and not in private/incognito mode.

## 📝 License

This project is open source and available for personal and commercial use.

## 🙏 Credits

- **Google Public DNS** - DNS-over-HTTPS service
- **Cloudflare DNS** - DNS-over-HTTPS service
- **IP-API.com** - IP geolocation service
- **Google Fonts** - Inter & Fira Code typefaces

## 🚀 Future Enhancements

Potential features for future versions:
- [ ] Bulk domain checking
- [ ] DNS record comparison tool
- [ ] Historical DNS tracking
- [ ] SSL certificate information
- [ ] Port scanning
- [ ] Domain availability checker
- [ ] DNS zone file export
- [ ] Custom DNS server queries

## 💬 Support

For issues or questions, please check the browser console for error messages. Most issues are related to:
1. Invalid domain/IP format
2. DNS record doesn't exist
3. API rate limiting
4. CORS restrictions

---

Made with ❤️ for hosting support teams worldwide
