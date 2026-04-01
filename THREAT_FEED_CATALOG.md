# Threat Intelligence Feed Catalog

Comprehensive list of public and commercial threat intelligence feeds for URL/domain blocking.

## Currently Integrated (Free)

- ✅ **URLhaus** - Malware distribution URLs (abuse.ch)
- ✅ **PhishTank** - Phishing URLs
- ✅ **OpenPhish** - Community phishing feed
- ✅ **ThreatFox** - Malware IOCs (abuse.ch)

## Malware & Malicious URLs

### Free Feeds

**Malware Domain List**
- URL: `http://www.malwaredomainlist.com/hostslist/hosts.txt`
- Format: Hosts file
- Update: Daily
- Content: Malware-hosting domains
- Registration: No

**MalwareDomains**
- URL: `http://mirror1.malwaredomains.com/files/justdomains`
- Format: Plaintext (domains)
- Update: Daily
- Content: Malware domains
- Registration: No

**Malware Domain Blocklist (RiskIQ)**
- URL: `https://reputation.alienvault.com/reputation.generic`
- Format: Plaintext
- Update: Hourly
- Content: Malicious IPs and domains
- Registration: Free API key

**abuse.ch SSL Blacklist**
- URL: `https://sslbl.abuse.ch/blacklist/sslblacklist.csv`
- Format: CSV
- Update: Every 30 minutes
- Content: Malicious SSL certificates/domains
- Registration: No

**Feodo Tracker (abuse.ch)**
- URL: `https://feodotracker.abuse.ch/downloads/ipblocklist.txt`
- Format: Plaintext (IPs)
- Update: Every 5 minutes
- Content: Botnet C&C servers
- Registration: No

**Ransomware Tracker (abuse.ch)**
- URL: `https://ransomwaretracker.abuse.ch/downloads/RW_URLBL.txt`
- Format: Plaintext
- Update: Every 5 minutes
- Content: Ransomware distribution URLs
- Registration: No

**ZeuS Tracker (abuse.ch)**
- URL: `https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist`
- Format: Plaintext
- Update: Every 30 minutes
- Content: ZeuS botnet domains
- Registration: No

### Commercial/Freemium

**VirusTotal Intelligence**
- URL: API-based
- Format: JSON
- Update: Real-time
- Content: Multi-vendor malware detection
- Cost: $$$

**Recorded Future**
- URL: API-based
- Format: JSON
- Update: Real-time
- Content: Threat intelligence, IOCs
- Cost: $$$

## Phishing & Fraud

### Free Feeds

**Spamhaus DBL (Domain Block List)**
- URL: DNS-based (query format)
- Format: DNS TXT records
- Update: Real-time
- Content: Spam/phishing domains
- Registration: Free for small use

**SURBL**
- URL: DNS-based
- Format: DNS queries
- Update: Real-time
- Content: Spam URIs
- Registration: Free tier available

**Google Safe Browsing**
- URL: API-based
- Format: JSON (Update API v4)
- Update: Real-time
- Content: Phishing, malware, unwanted software
- API Key: Free (rate limited)

**Anti-Phishing Working Group (APWG)**
- URL: Member access
- Format: Various
- Update: Regular
- Content: Phishing campaigns
- Registration: Membership required (free tier)

**CyberCrime Tracker**
- URL: `http://cybercrime-tracker.net/all.php`
- Format: HTML (needs scraping)
- Update: Real-time
- Content: C&C panels, phishing kits
- Registration: No

### Commercial

**PhishLabs**
- URL: API-based
- Cost: $$$
- Content: Phishing, brand abuse

**Cofense (PhishMe)**
- URL: API-based
- Cost: $$$
- Content: Phishing intelligence

## Adult Content Filtering

### Free Feeds

**Shallalist**
- URL: `http://www.shallalist.de/Downloads/shallalist.tar.gz`
- Format: Squid blocklist format
- Update: Weekly
- Content: Categorized URLs (adult, porn, violence, etc.)
- Size: ~1.5M domains
- Registration: No

**UT1 Blacklist**
- URL: `http://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz`
- Format: Squid format
- Update: Monthly
- Content: Adult, gambling, weapons, etc.
- Size: ~3M domains
- Registration: No

**MESD Blacklist**
- URL: `http://squidguard.mesd.k12.or.us/blacklists.tgz`
- Format: SquidGuard format
- Update: Periodic
- Content: Adult, gambling, violence, etc.
- Registration: No

**Porn Domains List (GitHub)**
- URL: `https://raw.githubusercontent.com/blocklistproject/Lists/master/porn.txt`
- Format: Plaintext
- Update: Regular
- Content: Adult content domains
- Registration: No

**Adult Site Blocklist (OSINT)**
- URL: `https://raw.githubusercontent.com/chadmayfield/my-pihole-blocklists/master/lists/pi_blocklist_porn_all.list`
- Format: Plaintext
- Update: Regular
- Content: Comprehensive adult content list
- Registration: No

### Commercial

**Webroot BrightCloud**
- URL: API-based
- Cost: $$
- Content: URL categorization (80+ categories)

**Zvelo**
- URL: API-based
- Cost: $$
- Content: Real-time URL categorization

**Forcepoint (Websense)**
- URL: API-based
- Cost: $$$
- Content: Enterprise URL filtering database

## Gambling & Gaming

### Free Feeds

**UT1 Blacklist - Gambling**
- URL: Included in UT1 download
- Content: Gambling, casino sites

**Shallalist - Gambling**
- URL: Included in Shallalist
- Content: Gambling domains

**Gambling Blocklist (GitHub)**
- URL: `https://raw.githubusercontent.com/blocklistproject/Lists/master/gambling.txt`
- Format: Plaintext
- Content: Gambling sites

## Cryptocurrency Mining

**NoCoin**
- URL: `https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt`
- Format: Hosts file
- Content: Cryptomining scripts/domains

**CoinBlockerLists**
- URL: `https://gitlab.com/ZeroDot1/CoinBlockerLists/raw/master/list.txt`
- Format: Plaintext
- Content: Cryptojacking domains

## Ads & Trackers

**EasyList**
- URL: `https://easylist.to/easylist/easylist.txt`
- Format: Adblock Plus format
- Content: Ad servers

**Peter Lowe's Ad Server List**
- URL: `https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0`
- Format: Hosts file
- Content: Ad/tracking servers

**Steven Black's Unified Hosts**
- URL: `https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts`
- Format: Hosts file
- Content: Ads, malware, fake news, gambling, porn

## Social Media (Productivity/Security)

**Social Media Blocklist**
- URL: `https://raw.githubusercontent.com/blocklistproject/Lists/master/facebook.txt`
- Format: Plaintext
- Content: Facebook/Meta domains

**YouTube Blocklist**
- URL: `https://raw.githubusercontent.com/blocklistproject/Lists/master/youtube.txt`
- Format: Plaintext
- Content: YouTube domains

**TikTok Blocklist**
- URL: `https://raw.githubusercontent.com/blocklistproject/Lists/master/tiktok.txt`
- Format: Plaintext
- Content: TikTok domains

## Piracy & Torrents

**The Block List Project - Piracy**
- URL: `https://raw.githubusercontent.com/blocklistproject/Lists/master/piracy.txt`
- Format: Plaintext
- Content: Torrent, streaming, file sharing sites

**RIAA Complaint Sites**
- URL: Various sources
- Content: Sites receiving DMCA complaints

## Scams & Fraud

**Scam Blocklist**
- URL: `https://raw.githubusercontent.com/blocklistproject/Lists/master/scam.txt`
- Format: Plaintext
- Content: Known scam domains

**419 Scam Sites**
- URL: `https://raw.githubusercontent.com/mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites/master/hacked-domains.list`
- Format: Plaintext
- Content: Compromised/scam sites

## Emerging Threats

**Bambenek Consulting Feeds**
- URL: `http://osint.bambenekconsulting.com/feeds/`
- Format: Various (CSV, TXT)
- Content: C&C servers, DGA domains
- Free: Yes

**EmergingThreats.net**
- URL: `https://rules.emergingthreats.net/open/`
- Format: Snort/Suricata rules
- Content: Threat rules, compromised IPs
- Free: Open ruleset available

**Blocklist.de**
- URL: `https://lists.blocklist.de/lists/all.txt`
- Format: Plaintext (IPs)
- Content: Attack sources (SSH, Mail, Apache)
- Free: Yes

## Regional/Government

**NCSC (UK) Suspicious Email Reporting**
- URL: Data sharing program
- Content: UK-reported phishing

**CISA (US) - Cybersecurity Advisories**
- URL: `https://www.cisa.gov/uscert/ncas/alerts`
- Format: Various
- Content: Government threat advisories

**CERT Feeds (Various Countries)**
- Multiple national CERTs provide feeds
- Usually free for constituents

## DNS-Based Blocklists

**RPZ (Response Policy Zones)**
- Multiple providers (Spamhaus, etc.)
- Format: DNS zone files
- Real-time DNS blocking

**Quad9 Threat Feed**
- DNS resolver with built-in blocking
- Can query their threat data

## Industry-Specific

**FS-ISAC (Financial Services)**
- URL: Member portal
- Content: Financial sector threats
- Cost: Membership required

**H-ISAC (Healthcare)**
- URL: Member portal
- Content: Healthcare sector threats
- Cost: Membership required

**E-ISAC (Energy)**
- URL: Member portal
- Content: Energy sector threats
- Cost: Membership required

## Aggregated/Meta Feeds

**AlienVault OTX (Open Threat Exchange)**
- URL: `https://otx.alienvault.com/`
- Format: API/STIX
- Content: Community threat intelligence
- Free: Yes (registration required)

**Abuse.ch Collection**
- URL: `https://abuse.ch/`
- Content: Multiple specialized feeds
- Free: Yes

**The Block List Project**
- URL: `https://github.com/blocklistproject/Lists`
- Format: Plaintext
- Content: Curated blocklists by category
- Free: Yes

**FireHOL IP Lists**
- URL: `https://iplists.firehol.org/`
- Format: Various
- Content: Aggregated IP/domain blocklists
- Free: Yes

## Implementation Examples

### Shallalist (Adult Content)

```yaml
reputation:
  feeds:
    enabled: true
    custom_feeds:
      - name: "Shallalist-Adult"
        url: "http://www.shallalist.de/Downloads/shallalist.tar.gz"
        type: "archive"  # Requires extraction
        category: "adult"
```

### Blocklistproject (Multiple Categories)

```yaml
reputation:
  feeds:
    enabled: true
    custom_feeds:
      - name: "BlockList-Porn"
        url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/porn.txt"
        type: "plaintext"
        category: "adult"

      - name: "BlockList-Gambling"
        url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/gambling.txt"
        type: "plaintext"
        category: "gambling"

      - name: "BlockList-Piracy"
        url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/piracy.txt"
        type: "plaintext"
        category: "piracy"

      - name: "BlockList-Scams"
        url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/scam.txt"
        type: "plaintext"
        category: "scam"

      - name: "BlockList-Malware"
        url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.txt"
        type: "plaintext"
        category: "malware"
```

### Enterprise Setup (All Categories)

```yaml
reputation:
  feeds:
    enabled: true
    update_interval: 30  # 30 minutes
    max_age: 14         # 2 weeks

    # Default malware/phishing feeds
    enable_urlhaus: true
    enable_phishtank: true
    enable_openphish: true
    enable_threatfox: true

    custom_feeds:
      # Adult content
      - name: "Adult-Content"
        url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/porn.txt"
        type: "plaintext"
        category: "adult"

      # Gambling
      - name: "Gambling"
        url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/gambling.txt"
        type: "plaintext"
        category: "gambling"

      # Piracy
      - name: "Piracy"
        url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/piracy.txt"
        type: "plaintext"
        category: "piracy"

      # Cryptomining
      - name: "CoinBlocker"
        url: "https://gitlab.com/ZeroDot1/CoinBlockerLists/raw/master/list.txt"
        type: "plaintext"
        category: "cryptomining"

      # Malware domains
      - name: "Malware-Domains"
        url: "http://mirror1.malwaredomains.com/files/justdomains"
        type: "plaintext"
        category: "malware"

      # Ransomware
      - name: "Ransomware-Tracker"
        url: "https://ransomwaretracker.abuse.ch/downloads/RW_URLBL.txt"
        type: "plaintext"
        category: "malware"

      # Social media (optional)
      - name: "Facebook"
        url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/facebook.txt"
        type: "plaintext"
        category: "social_media"

      - name: "TikTok"
        url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/tiktok.txt"
        type: "plaintext"
        category: "social_media"

      # Ads/Trackers
      - name: "Ad-Servers"
        url: "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0"
        type: "plaintext"
        category: "ads"
```

## Notes on Legal/Compliance

- **Adult content blocking**: May be required in schools, libraries (CIPA compliance)
- **Gambling**: May be required in certain jurisdictions or workplaces
- **Copyright/Piracy**: DMCA compliance, enterprise policies
- **Regional restrictions**: Some feeds may be geo-restricted
- **Privacy**: Consider user privacy when logging blocked categories
- **Transparency**: Inform users about blocking policies

## Performance Considerations

**Feed Sizes:**
- Small (< 10K entries): Malware feeds
- Medium (10K-100K): Phishing, adult content
- Large (100K-1M): Shallalist, UT1, comprehensive lists
- Very Large (> 1M): Combined/aggregated lists

**Memory Impact:**
- 10K URLs: ~2 MB
- 100K URLs: ~20 MB
- 1M URLs: ~200 MB
- 5M URLs: ~1 GB

**Update Frequency:**
- Critical (malware): Every 5-15 minutes
- Important (phishing): Every 30-60 minutes
- Standard (adult, gambling): Every 2-24 hours
- Low priority (ads): Daily

## Recommended Starter Configuration

For most deployments, start with:

1. **Security (Critical):**
   - URLhaus
   - PhishTank
   - OpenPhish
   - ThreatFox
   - Malware Domain List

2. **Content Filtering (Optional):**
   - BlockList Project - Porn
   - BlockList Project - Gambling
   - BlockList Project - Piracy

3. **Productivity (Optional):**
   - Social media blocklists (if needed)
   - Ad/tracker blocklists

Total: ~500K-1M URLs, ~100-200 MB RAM
