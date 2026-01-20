use regex::Regex;

static OTP_PATTERNS: &[&str] = &[
    r"(?:code|verification|otp|pin)[:\s]+(\d{4,8})",
    r"(\d{4,8})\s+is\s+your\s+(?:code|otp|verification|pin)",
    r"your\s+(?:code|otp|verification|pin)\s+is[:\s]+(\d{4,8})",
    r"enter[:\s]+(\d{4,8})\s+to\s+(?:verify|confirm)",
    r"\b(\d{6})\b",
];

pub fn extract_otp(text: &str) -> Option<String> {
    for pattern_str in OTP_PATTERNS {
        if let Ok(pattern) = Regex::new(pattern_str) {
            if let Some(caps) = pattern.captures(text) {
                if let Some(code) = caps.get(1) {
                    return Some(code.as_str().to_string());
                }
            }
        }
    }
    None
}

pub fn extract_provider(sender: &str) -> String {
    const MAPPINGS: &[(&str, &str)] = &[
        ("google", "Google"), ("gmail", "Google"),
        ("apple", "Apple"), ("microsoft", "Microsoft"), ("outlook", "Microsoft"),
        ("amazon", "Amazon"),
        ("facebook", "Facebook"), ("meta", "Meta"), ("instagram", "Instagram"),
        ("twitter", "Twitter"), ("x.com", "X"),
        ("github", "GitHub"),
        ("linkedin", "LinkedIn"),
        ("paypal", "PayPal"),
        ("stripe", "Stripe"),
        ("venmo", "Venmo"),
        ("cashapp", "Cash App"),
        ("square", "Square"),
        ("coinbase", "Coinbase"),
        ("binance", "Binance"),
        ("robinhood", "Robinhood"),
        ("chase", "Chase"),
        ("wellsfargo", "Wells Fargo"),
        ("bankofamerica", "Bank of America"),
        ("aws", "AWS"),
        ("heroku", "Heroku"),
        ("digitalocean", "DigitalOcean"),
        ("cloudflare", "Cloudflare"),
        ("shopify", "Shopify"),
        ("ebay", "eBay"),
        ("etsy", "Etsy"),
        ("doordash", "DoorDash"),
        ("grubhub", "Grubhub"),
        ("postmates", "Postmates"),
        ("uber", "Uber"),
        ("lyft", "Lyft"),
        ("spotify", "Spotify"),
        ("netflix", "Netflix"),
        ("notion", "Notion"),
        ("figma", "Figma"),
        ("canva", "Canva"),
        ("zoom", "Zoom"),
        ("webex", "Webex"),
        ("asana", "Asana"),
        ("trello", "Trello"),
        ("airbnb", "Airbnb"),
        ("twilio", "Twilio"),
        ("auth0", "Auth0"),
        ("okta", "Okta"),
        ("dropbox", "Dropbox"),
        ("slack", "Slack"),
        ("discord", "Discord"),
        ("salesforce", "Salesforce"),
        ("atlassian", "Atlassian"),
        ("jira", "Jira"),
        ("adobe", "Adobe"),
        ("oracle", "Oracle"),
        ("namecheap", "Namecheap"),
        ("godaddy", "GoDaddy"),
    ];

    let sender_lower = sender.to_lowercase();

    for (key, value) in MAPPINGS {
        if sender_lower.contains(key) {
            return value.to_string();
        }
    }

    // Try to extract name before email
    let name_re = Regex::new(r"^([^<@]+)").unwrap();
    if let Some(caps) = name_re.captures(sender) {
        let name = caps[1].trim();
        let clean_re = Regex::new(r"\s*(no-?reply|noreply|support|security|verify|verification|accounts?|team|notifications?)\s*").unwrap();
        let clean = clean_re.replace(name, "").trim().to_string();
        if !clean.is_empty() && clean.len() < 30 {
            return clean;
        }
        if !name.is_empty() && name.len() < 30 {
            return name.to_string();
        }
    }

    // Try to extract domain
    let domain_re = Regex::new(r"@([^.>]+)").unwrap();
    if let Some(caps) = domain_re.captures(sender) {
        let domain = &caps[1];
        let mut chars = domain.chars();
        if let Some(first) = chars.next() {
            return format!("{}{}", first.to_uppercase(), chars.as_str());
        }
    }

    "Unknown".to_string()
}
