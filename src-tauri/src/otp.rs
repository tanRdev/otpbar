use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref OTP_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"(?i)(?:code|verification|otp|pin)[:\s]+(\d{4,8})")
            .expect("OTP regex pattern 1 should be valid"),
        Regex::new(r"(?i)(\d{4,8})\s+(?:is\s+)?your\s+(?:code|otp|verification|pin)")
            .expect("OTP regex pattern 2 should be valid"),
        Regex::new(r"(?i)your\s+(?:code|otp|verification|pin)\s+(?:is[:\s]+)?(\d{4,8})")
            .expect("OTP regex pattern 3 should be valid"),
        Regex::new(r"(?i)enter[:\s]+(\d{4,8})\s+to\s+(?:verify|confirm)")
            .expect("OTP regex pattern 4 should be valid"),
        Regex::new(r"(?i)\b(\d{3}-\d{3})\b")
            .expect("OTP regex pattern 5 should be valid"),
        Regex::new(r"\b(\d{6})\b")
            .expect("OTP regex pattern 6 should be valid"),
    ];
}

pub fn extract_otp(text: &str) -> Option<String> {
    for pattern in OTP_PATTERNS.iter() {
        if let Some(caps) = pattern.captures(text) {
            if let Some(code) = caps.get(1) {
                return Some(code.as_str().to_string());
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

    // Extract domain from email address first to avoid substring false matches
    let domain = if let Some(at_pos) = sender_lower.find('@') {
        &sender_lower[at_pos + 1..]
    } else {
        &sender_lower
    };

    // Check domain and full sender with word boundary awareness
    for (key, value) in MAPPINGS {
        // For exact domain matches (e.g., "x.com")
        if key.contains('.') && domain == *key {
            return value.to_string();
        }
        // For domain component matches (e.g., "netflix" in "netflix.com")
        if domain.starts_with(key) || domain.contains(&format!(".{}", key)) {
            return value.to_string();
        }
        // Also check the full sender for name-based matches (e.g., "GitHub <noreply@github.com>")
        if sender_lower.contains(&format!("{} ", key)) || sender_lower.starts_with(key) {
            return value.to_string();
        }
    }

    // Try to extract name before email
    let name_re = Regex::new(r"^([^<@]+)")
        .expect("Name regex should be valid");
    if let Some(caps) = name_re.captures(sender) {
        let name = caps[1].trim();
        let clean_re = Regex::new(r"\s*(no-?reply|noreply|support|security|verify|verification|accounts?|team|notifications?)\s*")
            .expect("Clean regex should be valid");
        let clean = clean_re.replace(name, "").trim().to_string();
        if !clean.is_empty() && clean.len() < 30 {
            return clean;
        }
        if !name.is_empty() && name.len() < 30 {
            return name.to_string();
        }
    }

    // Try to extract domain
    let domain_re = Regex::new(r"@([^.>]+)")
        .expect("Domain regex should be valid");
    if let Some(caps) = domain_re.captures(sender) {
        let domain = &caps[1];
        let mut chars = domain.chars();
        if let Some(first) = chars.next() {
            return format!("{}{}", first.to_uppercase(), chars.as_str());
        }
    }

    "Unknown".to_string()
}
