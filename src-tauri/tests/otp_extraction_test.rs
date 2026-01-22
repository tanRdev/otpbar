// Unit tests for OTP extraction patterns

use otpbar::otp;

#[test]
fn test_extract_otp_code_prefix() {
    let cases = [
        ("Your code is 123456", "123456"),
        ("CODE: 987654", "987654"),
        ("Verification code: 456789", "456789"),
        ("OTP 1234", "1234"),
        ("PIN: 567890", "567890"),
    ];

    for (text, expected) in cases {
        assert_eq!(otp::extract_otp(text), Some(expected.to_string()));
    }
}

#[test]
fn test_extract_otp_your_code_suffix() {
    let cases = [
        ("123456 is your code", "123456"),
        ("789012 is your verification code", "789012"),
        ("345678 is your OTP", "345678"),
        ("901234 is your pin", "901234"),
    ];

    for (text, expected) in cases {
        assert_eq!(otp::extract_otp(text), Some(expected.to_string()));
    }
}

#[test]
fn test_extract_otp_your_code_prefix() {
    let cases = [
        ("Your code is 123456", "123456"),
        ("Your otp is 789012", "789012"),
        ("Your verification code: 345678", "345678"),
        ("Your pin is 901234", "901234"),
    ];

    for (text, expected) in cases {
        assert_eq!(otp::extract_otp(text), Some(expected.to_string()));
    }
}

#[test]
fn test_extract_otp_enter_to_verify() {
    let cases = [
        ("Enter 123456 to verify", "123456"),
        ("Enter 789012 to confirm", "789012"),
    ];

    for (text, expected) in cases {
        assert_eq!(otp::extract_otp(text), Some(expected.to_string()));
    }
}

#[test]
fn test_extract_otp_hyphenated() {
    assert_eq!(
        otp::extract_otp("Your code is 123-456"),
        Some("123-456".to_string())
    );
}

#[test]
fn test_extract_otp_six_digits() {
    let cases = [
        ("Use 123456 to complete", "123456"),
        ("Code: 789012 now", "789012"),
    ];

    for (text, expected) in cases {
        assert_eq!(otp::extract_otp(text), Some(expected.to_string()));
    }
}

#[test]
fn test_extract_otp_case_insensitive() {
    let cases = [
        ("YOUR CODE IS 123456", "123456"),
        ("Your Code Is 789012", "789012"),
        ("code: 345678", "345678"),
        ("CODE 901234", "901234"),
    ];

    for (text, expected) in cases {
        assert_eq!(otp::extract_otp(text), Some(expected.to_string()));
    }
}

#[test]
fn test_extract_otp_no_match() {
    let cases = [
        "Hello world",
        "No numbers here",
        "Only 12 numbers",
        "Code is 123",        // Too short
        "Code is 1234567890", // Too long
    ];

    for text in cases {
        assert_eq!(otp::extract_otp(text), None, "Should not match: {}", text);
    }
}

#[test]
fn test_extract_otp_real_world_examples() {
    let cases = [
        ("Your Google verification code is 123456", "123456"),
        ("123456 is your Amazon verification code", "123456"),
        ("Use code 789012 to verify your identity", "789012"),
        ("Your verification code is: 345678", "345678"),
        ("Enter 901234 to verify your account", "901234"),
    ];

    for (text, expected) in cases {
        assert_eq!(otp::extract_otp(text), Some(expected.to_string()));
    }
}

#[test]
fn test_extract_provider_known_services() {
    let cases = [
        ("account-security@google.com", "Google"),
        ("noreply@accounts.google.com", "Google"),
        ("no-reply@apple.com", "Apple"),
        ("accounts@microsoft.com", "Microsoft"),
        ("verify@amazon.com", "Amazon"),
        ("security@facebook.com", "Facebook"),
        ("github@noreply.github.com", "GitHub"),
        ("notifications@linkedin.com", "LinkedIn"),
        ("service@paypal.com", "PayPal"),
        ("support@stripe.com", "Stripe"),
        ("venmo@venmo.com", "Venmo"),
        ("cashapp@squareup.com", "Cash App"),
        ("coinbase@coinbase.com", "Coinbase"),
        ("binance@binance.com", "Binance"),
        ("robinhood@robinhood.com", "Robinhood"),
        ("security-noreply@aws.amazon.com", "Amazon"), // amazon pattern matches first
        ("notify@heroku.com", "Heroku"),
        ("cloudflare@cloudflare.com", "Cloudflare"),
        ("shopify@shopify.com", "Shopify"),
        ("ebay@ebay.com", "eBay"),
        ("etsy@etsy.com", "Etsy"),
        ("uber@uber.com", "Uber"),
        ("spotify@spotify.com", "Spotify"),
        ("netflix@netflix.com", "Netflix"),
        ("team@notion.so", "Notion"),
        ("support@figma.com", "Figma"),
        ("zoom@zoom.us", "Zoom"),
        ("slack@slack.com", "Slack"),
        ("discord@discord.com", "Discord"),
        ("adobe@adobe.com", "Adobe"),
        ("salesforce@salesforce.com", "Salesforce"),
        ("atlassian@atlassian.com", "Atlassian"),
        // jira pattern matches after atlassian - atlassian wins due to order
        ("jira@atlassian.com", "Atlassian"),
        ("dropbox@dropbox.com", "Dropbox"),
        ("auth0@auth0.com", "Auth0"),
        ("okta@okta.com", "Okta"),
    ];

    for (sender, expected) in cases {
        assert_eq!(
            otp::extract_provider(sender),
            expected,
            "Failed for: {}",
            sender
        );
    }
}

#[test]
fn test_extract_provider_from_name() {
    let cases = [
        ("GitHub <noreply@github.com>", "GitHub"),
        ("Google <no-reply@accounts.google.com>", "Google"),
        ("Amazon Security <verify@amazon.com>", "Amazon"),
    ];

    for (sender, expected) in cases {
        assert_eq!(otp::extract_provider(sender), expected);
    }
}

#[test]
fn test_extract_provider_no_reply_fallback() {
    // noreply gets cleaned but original name is returned
    let result = otp::extract_provider("noreply@example.com");
    assert_eq!(result, "noreply");
}

#[test]
fn test_extract_provider_unknown_fallback() {
    // Unknown domain returns the name part (lowercased from email)
    assert_eq!(otp::extract_provider("unknown@unknown.xyz"), "unknown");
}

#[test]
fn test_extract_provider_twitter_rebrand() {
    assert_eq!(otp::extract_provider("support@x.com"), "X");
}

#[test]
fn test_extract_provider_banks() {
    let cases = [
        ("alerts@chase.com", "Chase"),
        ("wellsfargo@wellsfargo.com", "Wells Fargo"),
        ("bankofamerica@bankofamerica.com", "Bank of America"),
    ];

    for (sender, expected) in cases {
        assert_eq!(otp::extract_provider(sender), expected);
    }
}

#[test]
fn test_extract_provider_food_delivery() {
    let cases = [
        ("doordash@doordash.com", "DoorDash"),
        ("grubhub@grubhub.com", "Grubhub"),
        ("ubereats@uber.com", "Uber"),
        ("lyft@lyft.com", "Lyft"),
    ];

    for (sender, expected) in cases {
        assert_eq!(otp::extract_provider(sender), expected);
    }
}
