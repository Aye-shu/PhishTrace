const API_URL = "https://ominous-space-engine-wr954qgvgg5gcgpg-5000.app.github.dev/analyze";
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    // Only run when the page is fully loaded and has a URL
    if (changeInfo.status === 'complete' && tab.url) {
        
        // Skip internal pages
        if (tab.url.startsWith("chrome://") || tab.url.startsWith("about:")) return;

        // Send URL to our Python API
        fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: tab.url })
        })
        .then(response => response.json())
        .then(data => {
            console.log("PhishTrace received data:", data); // ADD THIS LINE
            // Update the extension icon based on the verdict
            if (data.verdict === 'PHISHING') {
                chrome.action.setBadgeText({ text: "DANGER", tabId: tabId });
                chrome.action.setBadgeBackgroundColor({ color: "#e74c3c", tabId: tabId });
            } else if (data.verdict === 'SUSPICIOUS') {
                chrome.action.setBadgeText({ text: "WARN", tabId: tabId });
                chrome.action.setBadgeBackgroundColor({ color: "#f39c12", tabId: tabId });
            } else {
                chrome.action.setBadgeText({ text: "SAFE", tabId: tabId });
                chrome.action.setBadgeBackgroundColor({ color: "#27ae60", tabId: tabId });
            }
            
            // Save the result for the popup to read
            chrome.storage.local.set({ [tabId]: data });
        })
        .catch(error => console.error("PhishTrace Error:", error));
    }
});