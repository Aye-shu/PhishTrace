chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
    const tabId = tabs[0].id;
    
    chrome.storage.local.get([tabId.toString()], (result) => {
        const data = result[tabId];
        
        const box = document.getElementById('verdict-box');
        const score = document.getElementById('score');
        const reasonsList = document.getElementById('reasons');

        if (data) {
            box.innerText = data.verdict;
            box.className = `verdict ${data.verdict}`;
            score.innerText = `Risk Score: ${data.score}/100`;
            
            data.reasons.forEach(reason => {
                const li = document.createElement('li');
                li.innerText = reason;
                reasonsList.appendChild(li);
            });
        } else {
            box.innerText = "Analyzing...";
        }
    });
});