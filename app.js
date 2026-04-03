// SecureAccess Audit Dashboard
// Author Keenen Wilkins github.com/cruisethecity
// Description: This pulls the security logs, runs the math for the 
// threat scores, and builds out the interactive dashboard filters.

// I put allLogs out here in the global scope so the rest of the functions
// can actually reach the scored data. If I locked it inside a function it
// would be invisible to everything else.
let allLogs = [];



// fetch grabs the logs.json file in the background. It is asynchronous 
// which means the page does not freeze up while it waits for the data.
// The then blocks tell the app exactly what to do once the data arrives.
fetch('logs.json')
  .then(function(response) {
    // This converts the raw http response into a standard javascript array
    return response.json();
  })
  .then(function(logs) {
    // Here is the main pipeline running in order
    // 1. Run the math to score every log entry
    // 2. Build the visual table
    // 3. Update the big summary numbers at the top
    // 4. Hook up the click events for the filters
    allLogs = calculateThreatScores(logs);
    renderTable(allLogs);
    updateStats(allLogs);
    setupFilters();
  });

// formatTimestamp
// This takes the ugly raw timestamp and turns it into something readable
// like Apr 1 2026 02:11 AM. I use the built in Date object so it handles
// the local formatting automatically.
function formatTimestamp(timestamp) {
  const date = new Date(timestamp);
  return date.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric'
  }) + ' ' + date.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit'
  });
}

// calculateThreatScores
// This is the core scoring engine. It takes the raw logs and spits out a
// new array where every entry has a threatScore attached. I look for patterns
// across multiple signals instead of just flagging single isolated events.
function calculateThreatScores(logs) {

  // Pass 1: Count up the failed login attempts per username.
  // This lets us slap a brute force penalty on ALL activity for a user
  // if they fail 3 or more times, not just on the failed attempts themselves.
  const failedCounts = {};
  for (let i = 0; i < logs.length; i++) {
    const log = logs[i];
    if (log.action === 'LOGIN_FAILED') {
      if (failedCounts[log.username] === undefined) {
        failedCounts[log.username] = 0;
      }
      failedCounts[log.username]++;
    }
  }

  // Pass 2: Track down which usernames are sharing an IP address.
  // If one IP is trying to access multiple accounts that is a massive red flag
  // for credential stuffing or a shared attacker origin.
  const ipUsernames = {};
  for (let i = 0; i < logs.length; i++) {
    const log = logs[i];
    if (ipUsernames[log.ipAddress] === undefined) {
      ipUsernames[log.ipAddress] = [];
    }
    if (!ipUsernames[log.ipAddress].includes(log.username)) {
      ipUsernames[log.ipAddress].push(log.username);
    }
  }

  // Pass 3: Score each log entry based on the full context.
  // I use map here to transform every log into a fresh object that keeps
  // the original data but tacks on the calculated threatScore.
  const scoredLogs = logs.map(function(log) {
    let score = 0;

    // Extract the hour from the timestamp to catch late night activity.
    // Javascript makes this easy with getHours.
    const hour = new Date(log.timestamp).getHours();

    // Apply the scoring rules. Each one targets a specific security risk.
    if (log.action === 'LOGIN_FAILED') score += 10;        // Failed auth attempt
    if (hour >= 22 || hour < 6) score += 15;               // After hours activity
    if (log.action === 'PRIVILEGE_ESCALATION') score += 20; // Elevated access attempt
    if (log.action === 'ACCOUNT_LOCKOUT') score += 30;      // Lockout triggered
    if (failedCounts[log.username] >= 3) score += 25;       // Brute force pattern
    if (ipUsernames[log.ipAddress].length > 1) score += 10; // Shared IP risk

    // The spread operator ...log copies all the original fields into the
    // new object and then we just add the threatScore at the end.
    // This keeps the original data perfectly clean.
    return { ...log, threatScore: score };
  });

  return scoredLogs;
}



// renderTable
// This takes our scored data and actually builds the HTML table body.
// It maps each log object into a table row string and then joins them 
// all together so we can inject them into the DOM at once.
function renderTable(logs) {
  const tableBody = document.getElementById('table-body');

  tableBody.innerHTML = logs.map(function(log) {

    // Set up the status label and styling based on how high the threat score is.
    // These class names tie directly into the CSS file for the colors.
    let status = 'Normal';
    let statusClass = 'status-normal';
    let scoreClass = 'score-low';

    if (log.threatScore >= 50) {
      status = 'Suspicious';
      statusClass = 'status-suspicious';
    } else if (log.threatScore >= 20) {
      status = 'Warning';
      statusClass = 'status-warning';
    }

    if (log.threatScore >= 50) scoreClass = 'score-high';
    else if (log.threatScore >= 20) scoreClass = 'score-medium';

    // I use a template literal here to build the HTML string for the row.
    // This lets me drop javascript variables right into the html cleanly.
    return `<tr>
      <td>${formatTimestamp(log.timestamp)}</td>
      <td>${log.username}</td>
      <td>${log.action}</td>
      <td>${log.ipAddress}</td>
      <td>${log.department}</td>
      <td class="${statusClass}">${status}</td>
      <td class="${scoreClass}">${log.threatScore}</td>
    </tr>`;
  }).join('');
}

// updateStats
// This calculates the summary metrics and updates those four big stat cards
// at the top of the dashboard. It always looks at the full allLogs array
// so the numbers stay accurate even when the user is filtering the table.
function updateStats(logs) {
  const total = logs.length;

  // Count up all the failed login events across the entire dataset.
  const failed = allLogs.filter(function(log) {
    return log.action === 'LOGIN_FAILED';
  }).length;

  // Grab every entry that actually triggered a threat score.
  const flagged = allLogs.filter(function(log) {
    return log.threatScore > 0;
  });

  // Using new Set here strips out the duplicates. If a bot account shows up
  // eight times we only want to count it as one flagged account.
  const uniqueFlagged = [...new Set(flagged.map(function(log) {
    return log.username;
  }))].length;

  // A standard loop to compare scores and find the single highest risk user.
  let highRiskUser = '--';
  let highScore = 0;
  for (let i = 0; i < allLogs.length; i++) {
    if (allLogs[i].threatScore > highScore) {
      highScore = allLogs[i].threatScore;
      highRiskUser = allLogs[i].username;
    }
  }

  // Update the actual numbers on the screen. The querySelector lets me target
  // the exact class inside the specific ID.
  document.querySelector('#stat-total .stat-number').textContent = total;
  document.querySelector('#stat-failed .stat-number').textContent = failed;
  document.querySelector('#stat-flagged .stat-number').textContent = uniqueFlagged;
  document.querySelector('#stat-highrisk .stat-number').textContent = highRiskUser;
}

// setupFilters
// This hooks up the five filter buttons with click events. Each button looks
// at its own data attribute to figure out what to filter and then tells the
// table to re render with the new subset of data.
function setupFilters() {
  const buttons = document.querySelectorAll('.filter-btn');

  buttons.forEach(function(button) {
    button.addEventListener('click', function() {

      // Clear the active styling from all buttons and then apply it only to 
      // the one that just got clicked.
      buttons.forEach(function(btn) {
        btn.classList.remove('active');
      });
      button.classList.add('active');

      // Read the data attribute to see which rule we need to run.
      const filter = button.getAttribute('data-filter');
      let filtered = allLogs;

      if (filter === 'failed') {
        // Show only the authentication failures
        filtered = allLogs.filter(function(log) {
          return log.action === 'LOGIN_FAILED';
        });
      } else if (filter === 'afterhours') {
        // Show events outside standard business hours 10 PM to 6 AM
        filtered = allLogs.filter(function(log) {
          const hour = new Date(log.timestamp).getHours();
          return hour >= 22 || hour < 6;
        });
      } else if (filter === 'escalation') {
        // Show only the privilege escalation events
        filtered = allLogs.filter(function(log) {
          return log.action === 'PRIVILEGE_ESCALATION';
        });
      } else if (filter === 'suspicious') {
        // Show any entry that flagged a threat score above zero
        filtered = allLogs.filter(function(log) {
          return log.threatScore > 0;
        });
      }

      renderTable(filtered);
    });
  });
}