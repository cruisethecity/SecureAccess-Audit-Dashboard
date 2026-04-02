let allLogs = [];

fetch('logs.json')
  .then(function(response) {
    return response.json();
  })
  .then(function(logs) {
    allLogs = calculateThreatScores(logs);
    renderTable(allLogs);
    updateStats(allLogs);
    setupFilters();
  });

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

function calculateThreatScores(logs) {
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

  const scoredLogs = logs.map(function(log) {
    let score = 0;
    const hour = new Date(log.timestamp).getHours();

    if (log.action === 'LOGIN_FAILED') score += 10;
    if (hour >= 22 || hour < 6) score += 15;
    if (log.action === 'PRIVILEGE_ESCALATION') score += 20;
    if (log.action === 'ACCOUNT_LOCKOUT') score += 30;
    if (failedCounts[log.username] >= 3) score += 25;
    if (ipUsernames[log.ipAddress].length > 1) score += 10;

    return { ...log, threatScore: score };
  });

  return scoredLogs;
}

function renderTable(logs) {
  const tableBody = document.getElementById('table-body');

  tableBody.innerHTML = logs.map(function(log) {
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

function updateStats(logs) {
  const total = logs.length;

  const failed = allLogs.filter(function(log) {
    return log.action === 'LOGIN_FAILED';
  }).length;

  const flagged = allLogs.filter(function(log) {
    return log.threatScore > 0;
  });
  const uniqueFlagged = [...new Set(flagged.map(function(log) {
    return log.username;
  }))].length;

  let highRiskUser = '--';
  let highScore = 0;
  for (let i = 0; i < allLogs.length; i++) {
    if (allLogs[i].threatScore > highScore) {
      highScore = allLogs[i].threatScore;
      highRiskUser = allLogs[i].username;
    }
  }

  document.querySelector('#stat-total .stat-number').textContent = total;
  document.querySelector('#stat-failed .stat-number').textContent = failed;
  document.querySelector('#stat-flagged .stat-number').textContent = uniqueFlagged;
  document.querySelector('#stat-highrisk .stat-number').textContent = highRiskUser;
}

function setupFilters() {
  const buttons = document.querySelectorAll('.filter-btn');

  buttons.forEach(function(button) {
    button.addEventListener('click', function() {
      buttons.forEach(function(btn) {
        btn.classList.remove('active');
      });
      button.classList.add('active');

      const filter = button.getAttribute('data-filter');
      let filtered = allLogs;

      if (filter === 'failed') {
        filtered = allLogs.filter(function(log) {
          return log.action === 'LOGIN_FAILED';
        });
      } else if (filter === 'afterhours') {
        filtered = allLogs.filter(function(log) {
          const hour = new Date(log.timestamp).getHours();
          return hour >= 22 || hour < 6;
        });
      } else if (filter === 'escalation') {
        filtered = allLogs.filter(function(log) {
          return log.action === 'PRIVILEGE_ESCALATION';
        });
      } else if (filter === 'suspicious') {
        filtered = allLogs.filter(function(log) {
          return log.threatScore > 0;
        });
      }

      renderTable(filtered);
    });
  });
}