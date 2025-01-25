/**
 * Get an array of all currently selected repositories (checkboxes).
 */
function getSelectedRepos() {
  const checkboxes = document.querySelectorAll('input[name="repoSelect"]:checked');
  const repoNames = [];
  checkboxes.forEach(cb => repoNames.push(cb.value));
  return repoNames;
}

/**
 * Show a quick status message on the console (or replace with a fancy UI element).
 */
function showStatus(msg) {
  console.log('[STATUS]', msg);
}

/**
 * A tiny helper to handle server responses (text) and display them.
 */
function handleServerResponse(text) {
  // For simplicity, we just log it. You can also insert it into the DOM if you want.
  console.log('[SERVER RESPONSE]', text);
  alert(text);
}


///////////////////////////////
//  Individual Action Handlers
///////////////////////////////

/**
 * Pull a single repository by name, calling /pull?repo=<repoName>.
 */
function doPull(repoName, buttonElem) {
  if (!repoName) {
    alert('No repo specified!');
    return;
  }
  showStatus(`Pulling repo: ${repoName}...`);
  fetch('/pull?repo=' + encodeURIComponent(repoName))
    .then(resp => resp.text())
    .then(txt => handleServerResponse(txt))
    .catch(err => console.error('[ERROR]', err));
}

/**
 * Build a single repository by name, calling /build?repo=<repoName>.
 */
function doBuild(repoName, buttonElem) {
  if (!repoName) {
    alert('No repo specified!');
    return;
  }
  showStatus(`Building repo: ${repoName}...`);
  fetch('/build?repo=' + encodeURIComponent(repoName))
    .then(resp => resp.text())
    .then(txt => handleServerResponse(txt))
    .catch(err => console.error('[ERROR]', err));
}

/**
 * View logs for a single repository by name, calling /logs?repo=<repoName>.
 * This example opens in a new tab. Alternatively, you could fetch and display in a modal.
 */
function doViewLog(repoName, buttonElem) {
  if (!repoName) {
    alert('No repo specified!');
    return;
  }
  const url = '/logs?repo=' + encodeURIComponent(repoName);
  window.open(url, '_blank');
  // If you wanted to do a fetch instead:
  //   fetch(url).then(...) ...
}

/**
 * Pull ALL repositories at once, calling /pull-all.
 */
function doPullAll(buttonElem) {
  showStatus('Pulling ALL repositories...');
  fetch('/pull-all')
    .then(resp => resp.text())
    .then(txt => handleServerResponse(txt))
    .catch(err => console.error('[ERROR]', err));
}

/**
 * Build ALL repositories at once, calling /build-all.
 */
function doBuildAll(buttonElem) {
  showStatus('Building ALL repositories...');
  fetch('/build-all')
    .then(resp => resp.text())
    .then(txt => handleServerResponse(txt))
    .catch(err => console.error('[ERROR]', err));
}

/**
 * Pull AND build ALL repositories at once, calling /pull-and-build-all.
 */
function doPullAndBuildAll(buttonElem) {
  showStatus('Pulling & building ALL repositories...');
  fetch('/pull-and-build-all')
    .then(resp => resp.text())
    .then(txt => handleServerResponse(txt))
    .catch(err => console.error('[ERROR]', err));
}

/**
 * Pull the selected repositories, calling /pull-selected?repos=<comma-separated-list>.
 */
function doPullSelected(buttonElem) {
  const repos = getSelectedRepos();
  if (repos.length === 0) {
    alert('No repositories selected!');
    return;
  }
  const query = '/pull-selected?repos=' + encodeURIComponent(repos.join(','));
  showStatus('Pulling selected repos: ' + repos.join(', '));
  fetch(query)
    .then(resp => resp.text())
    .then(txt => handleServerResponse(txt))
    .catch(err => console.error('[ERROR]', err));
}

/**
 * Build the selected repositories, calling /build-selected?repos=<comma-separated-list>.
 */
function doBuildSelected(buttonElem) {
  const repos = getSelectedRepos();
  if (repos.length === 0) {
    alert('No repositories selected!');
    return;
  }
  const query = '/build-selected?repos=' + encodeURIComponent(repos.join(','));
  showStatus('Building selected repos: ' + repos.join(', '));
  fetch(query)
    .then(resp => resp.text())
    .then(txt => handleServerResponse(txt))
    .catch(err => console.error('[ERROR]', err));
}

/**
 * Pull AND build selected repositories, calling /pull-and-build-selected?repos=...
 */
function doPullAndBuildSelected(buttonElem) {
  const repos = getSelectedRepos();
  if (repos.length === 0) {
    alert('No repositories selected!');
    return;
  }
  const query = '/pull-and-build-selected?repos=' + encodeURIComponent(repos.join(','));
  showStatus('Pulling & building selected repos: ' + repos.join(', '));
  fetch(query)
    .then(resp => resp.text())
    .then(txt => handleServerResponse(txt))
    .catch(err => console.error('[ERROR]', err));
}


///////////////////////////////
//  "Select All" checkbox logic
///////////////////////////////
window.addEventListener('DOMContentLoaded', () => {
  const selectAllCb = document.getElementById('selectAll');
  if (selectAllCb) {
    selectAllCb.addEventListener('change', function () {
      // Check or uncheck all "repoSelect" checkboxes
      const allRepoCbs = document.querySelectorAll('input[name="repoSelect"]');
      allRepoCbs.forEach(cb => {
        cb.checked = selectAllCb.checked;
      });
    });
  }
});
