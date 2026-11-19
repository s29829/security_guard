/* ResourceSpace plugins – latest release info from the GitHub API.
   The static page already links to the release known at build time; this only refreshes the
   version, date, size and download link when a newer release exists. */
(function () {
  'use strict';

  var CACHE_MS = 10 * 60 * 1000;

  function cacheGet(key) {
    try {
      var raw = window.sessionStorage.getItem(key);
      if (!raw) return null;
      var item = JSON.parse(raw);
      return (Date.now() - item.t < CACHE_MS) ? item.v : null;
    } catch (e) { return null; }
  }

  function cacheSet(key, value) {
    try { window.sessionStorage.setItem(key, JSON.stringify({ t: Date.now(), v: value })); } catch (e) { /* storage unavailable */ }
  }

  function formatSize(bytes) {
    if (!bytes) return '';
    return bytes < 1048576 ? Math.round(bytes / 1024) + ' KB' : (bytes / 1048576).toFixed(1) + ' MB';
  }

  function formatDate(iso) {
    if (!iso) return '';
    var d = new Date(iso);
    if (isNaN(d.getTime())) return '';
    return d.toLocaleDateString('en-GB', { year: 'numeric', month: 'short', day: 'numeric' });
  }

  function fetchLatest(repo) {
    var key = 'rsp-release:' + repo;
    var cached = cacheGet(key);
    if (cached) return Promise.resolve(cached);
    return fetch('https://api.github.com/repos/' + repo + '/releases/latest', {
      headers: { Accept: 'application/vnd.github+json' }
    }).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    }).then(function (d) {
      var zip = (d.assets || []).filter(function (a) { return /\.zip$/i.test(a.name); })[0];
      var info = {
        version: String(d.tag_name || '').replace(/^v/, ''),
        url: zip ? zip.browser_download_url : d.html_url,
        file: zip ? zip.name : '',
        size: zip ? zip.size : 0,
        date: d.published_at || '',
        notes: d.html_url
      };
      if (!info.version) throw new Error('no version');
      cacheSet(key, info);
      return info;
    });
  }

  function apply(repo, info) {
    var nodes = document.querySelectorAll('[data-repo="' + repo + '"]');
    Array.prototype.forEach.call(nodes, function (el) {
      var field = el.getAttribute('data-field');
      if (field === 'version') {
        el.textContent = info.version;
      } else if (field === 'file' && info.file) {
        el.textContent = info.file;
      } else if (field === 'url') {
        el.setAttribute('href', info.url);
      } else if (field === 'notes') {
        el.setAttribute('href', info.notes);
      } else if (field === 'meta') {
        var parts = [];
        if (info.date) parts.push('Released ' + formatDate(info.date));
        if (info.size) parts.push(formatSize(info.size) + ' .zip');
        if (parts.length) el.textContent = parts.join(' · ');
      }
    });
  }

  var repos = {};
  Array.prototype.forEach.call(document.querySelectorAll('[data-repo]'), function (el) {
    repos[el.getAttribute('data-repo')] = true;
  });
  Object.keys(repos).forEach(function (repo) {
    fetchLatest(repo).then(function (info) { apply(repo, info); }).catch(function () {
      /* keep the links from the build (rate limit, offline) */
    });
  });

  // Copy buttons for code blocks
  Array.prototype.forEach.call(document.querySelectorAll('.code'), function (pre) {
    if (!navigator.clipboard) return;
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'copy';
    btn.textContent = 'Copy';
    btn.addEventListener('click', function () {
      var text = pre.querySelector('code').textContent;
      navigator.clipboard.writeText(text).then(function () {
        btn.textContent = 'Copied';
        setTimeout(function () { btn.textContent = 'Copy'; }, 1500);
      });
    });
    pre.parentNode.appendChild(btn);
  });
})();
