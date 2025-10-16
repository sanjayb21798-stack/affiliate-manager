const $ = (id) => document.getElementById(id);

// tiny toast helper
function toast(msg) {
  const t = $('toast');
  t.textContent = msg;
  t.style.display = 'block';
  setTimeout(() => (t.style.display = 'none'), 2200);
}

async function fetchJSON(url, options) {
  const res = await fetch(url, { headers: { 'Content-Type': 'application/json' }, ...options });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

function chip(value, type='') {
  return `<span class="chip ${type}">${value}</span>`;
}

async function refreshStats() {
  const data = await fetchJSON('/api/stats');
  const el = $('stats');
  if (!data.length) {
    el.innerHTML = '<p class="muted">No affiliates yet.</p>';
    return;
  }

  el.innerHTML = `
    <table>
      <thead>
        <tr>
          <th>Name</th><th>Code</th><th>Rate</th>
          <th>Clicks</th><th>Conversions</th>
          <th>Revenue (₹)</th><th>Earned (₹)</th><th>Paid-Out (₹)</th><th>Available (₹)</th>
          <th>Share Link</th>
        </tr>
      </thead>
      <tbody>
        ${data.map(r => {
          const avail = parseFloat(r.available);
          const badge = avail >= 100 ? chip('ready to withdraw', 'ok')
                       : avail > 0   ? chip('below min', 'warn')
                                     : chip('zero', 'danger');
          return `
            <tr>
              <td>${r.name}</td>
              <td><code>${r.code}</code></td>
              <td>${(r.rateBps/100).toFixed(2)}%</td>
              <td>${r.clicks}</td>
              <td>${r.conversions}</td>
              <td>${r.revenue}</td>
              <td>${r.earned}</td>
              <td>${r.paidOut}</td>
              <td>${r.available} ${badge}</td>
              <td><a href="${r.shareLink}?to=/">/r/${r.code}</a></td>
            </tr>
          `;
        }).join('')}
      </tbody>
    </table>
  `;
}

// Wire up actions
$('refresh').onclick = refreshStats;

$('createForm').onsubmit = async (e) => {
  e.preventDefault();
  const name = document.getElementById('affName').value.trim();
  const rateBps = Number(document.getElementById('rateBps').value || 1000);
  if (!name) return;
  const result = await fetchJSON('/api/affiliates', {
    method: 'POST',
    body: JSON.stringify({ name, rateBps })
  });
  document.getElementById('createResult').innerHTML =
    `Created <b>${result.name}</b> at ${(result.rateBps/100).toFixed(2)}% — code <code>${result.code}</code> — share <a href="${result.link}?to=/">link</a>`;
  document.getElementById('affName').value = '';
  document.getElementById('rateBps').value = '';
  toast('Affiliate created');
  await refreshStats();
};

$('convForm').onsubmit = async (e) => {
  e.preventDefault();
  const code = document.getElementById('convCode').value.trim();
  const orderId = document.getElementById('orderId').value.trim();
  const amount = Number(document.getElementById('amount').value || 0);
  try {
    const r = await fetchJSON('/api/convert', {
      method: 'POST',
      body: JSON.stringify({ code, orderId, amountCents: Math.round(amount * 100) })
    });
    document.getElementById('convCode').value = '';
    document.getElementById('orderId').value = '';
    document.getElementById('amount').value = '';
    toast(`Conversion recorded — commission ₹${(r.commissionCents/100).toFixed(2)}`);
    await refreshStats();
  } catch (err) {
    toast('Error recording conversion');
  }
};

$('payForm').onsubmit = async (e) => {
  e.preventDefault();
  const code = document.getElementById('payCode').value.trim();
  const amountInRupees = document.getElementById('payAmount').value ? Number(document.getElementById('payAmount').value) : null;
  const body = { code };
  if (amountInRupees != null) body.amountCents = Math.round(amountInRupees * 100);
  try {
    const r = await fetchJSON('/api/payouts/request', { method: 'POST', body: JSON.stringify(body) });
    document.getElementById('payResult').innerText = `Requested payout #${r.payoutId}. Admin must approve it.`;
    document.getElementById('payCode').value = '';
    document.getElementById('payAmount').value = '';
    toast('Payout requested');
  } catch (err) {
    document.getElementById('payResult').innerText = `Error: ${err.message}`;
    toast('Payout request failed');
  }
  await refreshStats();
};

// initial load
refreshStats();

