let token = '', selected = '', player = null, replayURL = '';
let sessionRows = [], pageNumber = 0;
const pageSize = 100;
const byId = id => document.getElementById(id);
async function request(path) {
  const response = await fetch(path, {headers:{Authorization:`Bearer ${token}`}});
  if (!response.ok) throw new Error(`Collection request failed (${response.status}).`);
  return response;
}
async function run(action) {
  byId('message').textContent = '';
  try { await action(); } catch (error) { byId('message').textContent = error.message; }
}
async function refresh() {
  const query = new URLSearchParams({lab:byId('lab').value,group:byId('group').value});
  const sessions = await (await request(`/api/sessions?${query}`)).json();
  sessionRows = sessions; pageNumber = 0; renderRows();
  byId('filters').classList.remove('hidden'); byId('login').classList.add('hidden');
  if (!sessions.length) byId('message').textContent = 'No sessions match the filters.';
}
function renderRows() {
  byId('sessions').replaceChildren();
  byId('pages').classList.toggle('hidden',sessionRows.length===0);
  byId('previous-page').disabled = pageNumber===0;
  byId('next-page').disabled = (pageNumber+1)*pageSize>=sessionRows.length;
  byId('page-label').textContent = `${pageNumber*pageSize+1}–${Math.min((pageNumber+1)*pageSize,sessionRows.length)} of ${sessionRows.length}`;
  for (const session of sessionRows.slice(pageNumber*pageSize,(pageNumber+1)*pageSize)) {
    const row = document.createElement('tr');
    for (const value of [new Date(session.started).toLocaleString(),`${session.lab} / ${session.group}`,session.actor,session.status]) {
      const cell = document.createElement('td'); cell.textContent = value; row.append(cell);
    }
    const cell = document.createElement('td'), button = document.createElement('button');
    button.textContent = session.id.slice(0,12); button.title = session.id;
    button.onclick = () => run(() => openSession(session.id)); cell.append(button); row.append(cell);
    byId('sessions').append(row);
  }
}
byId('previous-page').onclick = () => {pageNumber--;renderRows();};
byId('next-page').onclick = () => {pageNumber++;renderRows();};
async function openSession(id) {
  selected = id;
  const base = `/api/sessions/${id}/`;
  const meta = await (await request(base+'session.json')).json();
  byId('title').textContent = `${meta.lab} / ${meta.group} / ${id.slice(0,12)}`;
  byId('status').textContent = `${meta.status}${meta.reason ? ': '+meta.reason : ''}. ${meta.capture_input ? 'Input and output recorded.' : 'Output recorded; raw input disabled.'}`;
  const coverageText = await (await request(base+'coverage.jsonl')).text();
  const coverage = coverageText.trim() ? coverageText.trim().split('\n').map(JSON.parse) : [];
  const unsupported = [...new Set(coverage.filter(e=>e.type==='application_capability' && e.fields.protocol==='unsupported').map(e=>e.device))];
  byId('coverage').textContent = unsupported.length ? `The router image lacks vtysh command collection on: ${unsupported.join(', ')}. Terminal playback is available.` : '';
  const blob = await (await request(base+'replay.cast')).blob();
  if (player) player.dispose();
  if (replayURL) URL.revokeObjectURL(replayURL);
  byId('player').replaceChildren(); replayURL = URL.createObjectURL(blob);
  byId('detail').classList.remove('hidden');
  byId('detail').scrollIntoView({behavior:'instant'});
  player = AsciinemaPlayer.create(replayURL,byId('player'),{fit:'width',idleTimeLimit:2,preload:true});
  const text = await (await request(base+'activity.jsonl')).text();
  const events = text.trim() ? text.trim().split('\n').map(JSON.parse) : [];
  byId('commands').replaceChildren();
  for (const event of events) {
    const row = document.createElement('tr');
    const duration = event.duration_ns === undefined ? '—' : `${(event.duration_ns/1e9).toFixed(3)}s`;
    const mode = event.mode_before ? `${event.mode_before} → ${event.mode_after || '?'}` : '—';
    for (const value of [(event.start_ns/1e9).toFixed(3)+'s',event.device,event.command || JSON.stringify(event.argv),event.cwd || '—',mode,event.result_name ?? event.exit_code ?? event.status,duration,event.source]) {
      const cell = document.createElement('td');cell.textContent=value;row.append(cell);
    }
    byId('commands').append(row);
  }
  byId('no-commands').classList.toggle('hidden',events.length>0);
}
byId('login').onsubmit = event => {event.preventDefault();token=byId('token').value;byId('token').value='';run(refresh);};
byId('filters').onsubmit = event => {event.preventDefault();run(refresh);};
byId('logout').onclick = () => location.reload();
byId('refresh-session').onclick = () => run(() => openSession(selected));
for (const button of document.querySelectorAll('[data-download]')) button.onclick = () => run(async () => {
  const filename = button.dataset.download;
  const blob = await (await request(`/api/sessions/${selected}/${filename}`)).blob();
  const url = URL.createObjectURL(blob), a = document.createElement('a');
  a.href=url;a.download=`${selected}-${filename}`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
});
