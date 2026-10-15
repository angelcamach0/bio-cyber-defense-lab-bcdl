/* SPDX-License-Identifier: AGPL-3.0-only */
'use strict';
const $ = id => document.getElementById(id);
let sessionGeneration = 0, pollGeneration = 0, session = null;
let polling = null, pendingClick = null;
const controllers = new Set();
const runID = value => typeof value === 'string' && /^[a-f0-9]{16}$/.test(value);
const current = generation => generation === sessionGeneration;
function message(text) { $('message').textContent = text; }
function invalidate() {
  sessionGeneration += 1; pollGeneration += 1;
  if (polling) clearTimeout(polling);
  polling = null;
  controllers.forEach(controller => controller.abort()); controllers.clear();
  session = null; pendingClick = null;
  $('sign-in').disabled = false;
  $('catalog').replaceChildren(); $('history').replaceChildren();
  $('result-content').replaceChildren(); $('result').hidden = true;
  $('workspace').hidden = true; $('sign-out').hidden = true; $('login').hidden = false;
  return sessionGeneration;
}
async function api(path, options = {}, generation = sessionGeneration) {
  const controller = new AbortController(); controllers.add(controller);
  const timer = setTimeout(() => controller.abort(), 35000);
  try {
    const response = await fetch(path, {...options, credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: controller.signal,
      headers: {'Content-Type': 'application/json', ...(session ? {'X-CSRF-Token': session.csrf_token} : {}), ...(options.headers || {})}});
    const payload = await response.json();
    if (!current(generation)) throw new Error('stale_session');
    if (!response.ok) {
      if (response.status === 401 && session) { invalidate(); message('La sesión terminó. Inicia sesión para consultar tu historial.'); }
      const failure = new Error(payload.error_code || payload.code || 'request_failed'); failure.status = response.status; throw failure;
    }
    return payload;
  } finally { clearTimeout(timer); controllers.delete(controller); }
}
function paragraph(text, className = '') { const p = document.createElement('p'); p.textContent = text; p.className = className; return p; }
function badge(text, style) { const span = document.createElement('span'); span.textContent = text; span.className = 'badge ' + style; return span; }
function enter(value, generation) {
  if (!current(generation)) return;
  session = value; $('workspace').hidden = false; $('login').hidden = true; $('sign-out').hidden = false;
  $('greeting').textContent = 'Experimentos · ' + value.reviewer;
}
async function load(generation = sessionGeneration) {
  if (!session || !current(generation)) return;
  const [catalog, history] = await Promise.all([api('/api/experiments', {}, generation), api('/api/runs', {}, generation)]);
  if (!current(generation)) return;
  let recovered = null;
  if (pendingClick) {
    recovered = history.find(row => row.request_id === pendingClick.request && row.experiment_id === pendingClick.experiment && runID(row.run_id));
    if (recovered) { pendingClick = null; message('Operación encontrada en tu historial. No se volvió a enviar.'); }
  }
  $('catalog').replaceChildren();
  for (const experiment of catalog) {
    const card = document.createElement('article'); card.className = 'card';
    const title = document.createElement('h2'); title.textContent = experiment.label;
    const start = document.createElement('button'); start.type = 'button'; start.textContent = 'Ejecutar experimento'; start.disabled = pendingClick !== null;
    start.addEventListener('click', () => submit(experiment.id));
    card.append(title, paragraph(experiment.scope), start); $('catalog').append(card);
  }
  renderHistory(history, generation);
  if (recovered && current(generation)) follow(recovered.run_id);
}
function renderHistory(rows, generation) {
  if (!current(generation)) return;
  $('history').replaceChildren();
  if (!rows.length) { $('history').append(paragraph('Todavía no hay operaciones.')); return; }
  for (const row of rows) {
    const item = document.createElement('article'); item.className = 'run';
    const info = document.createElement('div'); info.append(paragraph(row.experiment_id));
    info.append(badge(row.needs_operator ? 'Requiere revisión del operador' : row.phase, row.needs_operator ? 'withheld' : 'pending'));
    const view = document.createElement('button'); view.type = 'button'; view.textContent = 'Consultar';
    view.addEventListener('click', () => follow(row.run_id)); item.append(info, view); $('history').append(item);
  }
}
async function submit(experiment) {
  if (!session || pendingClick) return;
  const generation = sessionGeneration;
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  const request = Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('');
  pendingClick = {request, experiment};
  document.querySelectorAll('#catalog button').forEach(button => { button.disabled = true; });
  message('Registrando la operación…');
  try {
    const row = await api('/api/experiments/' + encodeURIComponent(experiment) + '/runs', {method: 'POST', body: JSON.stringify({request_id: request})}, generation);
    if (!current(generation)) return;
    if (!runID(row.run_id)) throw new Error('invalid_operation');
    pendingClick = null; message('Operación registrada. Puedes cerrar sesión; seguirá su curso.');
    await load(generation); if (current(generation)) follow(row.run_id);
  } catch (error) {
    if (!current(generation)) return;
    // Keep the exact intent in memory. Never POST again after a lost response.
    message('No se confirmó la respuesta. Consulta el historial antes de iniciar otra operación. No se reenviará automáticamente.');
    try { await load(generation); } catch (_) { /* The explicit refresh remains available. */ }
  }
}
async function follow(operation) {
  if (!session || !runID(operation)) return;
  const generation = sessionGeneration, poll = ++pollGeneration, started = Date.now();
  if (polling) clearTimeout(polling);
  const live = () => current(generation) && poll === pollGeneration;
  const tick = async () => {
    if (!live()) return;
    try {
      const row = await api('/api/operations/' + operation, {}, generation);
      if (!live()) return;
      if (row.job_id && runID(row.job_id)) {
        const result = await api('/api/results/' + row.job_id, {}, generation);
        if (!live()) return;
        showResult(result);
        if (result.execution_state === 'committed') { message('Resultado consultado. Revisa el estado de aprobación científica.'); await load(generation); return; }
      }
      if (row.needs_operator) { message('Esta operación conserva su historial y requiere revisión del operador. No se reenviará.'); await load(generation); return; }
      message('La operación sigue pendiente. No es necesario volver a enviarla.');
    } catch (_) { if (!live()) return; message('No se pudo consultar ahora. La operación no se volverá a enviar.'); }
    if (!live()) return;
    if (Date.now() - started >= 12 * 60 * 1000) { message('La consulta automática terminó; el historial se conserva. Puedes actualizarlo manualmente.'); return; }
    polling = setTimeout(tick, 2000);
  };
  tick();
}
function showResult(result) {
  const panel = $('result-content'); panel.replaceChildren(); $('result').hidden = false;
  const passed = result.release_status === 'evaluated_passed';
  const pending = result.execution_state !== 'committed';
  panel.append(badge(pending ? 'Pendiente' : passed ? 'Validación sintética aprobada' : result.release_status === 'unassessed' ? 'Sin evaluación científica' : 'Resultado retenido', pending ? 'pending' : passed ? 'passed' : 'withheld'));
  panel.append(paragraph('Ejecución: ' + result.status + ' · Liberación: ' + result.release_status));
  const evaluation = result.scientific_evaluation;
  if (evaluation) {
    const metrics = document.createElement('div'); metrics.className = 'metrics';
    for (const [key, label] of [['tp', 'Verdaderos positivos'], ['fp', 'Falsos positivos'], ['fn', 'Falsos negativos']]) {
      if (!Number.isFinite(evaluation[key])) continue;
      const metric = document.createElement('div'); metric.className = 'metric'; const value = document.createElement('strong'); value.textContent = evaluation[key]; metric.append(value, document.createTextNode(label)); metrics.append(metric);
    }
    for (const [key, label] of [['precision', 'Precisión'], ['recall', 'Recall']]) {
      const metric = document.createElement('div'); metric.className = 'metric';
      const value = document.createElement('strong');
      value.textContent = Number.isFinite(evaluation[key]) ? evaluation[key] : 'Sin evaluar';
      metric.append(value, document.createTextNode(label)); metrics.append(metric);
    }
    panel.append(metrics);
  }
  const mode = result.pipeline_output && result.pipeline_output.mode;
  const scope = mode === 'stats'
    ? 'Alcance: estadísticas FASTQ de datos sintéticos, sin evaluación científica de variantes. No establece precisión clínica.'
    : mode === 'variants'
      ? 'Alcance: presencia de alelos en datos sintéticos. No valida genotipos, genomas completos ni precisión clínica.'
      : 'Alcance: experimento sintético. La evaluación científica aún no está disponible; no establece precisión clínica.';
  panel.append(paragraph(scope, 'muted'));
}
$('login-form').addEventListener('submit', async event => {
  event.preventDefault(); const generation = invalidate(); $('sign-in').disabled = true;
  const id = $('reviewer').value, code = $('access-code').value; $('access-code').value = '';
  try { const value = await api('/api/sign-in', {method: 'POST', body: JSON.stringify({id, access_code: code})}, generation); if (!current(generation)) return; enter(value, generation); await load(generation); message('Sesión iniciada.'); }
  catch (_) { if (current(generation)) message('No se pudo iniciar sesión. Comprueba tus credenciales.'); }
  finally { if (current(generation)) $('sign-in').disabled = false; }
});
$('sign-out').addEventListener('click', async () => {
  const csrf = session && session.csrf_token; const generation = invalidate();
  try { await api('/api/sign-out', {method: 'POST', body: '{}', headers: {'X-CSRF-Token': csrf || ''}}, generation); } catch (_) { /* Local state is already cleared. */ }
  if (current(generation)) message('Sesión cerrada en esta pestaña. Las operaciones autorizadas siguen conservadas.');
});
$('refresh').addEventListener('click', async () => { const generation = sessionGeneration; try { await load(generation); if (current(generation)) message('Historial actualizado. No se envió ninguna operación.'); } catch (_) { if (current(generation)) message('No se pudo actualizar el historial.'); } });
(async () => { const generation = sessionGeneration; try { const value = await api('/api/session', {}, generation); if (!current(generation)) return; enter(value, generation); await load(generation); } catch (_) { /* Sign-in remains available. */ } })();
