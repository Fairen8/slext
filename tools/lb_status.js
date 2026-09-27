// Статус балансировщика SLExt из консоли браузера (на странице панели SafeLine).
(async function () {
  var t = localStorage.getItem('safeline_auth');
  var h = { 'Authorization': 'Bearer ' + t };
  var r = await fetch('/extapi/api/lb', { headers: h });
  var j = await r.json();
  var st = (j.status || []).map(function (s) {
    return s.addr + ':' + (s.up ? 'up' : 'DOWN') + ':fails=' + s.fails;
  }).join(', ');
  var r2 = await fetch('/extapi/api/lb/test', { headers: h });
  var j2 = await r2.json();
  return st + ' || test=' + JSON.stringify(j2.results || []).slice(0, 140);
})()
