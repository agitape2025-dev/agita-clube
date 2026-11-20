/* Service worker do AGITA: recebe notificações push e abre o app no mural de avisos. */
self.addEventListener('install', function(){ self.skipWaiting(); });
self.addEventListener('activate', function(e){ e.waitUntil(self.clients.claim()); });

self.addEventListener('push', function(event){
  event.waitUntil((async function(){
    var titulo = 'Novo aviso do AGITA';
    var corpo = 'Toque para ver o aviso no mural.';
    // Pedido de fardamento recente? (só quem controla os fardamentos recebe esse alerta)
    try {
      var c2 = new AbortController();
      var t2 = setTimeout(function(){ c2.abort(); }, 3500);
      var ra = await fetch('/api/fardamentos/alerta', { credentials: 'include', signal: c2.signal });
      clearTimeout(t2);
      if (ra.ok) {
        var da = await ra.json();
        if (da && da.recente) {
          await self.registration.showNotification(da.titulo || 'Novo pedido de fardamento', {
            body: da.corpo || 'Toque para ver o pedido.',
            icon: '/icone.png',
            badge: '/icone.png',
            tag: 'agita-fard',
            renotify: true,
            data: { url: '/?secao=fardamentos' }
          });
          return;
        }
      }
    } catch (e) { /* segue para o aviso normal */ }
    try {
      var ctrl = new AbortController();
      var t = setTimeout(function(){ ctrl.abort(); }, 4000);
      var r = await fetch('/api/avisos/contagem?desde=0', { credentials: 'include', signal: ctrl.signal });
      clearTimeout(t);
      if (r.ok) {
        var d = await r.json();
        if (d && d.ultimo && d.ultimo.titulo) { corpo = d.ultimo.titulo; }
      }
    } catch (e) { /* mantém o texto padrão */ }
    await self.registration.showNotification(titulo, {
      body: corpo,
      icon: '/icone.png',
      badge: '/icone.png',
      tag: 'agita-aviso',
      renotify: true,
      data: { url: '/?secao=avisos' }
    });
  })());
});

self.addEventListener('notificationclick', function(event){
  event.notification.close();
  var alvo = (event.notification.data && event.notification.data.url) || '/?secao=avisos';
  event.waitUntil((async function(){
    var janelas = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (var i = 0; i < janelas.length; i++) {
      var j = janelas[i];
      if (j.url.indexOf(self.location.origin) === 0 && 'focus' in j) {
        await j.focus();
        if ('navigate' in j) { try { await j.navigate(alvo); } catch (e) {} }
        return;
      }
    }
    if (self.clients.openWindow) await self.clients.openWindow(alvo);
  })());
});
