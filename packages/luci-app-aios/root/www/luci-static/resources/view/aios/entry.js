'use strict';
'require view';
'require rpc';

return view.extend({
	render: function () {
		const sessionId = rpc.getSessionID();
		const targetUrl = '/aios/' + (sessionId ? ('#ubus_session=' + encodeURIComponent(sessionId)) : '');

		return E('div', { 'class': 'cbi-map' }, [
			E('div', {
				'style': 'display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;gap:12px;flex-wrap:wrap;'
			}, [
				E('div', {}, [
					E('h2', { 'style': 'margin:0;' }, _('AIOS Console (Xray / V2Ray)')),
					E('div', { 'class': 'cbi-map-descr', 'style': 'margin:4px 0 0;' },
						_('Standalone Vite + Vue 3 console powered by OpenWrt ubus.'))
				]),
				E('a', {
					'class': 'cbi-button cbi-button-action',
					'href': targetUrl,
					'target': '_blank',
					'rel': 'noopener'
				}, _('Open Fullscreen Console ↗'))
			]),
			E('iframe', {
				'src': targetUrl,
				'style': 'width:100%;height:calc(100vh - 180px);min-height:680px;border:1px solid #d0d7de;border-radius:8px;background:#fff;'
			})
		]);
	},
	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
