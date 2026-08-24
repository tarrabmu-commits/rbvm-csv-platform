(() => {
  'use strict';

  const current = document.currentScript;
  const currentUrl = current && current.src ? current.src : new URL('/customer-flow.js', location.origin).href;
  const baseUrl = new URL('customer-flow-base.js', currentUrl).href;
  const localApiUrl = new URL('customer-flow-local-api.js', currentUrl).href;

  const base = document.createElement('script');
  base.src = baseUrl;
  base.async = false;
  base.addEventListener('load', () => {
    const localApi = document.createElement('script');
    localApi.src = localApiUrl;
    localApi.async = false;
    localApi.addEventListener('error', () => {
      console.error('RBVM customer Local API UI extension could not be loaded.');
    });
    document.head.append(localApi);
  });
  base.addEventListener('error', () => {
    console.error('RBVM customer flow base UI could not be loaded.');
  });
  document.head.append(base);
})();
