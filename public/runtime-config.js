// Docker replaces this object at request time. Static builds intentionally
// default to API mode; demo data is enabled only with VITE_APP_MODE=demo or an
// explicit runtime mode of "demo".
globalThis.__AEGIS_CONFIG__ = globalThis.__AEGIS_CONFIG__ || {};
