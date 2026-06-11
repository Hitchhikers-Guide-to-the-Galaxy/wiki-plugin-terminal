// wiki-plugin-terminal — server-side component
//
// Intentionally minimal: the live capabilities (pty sessions, run-capture)
// belong to the local-first FastAPI service (service/terminal_service.py),
// not the wiki node server. On public servers the plugin is display-only,
// so there is nothing to register here.
//
// Future possibility: an admin-gated /plugin/terminal/run route mirroring
// wiki-plugin-shell's isAdmin-guarded exec, for shared servers that want
// Ward's run-capture mode without the FastAPI service.

const startServer = params => {}

export { startServer }
