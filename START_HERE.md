# Start S4BLE

1. Extract the ZIP and open a terminal in the `s4ble` folder.
2. Install a supported Node.js LTS (Node 22 or newer).
3. Run `npm ci`, then `npm test`, then `npm start`.
4. Open http://localhost:8080.
5. Choose Cloud Guide → Open example workspace, or Import → choose/paste infrastructure → Analyze workspace.

The `public` directory alone is not a complete deployment: `/api/analyze` and `/api/review` need `server.mjs` and `engine/`. Do not open `index.html` directly from the filesystem.

For www.s4ble.com hosting, follow VERCEL_DEPLOY.md. This archive does not change the live domain or its DNS. It contains no credentials or preloaded customer workspaces. Each new browser starts empty.
