# Sable production-ready build

This build removes all sample/demo loaders and starts with a clean, un-analyzed workspace for new visitors.

## Import flow
- The main **Import infrastructure** actions open the browser/OS native file picker.
- Supported infrastructure files: `.tf`, `.tf.json`, `.json`, `.yaml`, `.yml`.
- Multiple Terraform or YAML files can be selected together. JSON imports accept one document at a time.
- Drag-and-drop and pasted source remain supported.
- Client-side validation matches the server limit of 100 files / 7 MB of source.

## Runtime
1. Install Node.js 20 or newer.
2. Run `npm install`.
3. Run `npm start`.
4. Configure `PORT` and `HOST` with environment variables if needed.

The server uses Helmet/CSP, request-size limits, API 404 handling, static asset caching, and graceful shutdown handling.
