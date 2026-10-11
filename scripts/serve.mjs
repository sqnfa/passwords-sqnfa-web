import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
import {resolve, extname, sep} from 'node:path';

const root = resolve('.');
const mime = {
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.map': 'application/json',
};
createServer(async (request, response) => {
  try {
    const pathname = decodeURIComponent(
      new URL(request.url, 'http://localhost').pathname
    );
    const path = resolve(
      root,
      '.' + (pathname === '/' ? '/examples/vanilla.html' : pathname)
    );
    if (
      !path.startsWith(root + sep) ||
      !['examples', 'build'].includes(path.slice(root.length + 1).split(sep)[0])
    ) {
      response.writeHead(403).end();
      return;
    }
    const body = await readFile(path);
    response
      .writeHead(200, {
        'Content-Type': mime[extname(path)] || 'application/octet-stream',
      })
      .end(body);
  } catch {
    response.writeHead(404).end();
  }
}).listen(8080, '127.0.0.1', () =>
  console.log('Vanilla sample: http://localhost:8080')
);
