import { Hono } from 'hono';

const app = new Hono();

app.post('/contact', async (c) => {
  const payload = await c.req.json();
  console.info('contact', payload.phone);
  return c.json({ ok: true });
});

export default app;
