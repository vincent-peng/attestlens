export async function firstHandler(request: Request) {
  const body = await request.json();
  return Response.json({ accepted: Boolean(body) });
}

export async function secondHandler() {
  const body = { email: 'demo@example.com' };
  console.info('template', body.email);
  return Response.json({ ok: true });
}
