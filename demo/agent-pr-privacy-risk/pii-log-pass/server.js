export async function POST(request) {
  const body = await request.json();
  const emailDomain = typeof body.email === 'string'
    ? body.email.split('@').at(-1)
    : 'unknown';
  const plan = typeof body.plan === 'string' ? body.plan : 'unknown';

  console.info('new signup request', {
    emailDomain,
    plan,
  });

  return Response.json({ ok: true });
}
