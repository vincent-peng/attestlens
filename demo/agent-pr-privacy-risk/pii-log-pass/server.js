export async function POST(request) {
  const body = await request.json();
  const contactProvided = typeof body.email === 'string' && body.email.length > 0;
  const plan = typeof body.plan === 'string' ? body.plan : 'unknown';

  console.info('new signup request', {
    contactProvided,
    plan,
  });

  return Response.json({ ok: true });
}
