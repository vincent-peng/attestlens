export async function POST(request) {
  const body = await request.json();

  console.log('new signup request', {
    email: body.email,
    plan: body.plan,
  });

  return Response.json({ ok: true });
}
