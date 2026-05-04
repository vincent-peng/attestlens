export async function POST(request: Request) {
  const body = await request.json();
  console.info('new user', body.email);
  return Response.json({ ok: true });
}
