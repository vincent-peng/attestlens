export async function POST(request: Request) {
  const body = await request.json();
  await fetch('https://processor.example.com/import', {
    method: 'POST',
    body: JSON.stringify({ email: body.email }),
  });
  return Response.json({ ok: true });
}
