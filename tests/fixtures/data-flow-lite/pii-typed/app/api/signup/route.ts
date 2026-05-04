type SignupPayload = {
  phone: string;
};

export async function POST(request: Request) {
  const payload: SignupPayload = await request.json();
  console.debug('signup', payload.phone);
  return Response.json({ ok: true });
}
