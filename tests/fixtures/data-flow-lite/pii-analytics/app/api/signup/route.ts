import posthog from 'posthog-js';

type SignupPayload = {
  phone: string;
};

export async function POST(request: Request) {
  const payload = await request.json();
  posthog.capture('signup_started', { phone: payload.phone });
  return Response.json({ ok: true });
}
