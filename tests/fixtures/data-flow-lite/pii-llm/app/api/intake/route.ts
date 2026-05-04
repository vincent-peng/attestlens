import OpenAI from 'openai';

const openai = new OpenAI();

const IntakeSchema = z.object({
  health: z.string(),
});

export async function POST(request: Request) {
  const body = await request.json();
  await openai.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [{ role: 'user', content: `Summarize symptoms: ${body.health}` }],
  });
  return Response.json({ ok: true });
}
