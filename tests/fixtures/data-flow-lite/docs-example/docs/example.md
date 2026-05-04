# Data Flow Lite Example

```ts
export async function POST(request: Request) {
  const body = await request.json();
  console.log(body.email);
}
```
