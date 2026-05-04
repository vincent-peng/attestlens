type SignupPayload = {
  email: string;
};

export function logRouteName(routeName: string) {
  const payload: SignupPayload | null = null;
  console.info('route', { name: routeName, payloadPresent: Boolean(payload) });
}
