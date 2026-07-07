export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    return new Response("CF Pages deploy test v1 OK", {
      status: 200,
      headers: { "Content-Type": "text/plain" }
    });
  }
}
