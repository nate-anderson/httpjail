# httpjail

Go HTTP rate limiting middleware. Compatible with net/http, [Chi](https://github.com/go-chi/chi) and probably your favorite router/multiplexer.

Thread-safe but probably not performant

### Example use

```go
// Create a new jail (max 30 requests in rolling 30 seconds, respond with error message)
jail := httpjail.NewBasicJail(30, 30, false)

// if using a proxy or load balancer, use the X-Forwarded-For header to get request IPs
if proxy {
    jail.IsProxied()
}

// Use the middleware
router := chi.NewRouter()
router.Use(jail.Middleware)

http.ListenAndServe(port, router)
```
